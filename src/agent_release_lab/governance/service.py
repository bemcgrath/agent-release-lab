"""Deterministic governance and transactional human decisions."""

import hmac
import json
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from sqlite3 import Connection
from uuid import uuid4

from ..comparison import compare_manifests
from ..evidence import Evidence, EvidenceMismatch
from ..identity import canonical_json, sha256
from ..registry import RecordConflict, RecordMissing, Registry
from .models import (
    TIERS, Activation, ApprovalRequest, AssessmentRequest, LocalTrust,
    evidence_signature_payload, runtime_signature_payload, signature_matches,
)
from .policy import Policy


class Unauthorized(PermissionError):
    """The actor lacks the required role or fails separation of duties."""


class GovernanceInputError(ValueError):
    """A proposed policy or activation is inconsistent with registered records."""


class Governance:
    def __init__(self, registry: Registry, trust: LocalTrust, clock: Callable[[], datetime] | None = None):
        self.registry = registry
        self.trust = trust
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.actors = {actor.id: actor for actor in trust.actors}
        with registry.transaction() as db:
            db.executescript("""
                BEGIN IMMEDIATE;
                CREATE TABLE IF NOT EXISTS governance_policies (
                    fingerprint TEXT PRIMARY KEY NOT NULL, policy_id TEXT NOT NULL,
                    revision TEXT NOT NULL, payload BLOB NOT NULL, UNIQUE (policy_id, revision)
                );
                CREATE TABLE IF NOT EXISTS governance_active (
                    agent_id TEXT PRIMARY KEY NOT NULL, policy_fingerprint TEXT NOT NULL,
                    baseline_fingerprint TEXT NOT NULL, baseline_metadata BLOB NOT NULL,
                    baseline_policy_fingerprint TEXT NOT NULL, generation INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS governance_assessments (
                    id TEXT PRIMARY KEY NOT NULL, agent_id TEXT NOT NULL, submitter TEXT NOT NULL,
                    generation INTEGER NOT NULL, request BLOB NOT NULL, decision BLOB NOT NULL
                );
                CREATE TABLE IF NOT EXISTS governance_approvals (
                    assessment_id TEXT NOT NULL REFERENCES governance_assessments(id),
                    actor TEXT NOT NULL, role TEXT NOT NULL, decision TEXT NOT NULL,
                    PRIMARY KEY (assessment_id, role), UNIQUE (assessment_id, actor)
                );
                CREATE TABLE IF NOT EXISTS governance_invalidations (
                    assessment_id TEXT PRIMARY KEY NOT NULL REFERENCES governance_assessments(id)
                );
                CREATE TABLE IF NOT EXISTS governance_audit (
                    id INTEGER PRIMARY KEY, agent_id TEXT, event TEXT NOT NULL,
                    actor TEXT NOT NULL, occurred_at TEXT NOT NULL, details BLOB NOT NULL
                );
                CREATE INDEX IF NOT EXISTS governance_audit_agent ON governance_audit(agent_id, id);
            """)

    def authenticate(self, token: str) -> str:
        provided = sha256(token.encode("utf-8"))
        for actor in self.actors.values():
            if hmac.compare_digest(actor.token_digest, provided):
                return actor.id
        raise Unauthorized("Invalid bearer credential")

    def _require_role(self, actor_id: str, role: str, agent_id: str) -> None:
        actor = self.actors.get(actor_id)
        if actor is None or not actor.has(role, agent_id):
            raise Unauthorized("Actor lacks the required role for this agent")

    def _require_access(self, actor_id: str, agent_id: str) -> None:
        actor = self.actors.get(actor_id)
        if actor is None or not any(agent_id in agents for agents in actor.grants.values()):
            raise Unauthorized("Actor has no access to this agent")

    def _audit(self, db: Connection, agent: str | None, event: str, actor: str, now: datetime, details: dict):
        db.execute(
            """INSERT INTO governance_audit (agent_id, event, actor, occurred_at, details)
               VALUES (?, ?, ?, ?, ?)""",
            (agent, event, actor, now.isoformat(), canonical_json(details)),
        )

    def register_policy(self, actor_id: str, policy: Policy) -> str:
        actor = self.actors.get(actor_id)
        if actor is None or not actor.grants.get("policy_admin"):
            raise Unauthorized("Policy registration requires a policy administrator")
        policy = Policy.from_json(policy.canonical_bytes())
        fingerprint = policy.fingerprint
        payload = policy.canonical_bytes()
        for control in policy.controls.values():
            for suite_fingerprint, revision in control.accepted_suites.items():
                suite = self.registry.get_suite(suite_fingerprint)
                if suite.checks.get(control.check_id) != revision:
                    raise GovernanceInputError("Accepted suite does not contain the configured check revision")
        with self.registry.transaction(write=True) as db:
            cursor = db.execute(
                "INSERT INTO governance_policies VALUES (?, ?, ?, ?) ON CONFLICT DO NOTHING",
                (fingerprint, policy.id, policy.revision, payload),
            )
            stored = db.execute(
                "SELECT payload FROM governance_policies WHERE policy_id = ? AND revision = ?",
                (policy.id, policy.revision),
            ).fetchone()
            if stored != (payload,):
                raise RecordConflict("Policy revision already exists with different content")
            if cursor.rowcount:
                self._audit(db, None, "policy_registered", actor_id, self.clock(), {
                    "policy_fingerprint": fingerprint, "policy_id": policy.id, "revision": policy.revision,
                })
        return fingerprint

    @staticmethod
    def _get_policy(db: Connection, fingerprint: str) -> Policy:
        row = db.execute("SELECT payload FROM governance_policies WHERE fingerprint = ?", (fingerprint,)).fetchone()
        if row is None:
            raise RecordMissing("Unknown governance policy")
        try:
            policy = Policy.from_json(row[0])
        except (ValueError, RecursionError) as error:
            raise RecordConflict("Stored policy is invalid") from error
        if policy.fingerprint != fingerprint:
            raise RecordConflict("Stored policy fingerprint mismatch")
        return policy

    def get_policy(self, fingerprint: str) -> Policy:
        with self.registry.transaction() as db:
            return self._get_policy(db, fingerprint)

    @staticmethod
    def _active(db: Connection, agent_id: str) -> dict | None:
        row = db.execute(
            """SELECT policy_fingerprint, baseline_fingerprint, baseline_metadata,
                      baseline_policy_fingerprint, generation
               FROM governance_active WHERE agent_id = ?""",
            (agent_id,),
        ).fetchone()
        if row is None:
            return None
        policy, baseline, metadata, baseline_policy, generation = row
        return {
            "policy_fingerprint": policy, "baseline_fingerprint": baseline,
            "baseline_metadata": json.loads(metadata), "baseline_policy_fingerprint": baseline_policy,
            "generation": generation,
        }

    def active(self, actor_id: str, agent_id: str) -> dict:
        self._require_access(actor_id, agent_id)
        with self.registry.transaction() as db:
            active = self._active(db, agent_id)
        if active is None:
            raise RecordMissing("Agent has no active policy")
        return active

    def activate(self, actor_id: str, agent_id: str, activation: Activation) -> dict:
        self._require_role(actor_id, "policy_admin", agent_id)
        with self.registry.transaction(write=True) as db:
            self._get_policy(db, activation.policy_fingerprint)
            baseline = self.registry.get_manifest(activation.baseline_fingerprint)
            if baseline.agent_id != agent_id:
                raise GovernanceInputError("Baseline must belong to the configured agent")
            current = self._active(db, agent_id)
            requested = activation.model_dump(mode="json")
            if current and all(current[key] == value for key, value in requested.items()):
                return current
            generation = 1 if current is None else current["generation"] + 1
            baseline_policy = activation.policy_fingerprint
            if current and current["baseline_fingerprint"] == activation.baseline_fingerprint:
                baseline_policy = current["baseline_policy_fingerprint"]
            db.execute(
                """INSERT INTO governance_active VALUES (?, ?, ?, ?, ?, ?)
                   ON CONFLICT (agent_id) DO UPDATE SET policy_fingerprint=excluded.policy_fingerprint,
                   baseline_fingerprint=excluded.baseline_fingerprint, baseline_metadata=excluded.baseline_metadata,
                   baseline_policy_fingerprint=excluded.baseline_policy_fingerprint, generation=excluded.generation""",
                (agent_id, activation.policy_fingerprint, activation.baseline_fingerprint,
                 activation.baseline_metadata.canonical_bytes(), baseline_policy, generation),
            )
            active = self._active(db, agent_id)
            self._audit(db, agent_id, "policy_activated", actor_id, self.clock(), active)
            return active

    def _classify(self, request, candidate, policy, now):
        attestation = request.runtime
        if candidate.scope is None:
            return None, {}, "declared_scope_missing"
        if attestation is None:
            return None, {}, "runtime_attestation_missing"
        statement = attestation.statement
        if statement.candidate_fingerprint != candidate.fingerprint or not signature_matches(
            self.trust.runtime_keys.get(statement.verifier), policy.runtime_verifier_keys.get(statement.verifier),
            runtime_signature_payload(statement), attestation.signature,
        ):
            return None, {}, "runtime_attestation_untrusted"
        try:
            verified_at = Evidence.require_explicit_offset(statement.verified_at)
            verified_at = Evidence.normalize_time(verified_at)
        except (ValueError, OverflowError):
            return None, {}, "runtime_time_invalid"
        if verified_at > now or now - verified_at > timedelta(seconds=policy.runtime_max_age_seconds):
            return None, {}, "runtime_attestation_stale"
        profile = statement.profile
        allows_writes = profile.effective_permissions in {"bounded_write", "external_egress_write"}
        if (statement.enforced_boundaries != candidate.scope.boundaries
                or allows_writes != statement.enforced_boundaries.can_write
                or (profile.effective_permissions.startswith("external_egress")
                    and not statement.enforced_boundaries.allowed_destinations)):
            return None, {}, "runtime_boundaries_unverified"
        matches = {
            field: {"value": value, "tier": policy.risk_rules[field][value]}
            for field, value in profile.model_dump().items()
        }
        return max((match["tier"] for match in matches.values()), key=TIERS.index), matches, None

    def _collect_evidence(self, request):
        records = []
        findings = []
        for proof in sorted(request.evidence, key=lambda item: item.evidence_id):
            reference = {"evidence_id": proof.evidence_id, "record_fingerprint": proof.record_fingerprint}
            try:
                evidence, _ = self.registry.get_evidence(proof.evidence_id)
            except RecordMissing:
                findings.append(reference | {"code": "evidence_not_found"})
                continue
            except (EvidenceMismatch, ValueError, RecursionError):
                findings.append(reference | {"code": "evidence_integrity_invalid"})
                continue
            if evidence.fingerprint != proof.record_fingerprint:
                findings.append(reference | {"code": "evidence_fingerprint_mismatch"})
            elif evidence.candidate_fingerprint != request.candidate_fingerprint:
                findings.append(reference | {"code": "evidence_wrong_candidate"})
            else:
                records.append((proof, evidence))
        return records, findings

    def _check_evidence(self, policy, control, proof, evidence, now):
        if control.accepted_suites.get(evidence.suite_fingerprint) != evidence.check_revision:
            return "evidence_suite_unaccepted"
        if evidence.producer not in control.producers or not signature_matches(
            self.trust.producer_keys.get(evidence.producer), policy.producer_keys.get(evidence.producer),
            evidence_signature_payload(evidence), proof.signature,
        ):
            return "evidence_producer_untrusted"
        if evidence.executed_at > now:
            return "evidence_from_future"
        if now - evidence.executed_at > timedelta(seconds=control.max_age_seconds):
            return "evidence_stale"
        if evidence.result != "passed":
            return "evidence_failed"
        return "control_passed"

    def _evaluate(self, db, candidate, request, active, now):
        result = {
            "candidate_fingerprint": request.candidate_fingerprint,
            "policy_fingerprint": active["policy_fingerprint"] if active else None,
            "baseline_fingerprint": active["baseline_fingerprint"] if active else None,
            "risk_tier": None,
            "risk_dimensions": {},
            "runtime_attestation": None,
            "change_categories": [],
            "classification_version": None,
            "mandatory_controls": [],
            "required_roles": [],
            "evidence": [proof.model_dump(exclude={"signature"}) for proof in request.evidence],
            "reasons": [],
            "eligibility": "blocked",
        }
        if not active:
            result["reasons"] = [{"code": "active_policy_missing"}]
            return result
        try:
            policy = self._get_policy(db, active["policy_fingerprint"])
            baseline = self.registry.get_manifest(active["baseline_fingerprint"])
            activation = Activation.model_validate({
                key: active[key] for key in ("policy_fingerprint", "baseline_fingerprint", "baseline_metadata")
            })
            comparison = compare_manifests(
                baseline, candidate, baseline_metadata=activation.baseline_metadata,
                candidate_metadata=request.metadata or activation.baseline_metadata,
            )
            categories = {category for change in comparison.changes for category in change.categories}
        except (RecordMissing, ValueError, RecursionError):
            result["reasons"] = [{"code": "governance_baseline_unverifiable"}]
            return result
        if active["baseline_policy_fingerprint"] != policy.fingerprint:
            categories.add("governance")
        result["change_categories"] = sorted(categories)
        result["classification_version"] = comparison.classification_version
        tier, matches, risk_error = self._classify(request, candidate, policy, now)
        if risk_error:
            result["reasons"] = [{"code": risk_error}]
            return result
        controls, roles = policy.requirements(tier, categories)
        result.update(risk_tier=tier, risk_dimensions=matches, mandatory_controls=controls, required_roles=roles)
        statement = request.runtime.statement
        result["runtime_attestation"] = {
            "verifier": statement.verifier, "verified_at": statement.verified_at,
            "fingerprint": sha256(runtime_signature_payload(statement)),
        }
        evidence_records, reasons = self._collect_evidence(request)
        for control_id in controls:
            control = policy.controls[control_id]
            matching = [(proof, evidence) for proof, evidence in evidence_records if evidence.check_id == control.check_id]
            if not matching:
                reasons.append({"code": "evidence_missing", "control": control_id})
            for proof, evidence in matching:
                reasons.append({
                    "code": self._check_evidence(policy, control, proof, evidence, now),
                    "control": control_id, "evidence_id": evidence.id, "record_fingerprint": evidence.fingerprint,
                    "suite_fingerprint": evidence.suite_fingerprint, "producer": evidence.producer,
                })
        result["reasons"] = reasons
        if all(reason["code"] == "control_passed" for reason in reasons):
            result["eligibility"] = "eligible"
        return result

    def assess(self, actor_id: str, request: AssessmentRequest) -> dict:
        with self.registry.transaction(write=True) as db:
            candidate = self.registry.get_manifest(request.candidate_fingerprint)
            agent = candidate.agent_id
            self._require_role(actor_id, "submitter", agent)
            now = self.clock()
            active = self._active(db, agent)
            decision = self._evaluate(db, candidate, request, active, now)
            assessment_id = uuid4().hex
            generation = active["generation"] if active else 0
            stored = decision | {"assessed_at": now.isoformat()}
            db.execute("INSERT INTO governance_assessments VALUES (?, ?, ?, ?, ?, ?)", (
                assessment_id, agent, actor_id, generation, request.canonical_bytes(), canonical_json(stored),
            ))
            self._audit(db, agent, "assessment_recorded", actor_id, now, stored | {
                "assessment_id": assessment_id, "generation": generation,
            })
            return self._view(db, assessment_id, agent, actor_id, generation, stored)

    @staticmethod
    def _assessment(db, assessment_id):
        row = db.execute(
            "SELECT agent_id, submitter, generation, request, decision FROM governance_assessments WHERE id = ?",
            (assessment_id,),
        ).fetchone()
        if row is None:
            raise RecordMissing("Unknown release assessment")
        return row[0], row[1], row[2], AssessmentRequest.from_json(row[3]), json.loads(row[4])

    @staticmethod
    def _approvals(db, assessment_id):
        return [
            {"actor": actor, "role": role, "decision": decision}
            for actor, role, decision in db.execute(
                "SELECT actor, role, decision FROM governance_approvals WHERE assessment_id = ? ORDER BY role",
                (assessment_id,),
            )
        ]

    def _view(self, db, assessment_id, agent, submitter, generation, decision):
        actions = self._approvals(db, assessment_id)
        active = self._active(db, agent)
        if decision["eligibility"] == "blocked":
            status = "blocked"
        elif any(action["decision"] == "decline" for action in actions):
            status = "declined"
        elif set(decision["required_roles"]) == {action["role"] for action in actions}:
            status = "approved"
        elif not active or active["generation"] != generation or self._invalidated(db, assessment_id):
            status = "stale"
        else:
            status = "pending"
        return decision | {
            "assessment_id": assessment_id, "agent_id": agent, "submitter": submitter,
            "authorization": status, "approvals": actions,
        }

    @staticmethod
    def _invalidated(db, assessment_id):
        return db.execute(
            "SELECT 1 FROM governance_invalidations WHERE assessment_id = ?", (assessment_id,)
        ).fetchone() is not None

    def get_assessment(self, actor_id, assessment_id):
        with self.registry.transaction() as db:
            agent, submitter, generation, _, decision = self._assessment(db, assessment_id)
            self._require_access(actor_id, agent)
            return self._view(db, assessment_id, agent, submitter, generation, decision)

    def decide(self, actor_id: str, assessment_id: str, approval: ApprovalRequest) -> dict:
        with self.registry.transaction(write=True) as db:
            agent, submitter, generation, request, decision = self._assessment(db, assessment_id)
            self._require_role(actor_id, approval.role, agent)
            if actor_id == submitter or approval.role not in decision["required_roles"]:
                raise Unauthorized("Approval requires a separate actor in a required role")
            view = self._view(db, assessment_id, agent, submitter, generation, decision)
            if view["authorization"] in {"approved", "declined", "blocked"} or self._invalidated(db, assessment_id):
                raise RecordConflict("Assessment is not open for approval")
            previous = view["approvals"]
            if any(actor_id == action["actor"] for action in previous):
                raise Unauthorized("Separate approval roles require different actors")
            if any(approval.role == action["role"] for action in previous):
                raise RecordConflict("The approval role already recorded a decision")
            now = self.clock()
            active = self._active(db, agent)
            try:
                candidate = self.registry.get_manifest(request.candidate_fingerprint)
                reassessed = self._evaluate(db, candidate, request, active, now)
            except (RecordMissing, ValueError, RecursionError):
                reassessed = {"eligibility": "blocked", "reasons": [{"code": "candidate_unverifiable"}]}
            scoped = all(
                action["actor"] in self.actors and self.actors[action["actor"]].has(action["role"], agent)
                for action in previous
            )
            stale = (
                not active or active["generation"] != generation or not scoped
                or reassessed != {key: value for key, value in decision.items() if key != "assessed_at"}
            )
            if stale:
                db.execute("INSERT INTO governance_invalidations VALUES (?)", (assessment_id,))
                self._audit(db, agent, "approval_rejected_stale", actor_id, now, {
                    "assessment_id": assessment_id, "role": approval.role, "decision": approval.decision,
                    "original_policy_fingerprint": decision["policy_fingerprint"], "reassessment": reassessed,
                    "active_generation": active["generation"] if active else None,
                })
                return view | {"authorization": "stale", "reassessment": reassessed}
            db.execute("INSERT INTO governance_approvals VALUES (?, ?, ?, ?)", (
                assessment_id, actor_id, approval.role, approval.decision,
            ))
            updated = self._view(db, assessment_id, agent, submitter, generation, decision)
            self._audit(db, agent, "human_decision_recorded", actor_id, now, {
                "assessment_id": assessment_id, "role": approval.role, "decision": approval.decision,
                "rationale": approval.rationale, "authorization": updated["authorization"],
                "reassessment": reassessed,
            })
            return updated

    def audit(self, actor_id: str, agent_id: str, after_id: int = 0) -> list[dict]:
        self._require_access(actor_id, agent_id)
        with self.registry.transaction() as db:
            return [
                {"id": identifier, "agent_id": agent, "event": event, "actor": actor,
                 "occurred_at": timestamp, "details": json.loads(details)}
                for identifier, agent, event, actor, timestamp, details in db.execute(
                    """SELECT id, agent_id, event, actor, occurred_at, details FROM governance_audit
                       WHERE (agent_id = ? OR agent_id IS NULL) AND id > ? ORDER BY id LIMIT 100""",
                    (agent_id, after_id),
                )
            ]
