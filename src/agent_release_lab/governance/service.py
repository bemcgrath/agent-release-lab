"""Deterministic governance and transactional human decisions."""

import hmac
import json
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from sqlite3 import Connection
from uuid import uuid4

from ..comparison import compare_manifests
from ..evidence import Evidence
from ..identity import canonical_json, sha256
from ..registry import RecordConflict, RecordMissing, Registry
from .models import (
    TIERS, Activation, ApprovalRequest, AssessmentRequest, Bootstrap, EvidenceReport, LocalTrust,
    OwnershipAssignment, runtime_signature_payload, signature_matches,
)
from .policy import Policy
from .selection import authentic_proof, check_control, select_evidence, valid_rerun


class Unauthorized(PermissionError):
    """The actor lacks the required role or fails separation of duties."""


class GovernanceInputError(ValueError):
    """A proposed policy or activation is inconsistent with registered records."""


class Governance:
    def __init__(self, registry: Registry, trust: LocalTrust, clock: Callable[[], datetime] | None = None):
        self.registry = registry
        self.trust = LocalTrust.from_json(trust.canonical_bytes())
        self.trust_fingerprint = self.trust.fingerprint
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.actors = {actor.id: actor for actor in self.trust.actors}
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
                CREATE TABLE IF NOT EXISTS governance_trust_revisions (
                    generation INTEGER PRIMARY KEY, fingerprint TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS governance_owners (
                    agent_id TEXT PRIMARY KEY NOT NULL, owner_id TEXT NOT NULL, revision INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS governance_bootstraps (
                    agent_id TEXT PRIMARY KEY NOT NULL, candidate_fingerprint TEXT NOT NULL,
                    audit_id INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS governance_authorized_releases (
                    agent_id TEXT NOT NULL, candidate_fingerprint TEXT NOT NULL,
                    assessment_id TEXT NOT NULL REFERENCES governance_assessments(id),
                    PRIMARY KEY (agent_id, candidate_fingerprint)
                );
                CREATE TABLE IF NOT EXISTS governance_evidence_reports (
                    evidence_id TEXT PRIMARY KEY NOT NULL REFERENCES evidence(id), payload BLOB NOT NULL
                );
                CREATE TABLE IF NOT EXISTS governance_audit (
                    id INTEGER PRIMARY KEY, agent_id TEXT, event TEXT NOT NULL,
                    actor TEXT NOT NULL, occurred_at TEXT NOT NULL, details BLOB NOT NULL
                );
                CREATE INDEX IF NOT EXISTS governance_audit_agent ON governance_audit(agent_id, id);
            """)
            current = self._trust_revision(db)
            if current is None or current["fingerprint"] != self.trust_fingerprint:
                generation = 1 if current is None else current["generation"] + 1
                db.execute("INSERT INTO governance_trust_revisions VALUES (?, ?)", (generation, self.trust_fingerprint))
                self._audit(db, None, "trust_configuration_activated", "local-operator", self.clock(), {
                    "trust_fingerprint": self.trust_fingerprint, "trust_generation": generation,
                })

    @staticmethod
    def _trust_revision(db):
        row = db.execute(
            "SELECT fingerprint, generation FROM governance_trust_revisions ORDER BY generation DESC LIMIT 1"
        ).fetchone()
        return {"fingerprint": row[0], "generation": row[1]} if row else None

    def _require_current_trust(self, db):
        revision = self._trust_revision(db)
        if revision is None or revision["fingerprint"] != self.trust_fingerprint:
            raise RecordConflict("Server trust configuration is stale")
        return revision

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
        cursor = db.execute(
            """INSERT INTO governance_audit (agent_id, event, actor, occurred_at, details)
               VALUES (?, ?, ?, ?, ?)""",
            (agent, event, actor, now.isoformat(), canonical_json(details)),
        )
        return cursor.lastrowid

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
            self._require_current_trust(db)
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
    def _owner(db, agent_id):
        row = db.execute(
            "SELECT owner_id, revision FROM governance_owners WHERE agent_id = ?", (agent_id,)
        ).fetchone()
        return {"owner_id": row[0], "owner_revision": row[1]} if row else None

    def owner(self, actor_id, agent_id):
        self._require_access(actor_id, agent_id)
        with self.registry.transaction() as db:
            owner = self._owner(db, agent_id)
        if owner is None:
            raise RecordMissing("Agent has no accountable owner")
        return owner

    def assign_owner(self, actor_id: str, agent_id: str, assignment: OwnershipAssignment) -> dict:
        self._require_role(actor_id, "policy_admin", agent_id)
        if assignment.owner_id not in self.actors:
            raise GovernanceInputError("Owner must be a configured human identity")
        with self.registry.transaction(write=True) as db:
            self._require_current_trust(db)
            prior = self._owner(db, agent_id)
            if prior and prior["owner_id"] == assignment.owner_id:
                return prior
            revision = 1 if prior is None else prior["owner_revision"] + 1
            db.execute(
                """INSERT INTO governance_owners VALUES (?, ?, ?) ON CONFLICT (agent_id) DO UPDATE
                   SET owner_id=excluded.owner_id, revision=excluded.revision""",
                (agent_id, assignment.owner_id, revision),
            )
            owner = {"owner_id": assignment.owner_id, "owner_revision": revision}
            self._audit(db, agent_id, "agent_owner_assigned", actor_id, self.clock(), owner | {
                "previous_owner": prior, "rationale": assignment.rationale,
            })
            return owner

    def bootstrap(self, actor_id: str, agent_id: str, request: Bootstrap) -> dict:
        self._require_role(actor_id, "policy_admin", agent_id)
        with self.registry.transaction(write=True) as db:
            revision = self._require_current_trust(db)
            owner = self._owner(db, agent_id)
            if owner is None:
                raise RecordConflict("Assign an accountable owner before bootstrap")
            candidate = self.registry.get_manifest(request.candidate_fingerprint)
            if candidate.agent_id != agent_id or candidate.scope is None:
                raise GovernanceInputError("Bootstrap requires a scoped manifest for this agent")
            if db.execute("SELECT 1 FROM governance_authorized_releases WHERE agent_id = ?", (agent_id,)).fetchone():
                raise RecordConflict("Bootstrap is closed after first release authorization")
            if db.execute("SELECT 1 FROM governance_bootstraps WHERE agent_id = ?", (agent_id,)).fetchone():
                raise RecordConflict("This agent already has a recorded bootstrap baseline")
            details = request.model_dump() | owner | {"trust_fingerprint": revision["fingerprint"]}
            audit_id = self._audit(db, agent_id, "baseline_bootstrapped", actor_id, self.clock(), details)
            db.execute("INSERT INTO governance_bootstraps VALUES (?, ?, ?)", (
                agent_id, request.candidate_fingerprint, audit_id,
            ))
            return details | {"audit_id": audit_id}

    @staticmethod
    def _baseline_authority(db, agent_id, baseline_fingerprint):
        approved = db.execute(
            """SELECT assessment_id FROM governance_authorized_releases
               WHERE agent_id = ? AND candidate_fingerprint = ?""",
            (agent_id, baseline_fingerprint),
        ).fetchone()
        if approved is not None:
            return {"kind": "authorized_release", "assessment_id": approved[0]}
        if db.execute("SELECT 1 FROM governance_authorized_releases WHERE agent_id = ?", (agent_id,)).fetchone():
            return None
        bootstrap = db.execute(
            "SELECT audit_id FROM governance_bootstraps WHERE agent_id = ? AND candidate_fingerprint = ?",
            (agent_id, baseline_fingerprint),
        ).fetchone()
        return {"kind": "first_release_bootstrap", "audit_id": bootstrap[0]} if bootstrap else None

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
            self._require_current_trust(db)
            if self._owner(db, agent_id) is None:
                raise RecordConflict("Assign an accountable owner before policy activation")
            self._get_policy(db, activation.policy_fingerprint)
            baseline = self.registry.get_manifest(activation.baseline_fingerprint)
            if baseline.agent_id != agent_id:
                raise GovernanceInputError("Baseline must belong to the configured agent")
            authority = self._baseline_authority(db, agent_id, activation.baseline_fingerprint)
            if authority is None:
                raise RecordConflict("Baseline lacks prior release authorization or first-release bootstrap")
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
            self._audit(db, agent_id, "policy_activated", actor_id, self.clock(), active | {
                "baseline_authority": authority,
            })
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

    def report_evidence(self, report: EvidenceReport) -> dict:
        with self.registry.transaction(write=True) as db:
            trust_revision = self._require_current_trust(db)
            record, _ = self.registry.get_evidence(report.evidence_id)
            candidate = self.registry.get_manifest(record.candidate_fingerprint)
            active = self._active(db, candidate.agent_id)
            if active is None:
                raise RecordConflict("Evidence reports require an active policy")
            policy = self._get_policy(db, active["policy_fingerprint"])
            if not any(
                control.check_id == record.check_id
                and record.producer in control.producers
                and control.accepted_suites.get(record.suite_fingerprint) == record.check_revision
                for control in policy.controls.values()
            ) or not authentic_proof(record, report, policy, self.trust):
                raise Unauthorized("Evidence report is not authenticated for an accepted control")
            now = self.clock()
            if report.supersedes:
                previous, _ = self.registry.get_evidence(report.supersedes.evidence_id)
                if not valid_rerun(record, report.supersedes, previous, now):
                    raise GovernanceInputError("Rerun must pass, be later, and match the predecessor's binding")
            payload = report.canonical_bytes()
            cursor = db.execute(
                "INSERT INTO governance_evidence_reports VALUES (?, ?) ON CONFLICT DO NOTHING", (record.id, payload)
            )
            stored = db.execute(
                "SELECT payload FROM governance_evidence_reports WHERE evidence_id = ?", (record.id,)
            ).fetchone()
            if stored != (payload,):
                raise RecordConflict("An immutable producer report already exists for this record")
            details = report.model_dump(mode="json", exclude={"signature"}) | {
                "candidate_fingerprint": record.candidate_fingerprint, "policy_fingerprint": policy.fingerprint,
                "trust_fingerprint": trust_revision["fingerprint"], "result": record.result,
            }
            if cursor.rowcount:
                self._audit(db, candidate.agent_id, "producer_evidence_reported", record.producer, now, details)
            return details

    def _evaluate(self, db, candidate, request, active, now):
        trust_revision = self._trust_revision(db)
        owner = self._owner(db, candidate.agent_id)
        result = {
            "candidate_fingerprint": request.candidate_fingerprint,
            "policy_fingerprint": active["policy_fingerprint"] if active else None,
            "baseline_fingerprint": active["baseline_fingerprint"] if active else None,
            "baseline_authority": None,
            "trust_fingerprint": trust_revision["fingerprint"],
            "trust_generation": trust_revision["generation"],
            "ownership": owner,
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
        if trust_revision["fingerprint"] != self.trust_fingerprint:
            result["reasons"] = [{"code": "server_trust_stale"}]
            return result
        if owner is None or owner["owner_id"] not in self.actors:
            result["reasons"] = [{"code": "agent_owner_unverified"}]
            return result
        authority = self._baseline_authority(db, candidate.agent_id, active["baseline_fingerprint"])
        result["baseline_authority"] = authority
        if authority is None or (authority["kind"] == "first_release_bootstrap"
                                 and candidate.fingerprint != active["baseline_fingerprint"]):
            result["reasons"] = [{"code": "baseline_not_authorized"}]
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
        evidence_records, reasons, references = select_evidence(self.registry, db, request, policy, controls)
        result["evidence"] = references
        for control_id in controls:
            reasons.extend(check_control(policy, control_id, evidence_records, self.trust, now))
        result["reasons"] = reasons
        if all(reason["code"] in {"control_passed", "evidence_superseded"} for reason in reasons):
            result["eligibility"] = "eligible"
        return result

    def assess(self, actor_id: str, request: AssessmentRequest) -> dict:
        with self.registry.transaction(write=True) as db:
            self._require_current_trust(db)
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
        trust_revision = self._trust_revision(db)
        if decision["eligibility"] == "blocked":
            status = "blocked"
        elif any(action["decision"] == "decline" for action in actions):
            status = "declined"
        elif set(decision["required_roles"]) == {action["role"] for action in actions}:
            status = "approved"
        elif (not active or active["generation"] != generation or self._invalidated(db, assessment_id)
              or decision.get("trust_generation") != trust_revision["generation"]
              or decision.get("ownership") != self._owner(db, agent)):
            status = "stale"
        else:
            status = "pending"
        return decision | {
            "assessment_id": assessment_id, "agent_id": agent, "submitter": submitter,
            "authorization": status, "deployment_authorization": "not_evaluated", "approvals": actions,
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
            trust_revision = self._trust_revision(db)
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
                    "original_trust_fingerprint": decision.get("trust_fingerprint"),
                    "trust_fingerprint": trust_revision["fingerprint"],
                    "trust_generation": trust_revision["generation"],
                })
                return view | {"authorization": "stale", "reassessment": reassessed}
            db.execute("INSERT INTO governance_approvals VALUES (?, ?, ?, ?)", (
                assessment_id, actor_id, approval.role, approval.decision,
            ))
            updated = self._view(db, assessment_id, agent, submitter, generation, decision)
            if updated["authorization"] == "approved":
                db.execute(
                    "INSERT INTO governance_authorized_releases VALUES (?, ?, ?) ON CONFLICT DO NOTHING",
                    (agent, request.candidate_fingerprint, assessment_id),
                )
            self._audit(db, agent, "human_decision_recorded", actor_id, now, {
                "assessment_id": assessment_id, "role": approval.role, "decision": approval.decision,
                "rationale": approval.rationale, "authorization": updated["authorization"],
                "reassessment": reassessed,
                "trust_fingerprint": trust_revision["fingerprint"],
                "trust_generation": trust_revision["generation"],
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
