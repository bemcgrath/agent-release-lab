"""Authoritative evidence selection and explicitly signed remediation runs."""

from dataclasses import dataclass

from ..evidence import Evidence, EvidenceMismatch
from ..registry import RecordMissing, Registry
from .models import (
    EvidenceProof, EvidenceReport, evidence_signature_payload, rerun_signature_payload, signature_matches,
)


@dataclass(frozen=True)
class SelectedEvidence:
    record: Evidence
    proof: EvidenceProof | None

    @property
    def reference(self) -> dict:
        return {"evidence_id": self.record.id, "record_fingerprint": self.record.fingerprint}


def authentic_proof(record, proof, policy, trust):
    if proof is None or proof.record_fingerprint != record.fingerprint:
        return False
    predecessor = proof.supersedes if isinstance(proof, EvidenceReport) else None
    payload = (
        rerun_signature_payload(record, predecessor) if predecessor else evidence_signature_payload(record)
    )
    return signature_matches(
        trust.producer_keys.get(record.producer), policy.producer_keys.get(record.producer),
        payload, proof.signature,
    )


def valid_rerun(record, predecessor, previous, now):
    return (
        record.result == "passed" and predecessor.record_fingerprint == previous.fingerprint
        and record.candidate_fingerprint == previous.candidate_fingerprint
        and record.suite_fingerprint == previous.suite_fingerprint
        and record.check_id == previous.check_id and record.check_revision == previous.check_revision
        and record.producer == previous.producer
        and previous.executed_at < record.executed_at <= now
    )


def select_evidence(registry: Registry, db, request, policy, controls):
    submitted = {proof.evidence_id: proof for proof in request.evidence}
    accepted_pairs = {
        (policy.controls[control_id].check_id, suite)
        for control_id in controls for suite in policy.controls[control_id].accepted_suites
    }
    accepted = {suite for _, suite in accepted_pairs}
    check_ids = {policy.controls[control_id].check_id for control_id in controls}
    registered = {
        evidence_id for evidence_id, suite in registry.evidence_index(db, request.candidate_fingerprint)
        if suite in accepted
    }
    findings = []
    records = []
    references = {}
    for evidence_id in sorted(registered | submitted.keys()):
        supplied = submitted.get(evidence_id)
        reference = {"evidence_id": evidence_id}
        if supplied is not None:
            reference["record_fingerprint"] = supplied.record_fingerprint
        try:
            record, _ = registry.get_evidence(evidence_id)
        except RecordMissing:
            findings.append(reference | {"code": "evidence_not_found"})
        except (EvidenceMismatch, ValueError, RecursionError):
            findings.append(reference | {"code": "evidence_integrity_invalid"})
        else:
            reference["record_fingerprint"] = record.fingerprint
            if supplied is not None and supplied.record_fingerprint != record.fingerprint:
                findings.append(reference | {"code": "evidence_fingerprint_mismatch"})
            elif record.candidate_fingerprint != request.candidate_fingerprint:
                findings.append(reference | {"code": "evidence_wrong_candidate"})
            elif record.check_id in check_ids and (
                supplied is not None or (record.check_id, record.suite_fingerprint) in accepted_pairs
            ):
                row = db.execute(
                    "SELECT payload FROM governance_evidence_reports WHERE evidence_id = ?", (evidence_id,)
                ).fetchone()
                try:
                    proof = EvidenceReport.from_json(row[0]) if row else supplied
                except (ValueError, RecursionError):
                    findings.append(reference | {"code": "evidence_report_invalid"})
                else:
                    if proof is not None and proof.evidence_id != evidence_id:
                        findings.append(reference | {"code": "evidence_report_invalid"})
                    else:
                        records.append(SelectedEvidence(record, proof))
            elif supplied is None:
                continue
        references[evidence_id] = reference
    return records, findings, list(references.values())


def check_control(policy, control_id, records, trust, now):
    control = policy.controls[control_id]
    relevant = [item for item in records if item.record.check_id == control.check_id]
    matching = {
        item.record.id: item for item in relevant
        if control.accepted_suites.get(item.record.suite_fingerprint) == item.record.check_revision
    }
    if not matching and relevant:
        return [
            item.reference | {"code": "evidence_suite_unaccepted", "control": control_id}
            for item in relevant
        ]
    if not matching:
        return [{"code": "evidence_missing", "control": control_id}]
    results = {}
    superseded = {}
    for item in matching.values():
        record, proof = item.record, item.proof
        if proof is None:
            code = "evidence_proof_missing"
        elif record.producer not in control.producers or not authentic_proof(record, proof, policy, trust):
            code = "evidence_producer_untrusted"
        elif record.executed_at > now:
            code = "evidence_from_future"
        elif (now - record.executed_at).total_seconds() > control.max_age_seconds:
            code = "evidence_stale"
        elif record.result != "passed":
            code = "evidence_failed"
        else:
            code = "control_passed"
        if isinstance(proof, EvidenceReport) and proof.supersedes and code == "control_passed":
            previous = matching.get(proof.supersedes.evidence_id)
            if previous and valid_rerun(record, proof.supersedes, previous.record, now):
                superseded[previous.record.id] = record.id
            else:
                code = "evidence_rerun_invalid"
        results[record.id] = item.reference | {
            "code": code, "control": control_id, "suite_fingerprint": record.suite_fingerprint,
            "producer": record.producer,
        }
    for previous, replacement in superseded.items():
        results[previous].update(code="evidence_superseded", superseded_by=replacement)
    return list(results.values())
