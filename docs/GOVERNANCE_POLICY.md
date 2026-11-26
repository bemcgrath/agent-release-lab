# Governance policy contract

A policy revision has a policy ID, version, content fingerprint and schema version. Its YAML defines mandatory check IDs and accepted revisions, artifact and provenance requirements, freshness constraints and authorized approval scopes. The registry validates the schema before activation and prevents editing published revisions. Resolve and record an explicit revision at assessment time.

## Decision rules

1. Verify the candidate and applicable policy revision. Evaluate every mandatory control against evidence bound to the candidate fingerprint.
2. Return `blocked` for any mandatory failure or missing, expired, mismatched or unverifiable required evidence. An unavailable verification produces a blocking reason.
3. Return `eligible` once every mandatory control passes. Record the policy fingerprint, candidate fingerprint, evaluated evidence references, assessment time and per-control reason codes for either outcome.
4. Record AI advice separately. AI may flag additional risk for human review. The gate result is determined solely by the verified inputs and policy.
5. Require an authorized human to record approval for a current, eligible assessment. Record actor, scope, outcome, time and rationale in the audit history. A human can decline an eligible candidate. A blocked candidate requires remediation and reassessment before approval.

Illustrative policy rule: require a passing regression check of an accepted revision, executed within seven days by a registered synthetic runner, with its artifact digest verified. Evaluate freshness against an explicit assessment time and use the same clock input during replay.

## Configurable agent risk classification

Store risk rules and tier-to-control mappings in the immutable policy revision. Classify the candidate deterministically from declared and verified capabilities, effective permissions, data exposure, autonomy, reversibility and impact. Evaluate all matching rules and select the highest applicable tier. Missing or unverifiable input blocks eligibility until it is resolved. An assessment records the tier, matched rules and resolved mandatory controls. Recompute after capability, permission or policy changes.

| Illustrative tier | Example condition | Mandatory requirements |
| --- | --- | --- |
| Low | Local, read-only access to synthetic records | Baseline regression and an authorized release approver. |
| Moderate | Bounded, reversible writes to synthetic records | Low controls plus least-privilege and rollback checks. |
| High | External egress, sensitive synthetic data or irreversible action | Moderate controls plus security review evidence and separate security and release approvers. |

Combine universal, tier-specific and change-category controls. A category or tier may add requirements. Policy activation validates that higher tiers retain lower-tier requirements and every tier preserves the universal evidence and human authorization rules. The illustrative thresholds, check suites and approver scopes are configurable governance inputs.

## Deterministic classification and verification

The server classifies all six verified dimensions and takes the highest configured tier. Policy validation requires a label for every value and enforces the minimum tiers below. A policy can raise a tier assignment.

| Verified dimension | Values and minimum tiers |
| --- | --- |
| Capabilities | `read` low, `write` moderate, `external` high |
| Effective permissions | `read_only` low, `bounded_write` moderate, `external_egress` and `external_egress_write` high |
| Data exposure | `synthetic` low, `sensitive` high |
| Autonomy | `supervised` and `bounded` low, `autonomous` high |
| Reversibility | `reversible` low, `irreversible` high |
| Impact | `low` low, `moderate` moderate, `high` high |

The runtime verifier signs observations independently of the manifest author. A declaration alone cannot establish enforcement. The signed scope must match the declaration, the write observation must agree with the effective permission, and external egress must have a declared destination. Missing, stale, forged, mismatched, and unsupported risk inputs block eligibility or reject an invalid request. The local service relies on the configured verifier to make truthful runtime observations.

An administrator selects the immutable baseline. The service derives categories from the registered candidate and baseline and applies every matching category's requirements. A change from the policy pinned to the baseline also adds the governance category. A tier automatically inherits the checks and approval roles of lower tiers. Controls are combined by ID. Every mandatory control needs submitted evidence. Each matching proof must pass, so a passing proof does not mask a failed or stale proof submitted for the same control.

Evidence validation recomputes the record and artifact digests, checks the candidate and suite binding and the suite's check revision, and compares the record fingerprint with the fingerprint retained by the caller. It then checks the control's accepted suite revisions and freshness, verifies the producer MAC against a policy-pinned key, and requires a passing result. Digest checks establish integrity, and the MAC establishes possession of a trusted producer's key. They do not establish that the producer performed a truthful evaluation.

Reasons carry stable machine-readable codes. Common failures include `active_policy_missing`, `runtime_attestation_untrusted`, `runtime_boundaries_unverified`, `evidence_missing`, `evidence_wrong_candidate`, `evidence_integrity_invalid`, `evidence_producer_untrusted`, `evidence_suite_unaccepted`, `evidence_failed`, and `evidence_stale`. Successful checks return `control_passed`. Assessment records include the policy and baseline fingerprints, matched risk values, effective control and role lists, evidence references, and timestamp.

## Approval and audit

Policy and baseline activation is scoped to the configured agent and advances a generation for each change. Restoring a previous policy also changes the generation. Each decision uses one SQLite writer transaction to re-evaluate the candidate against current policy, runtime freshness, evidence, and actor scopes. A stale result invalidates the assessment and needs a fresh submission. Concurrent decisions are serialized and each role and each actor can record at most one decision for an assessment.

The release submitter cannot approve that assessment. High-risk releases require distinct release and security approvers, each with an explicit agent grant. A decline is terminal. The service appends events for policy registration, activation, assessment, stale approval rejection, and successful human decisions. The audit records include linked assessment IDs, actor, role, rationale, timestamps, and policy and evidence references. The local SQLite administrator can still alter the database directly. See the [Governance API](GOVERNANCE_API.md) for request and configuration details.
