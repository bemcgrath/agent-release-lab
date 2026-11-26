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
