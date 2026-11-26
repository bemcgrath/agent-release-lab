# Deterministic governance HTTP API

The local server exposes governance under `/v1/governance`. The existing Phase 1 registry endpoints still register manifests, suites, and evidence. Governed releases require a schema 2 manifest with structured scope, an accountable owner, an active baseline and policy, independently signed runtime claims, and authenticated evidence.

## Configure local identities and signing keys

Set `AGENT_RELEASE_LAB_TRUST` to the path of a local UTF-8 JSON configuration file before starting the server. The server reads the file at startup. Keep it outside the repository with access limited to the local operator. The default configuration grants no governance access. Continue to bind the service to loopback.

| Configuration field | Shape |
| --- | --- |
| `actors` | Array of actor objects with an `id`, a `token_digest` containing the lowercase SHA-256 of the actor's UTF-8 bearer token, and a `grants` map from role to explicit agent IDs |
| `producer_keys` | Map from evidence producer ID to its 32-byte HMAC key encoded as 64 lowercase hex characters |
| `runtime_keys` | Map from runtime verifier ID to its separately issued 32-byte HMAC key encoded as 64 lowercase hex characters |

Use distinct, random credentials and signing keys. An actor's client sends `Authorization: Bearer <token>`. Tokens identify actors independently of request bodies. Roles are `policy_admin`, `submitter`, `release`, and `security`. An agent-scoped administrator may set that agent's baseline and active policy. Any administrator with at least one grant may register a global policy revision. Policy lookup is available to authenticated actors. Assessments, active configuration, and audit history require an agent grant. Separate actor credentials represent separate accountable humans.

Restart the server to load trust changes. The service records a non-secret aggregate fingerprint and monotonically increasing generation when trust changes. Keys and individual token digests stay out of the audit. A process with a different trust fingerprint cannot write governance decisions. Pending approvals require reassessment after any trust change, including a change followed by rollback.

## Endpoints

| Method and path under `/v1/governance` | Request | Success response |
| --- | --- | --- |
| `POST /policies` | Policy YAML with `Content-Type: application/yaml` | Immutable policy `fingerprint` |
| `GET /policies/{fingerprint}` | Policy fingerprint | Fingerprint and parsed policy record |
| `PUT /agents/{agent_id}/owner` | Configured human `owner_id` and `rationale` | Accountable owner and assignment revision |
| `GET /agents/{agent_id}/owner` | Agent ID | Accountable owner and assignment revision |
| `POST /agents/{agent_id}/bootstrap` | First scoped `candidate_fingerprint` and `rationale` | Audited one-time baseline exception for that exact candidate |
| `PUT /agents/{agent_id}/active-policy` | `policy_fingerprint`, `baseline_fingerprint`, optional `baseline_metadata` | Active policy, baseline and generation |
| `GET /agents/{agent_id}/active-policy` | Agent ID | Active policy, baseline and generation |
| `POST /assessments` | Candidate fingerprint, runtime attestation, evidence proofs, optional `metadata` | Immutable eligibility result and current authorization state |
| `POST /evidence-reports` | Producer-authenticated `evidence_id`, `record_fingerprint`, `signature`, and optional `supersedes` reference | Immutable producer report receipt |
| `GET /assessments/{assessment_id}` | Assessment ID | Stored eligibility result, authorization state and human decisions |
| `POST /assessments/{assessment_id}/decisions` | `role` (`release` or `security`), `decision` (`approve` or `decline`), and nonblank `rationale` | Updated authorization state |
| `GET /agents/{agent_id}/audit?after_id=0` | Agent ID and optional event cursor | Up to 100 ordered audit events. Pass the last event ID to continue. |

Requests besides policy registration use the Phase 1 strict JSON boundary. Governance routes use actor bearer credentials except evidence reports, which authenticate the producer by its MAC. Missing or invalid bearer credentials return 401. A valid actor without scope, a separation-of-duties conflict, or an unauthenticated producer report receives 403. An unknown record returns 404. Conflicting writes and stale or closed approval attempts return 409. Invalid input or policy definitions return 422. A valid assessment with incomplete or failed checks returns 200 and `eligibility: blocked` with structured reason codes. During approval, a stale result includes the current reassessment and requires a new assessment.

## Establish the first baseline

An agent-scoped administrator assigns an accountable configured human owner and registers the first scoped manifest. Post its exact fingerprint and a rationale to `/bootstrap`; then activate the policy with that same fingerprint as the baseline. This exception permits evaluation of the first candidate through the ordinary gate and human approval workflow. It cannot serve as the baseline for another candidate. Once approved, the first release becomes an authorized baseline. Future activation accepts only releases previously approved for the same agent. Ownership alone grants no approval or administration rights.

## Build an assessment request

1. Register the candidate, evaluation suite and evidence artifact through the [Phase 1 API](API.md). Save the evidence record fingerprint returned at registration.
2. Have the configured producer sign the bytes from `agent_release_lab.governance.models.evidence_signature_payload(record)` using HMAC-SHA256. The message is canonical JSON containing the domain `agent-release-lab/evidence/v1` and the complete evidence record fingerprint. Report each completed run through `/evidence-reports` so its authentication is available independently of assessment requests.
3. Have a trusted runtime verifier inspect the candidate configuration and the effective runtime. It signs `runtime_signature_payload(statement)`, which includes the independent domain `agent-release-lab/runtime/v1` and a canonical statement with `candidate_fingerprint`, `verifier`, offset-bearing `verified_at`, `enforced_boundaries` and the six-field `profile`.
4. Submit `candidate_fingerprint` and `runtime: {"statement": {…}, "signature": "…"}`. The optional `evidence: [{"evidence_id": "…", "record_fingerprint": "…", "signature": "…"}]` provides inline proofs for registered runs. The service checks the full relevant registry inventory even when the array is empty. Signatures are lowercase hexadecimal SHA-256 MACs. Optional display metadata is compared with the administrator-supplied baseline display metadata.

For remediation, register a later passing run with its own evidence ID. Submit an evidence report with `supersedes: {"evidence_id": "…", "record_fingerprint": "…"}` and MAC the bytes from `rerun_signature_payload(new_record, predecessor)`. The service verifies both records refer to the same candidate, suite, check revision, and producer. An ordinary evidence MAC cannot authorize supersession. The old run remains visible in the decision with its replacement reference.

For an eligible response, inspect `required_roles`. Each required role submits its own decision with its own actor token. The submitter cannot approve the assessment, and a single actor cannot fill two approval roles. An eligible assessment can be pending, approved, declined, or stale. Final approvals and declines are historical decisions recorded at a specific time. Every response reports `deployment_authorization: not_evaluated`. The service has no deployment authorization endpoint.

## Illustrative policy structure

`schema_version` is the integer 1. The stable `id` and immutable `revision` are independent of deployment and suite versions. Use unique string keys throughout. Anchors, aliases, explicit YAML tags and implicit YAML-specific scalars are excluded.

| Field | Contents |
| --- | --- |
| `risk_rules` | Complete mapping from each accepted value in every dimension to `low`, `moderate`, or `high` |
| `producer_keys`, `runtime_verifier_keys` | Map from signer identity to SHA-256 digest of the corresponding configured 32-byte key |
| `runtime_max_age_seconds` | Positive integer maximum age for a verified runtime statement |
| `controls` | Map from control ID to `check_id`, `accepted_suites` (suite fingerprint to check revision), `max_age_seconds`, and a nonempty list of trusted `producers` |
| `universal_controls` | Nonempty list of control IDs for every assessment |
| `tier_controls` | Map from each of `low`, `moderate`, and `high` to additional control IDs |
| `change_controls` | Map from change category to additional control IDs |
| `tier_approval_roles` | Map from each tier to additional roles. The low tier includes `release`, and the high tier includes `security`. |

The executable [scenario runner](../tests/test_governance.py) generates a complete fictional YAML policy with real fixture suite fingerprints for test runs. See the [governance contract](GOVERNANCE_POLICY.md) for allowed dimension values, inheritance and trust limits.
