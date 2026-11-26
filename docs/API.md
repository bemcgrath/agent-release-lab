# Phase 1 HTTP API

Run the server using the [Windows setup](../README.md#run-locally-on-windows). The registry opens `agent-release-lab.sqlite3` in the starting directory on the first registry request. Set `AGENT_RELEASE_LAB_DB` before startup to use a different SQLite file. Use a local, loopback-bound service with synthetic data.

## Requests and responses

Send UTF-8 JSON with `Content-Type: application/json` for POST requests. The API reads the raw body and applies the same strict parser as the Python contracts. Duplicate keys at any depth, unknown fields, unsupported versions, and ambiguous scalar types are rejected. The encoded JSON body may be at most 8 MiB. Evidence bytes use standard padded base64 inside JSON.

| Method and path | Request | Success response |
| --- | --- | --- |
| `GET /health` | None | `{"status":"ok"}` |
| `POST /v1/manifests` | Manifest with `schema_version` 1 or 2. Version 2 requires structured scope. | `{"fingerprint":"…"}` |
| `GET /v1/manifests/{fingerprint}` | Manifest fingerprint | `{"fingerprint":"…","record":{…}}` |
| `POST /v1/suites` | Evaluation suite with explicit `schema_version` 1 | `{"fingerprint":"…"}` |
| `GET /v1/suites/{fingerprint}` | Suite fingerprint | `{"fingerprint":"…","record":{…}}` |
| `POST /v1/evidence` | `{"record":{…},"artifact_base64":"…"}`. The record requires explicit `schema_version` 1. | `{"id":"…","fingerprint":"…"}`. Retain the fingerprint independently for verification. |
| `GET /v1/evidence/{evidence_id}` | Evidence ID | `{"fingerprint":"…","record":{…},"artifact_base64":"…"}` after integrity and binding checks |
| `POST /v1/comparisons` | `baseline_fingerprint` and `candidate_fingerprint`. Optional `baseline_metadata` and `candidate_metadata` must be supplied together. | Both fingerprints, classification version, and changes with `field`, `categories`, `before`, and `after`. |
| `POST /v1/evidence-verifications` | `evidence_id`, `candidate_fingerprint`, `suite_fingerprint`, and independently retained `expected_record_fingerprint` | `{"verified":true,"fingerprint":"…"}` when the record, artifact, and expected bindings match |

Successful responses use HTTP 200, including identical registration retries. A missing stored record returns 404. Reusing an immutable suite revision or evidence ID with different content, or detecting a missing or mismatched stored evidence record fingerprint, returns 409. An invalid payload or verification mismatch returns 422. Unsupported media and oversized bodies return 415 and 413 respectively.

## Record fields

- **Manifest** requires `schema_version`, `agent_id`, and `components`. Components are `model`, `prompt`, `harness`, `business_rules`, and a `tools` map. Each component pin includes `id` and at least one of `revision` or `digest`. A tool entry has `interface`, `executable`, and `configuration` pins, with optional `permissions` and `security` objects. Manifest-level `runtime` and `security` are optional.
- **Manifest scope** in schema 2 requires `purpose`, a nonempty `allowed_tasks` list, and `boundaries` with `allowed_tools`, `allowed_data_sources`, `allowed_destinations`, and Boolean `can_write`. Identifiers such as `ledger-reconciliation` and `synthetic-ledger` are fictional. Empty boundary lists express no allowed items.
- **Suite** requires `schema_version`, `id`, `revision`, a `checks` map from check IDs to revisions, `dataset` containing `id`, `revision`, and `digest`, a `runner` pin, plus `scoring` and `thresholds` objects.
- **Evidence** requires `schema_version`, `id`, `candidate_fingerprint`, `suite_fingerprint`, `check_id`, `check_revision`, `dataset`, `runner`, `executed_at` with explicit UTC offset, `result` (`passed`, `failed`, or `error`), `artifact_digest`, `producer`, and `source`. Register the manifest and suite first.
- **Administrative metadata** accepts `label` and `description` for comparison. The request supplies these display values separately from the stored manifest identity.

Fingerprints and digests are 64 lowercase hexadecimal characters. A verification response confirms integrity and binding. The original evaluation result remains in the evidence record, and Phase 2 will determine which evidence satisfies release policy. See the [record contracts](RELEASE_MANIFEST.md) for versioning, legacy data, and trust limits.
