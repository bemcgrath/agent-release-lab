# Security model

Assume local Windows development with fictional agents, synthetic data and illustrative policies. Treat uploads, YAML, evidence artifacts, provider responses and browser inputs as untrusted. Identify submitters, reviewers and authorized approvers as separate roles in the design even when a developer exercises several roles locally.

| Risk | Planned control |
| --- | --- |
| Evidence substitution or replay | Require exact candidate binding, digest verification, check revision, provenance and policy freshness. |
| Embedded instructions | Pass evidence as bounded data. Give reviewers read-only access and validate structured outputs and evidence citations. |
| Parser abuse and unsafe attachments | Apply strict schemas and size limits, safe YAML loading and duplicate-key rejection. Store artifacts as inert data and escape rendered content. |
| Release bypass | Require deterministic eligibility and authorized human action at the server boundary. Reverify current inputs transactionally before approval. |
| Audit rewriting | Append events within application transactions. Local administrators can still alter SQLite files. Stronger tamper evidence remains open. |
| Data exposure | Keep secrets and enterprise data out of fixtures and audit text. Send only the needed synthetic context to configured providers. |

Fail closed when mandatory controls cannot verify their inputs. Provider failures leave deterministic assessment available and surface advisory unavailability. Bind the initial service to loopback. Any shared deployment requires a resolved identity model, audit integrity controls and a new threat review.

The Phase 2 trust file is server-owned. Protect its bearer-token digests and signing keys with local file permissions. Configure distinct credentials for each responsible human and signer. A shared HMAC key can be used by any holder to produce a valid proof, including the local server operator. HMAC therefore does not provide nonrepudiation or independently establish that a runtime observation or evaluation was truthful. Disable compromised signers by activating the updated trust configuration with the local operator command, restarting the server, and activating a policy with updated key pins. Changes to active trust or policy invalidate pending assessments.

The service assumes a trusted machine, operator, and SQLite store. Its append-only audit interface has no event mutation endpoint. An administrator with direct filesystem access can still change the database. Production identity federation, short-lived credentials, externally managed attestation keys, provider model identity verification, and tamper-evident audit storage remain open.

Governance evaluates the relevant registry inventory, including records omitted by the assessment submitter. This cannot detect a run that never reaches the registry. Producers must publish every relevant run independently for completeness. The loopback Phase 1 registration endpoints remain open to local clients, so a client can cause an availability failure by registering a relevant unverifiable record. Restrict access to the local service and plan authenticated producer ingestion before shared deployment.

An approved assessment remains a historical decision. The API reports deployment authorization as unevaluated. A deployment integration must implement the separate revalidation described in the [governance contract](GOVERNANCE_POLICY.md#deployment-authorization-is-deferred) before accepting releases.

The advisory provider receives immutable bytes and has no application tools or human credentials. Bounded evidence excerpts remain untrusted. The server validates structured output and citation pairs, and the dashboard inserts findings as text. An operator enabling an external provider permits the selected synthetic snapshot to be sent to that endpoint. This design limits the impact of model output and does not isolate arbitrary in-process provider code. See the [advisory security boundaries](ADVISORY_REVIEW.md#security-boundaries).
