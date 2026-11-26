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
