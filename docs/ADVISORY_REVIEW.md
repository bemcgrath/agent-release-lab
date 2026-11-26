# Advisory reviewer and dashboard

Start the server as described in the [README](../README.md#run-locally-on-windows) and open `http://127.0.0.1:8000/`. The dashboard opens the synthetic Ledger Finch demonstration. Select a scenario to see missing tests, conflicting outcomes, instruction-like artifact text, an eligible release awaiting review, or a historically approved high-risk release. The demonstration uses the real deterministic gate and a credential-free fake reviewer in a temporary SQLite database. It never uses the configured external provider or the local registry.

To view local records, connect with a governance bearer credential. The browser keeps it in memory until you leave registry mode or reload. Inventory shows agents in your scope. Choose an assessment to inspect the comparison, control requirements, evidence and supersession, findings, and audit. Human decisions go through the existing scoped governance endpoint. The dashboard presents deterministic eligibility, historical approval, and unevaluated deployment authorization as separate statuses.

## Provider configuration

The default provider is `fake`. Set `AGENT_RELEASE_LAB_REVIEWER_CONFIG` to a local UTF-8 JSON file to select another configuration. Restart the server after editing it. Configuration is loaded on the first review request so a bad reviewer configuration does not prevent deterministic assessment or human decisions.

| Key | Default | Meaning |
| --- | --- | --- |
| `provider` | `fake` | `fake` or `chat-completions` |
| `model` | `ledger-fake-v1` | Requested model ID. Supply it explicitly for an external provider. |
| `prompt_version` | `v1` | Versioned built-in prompt, `v1` or `v2` |
| `timeout_seconds` | 15 | Per-call wall-clock timeout, from 1 to 120 seconds |
| `max_input_bytes` | 48000 | Limit for the prompt and canonical snapshot together |
| `max_output_tokens` | 1800 | Maximum output requested from the provider before applying the total budget |
| `max_total_tokens` | 52000 | Per-review token budget. A conservative UTF-8 byte estimate and framing allowance reserve input budget before a remote call. |
| `cumulative_token_budget` | 1000000 | Lifetime accounting limit for the review ledger in this SQLite file. Set to zero to disable provider calls. |
| `retain_provider_output` | false | Store up to 16 KiB of raw provider text in a separate local table for experimental inspection. |
| `endpoint` | unset | Full chat-completions URL, required for `chat-completions`. HTTPS or loopback HTTP. |

The optional HTTP adapter uses the text-only chat-completions contract with JSON-object response format and a completion limit. It supplies no tools or callbacks, and redirects are disabled. Supply a provider bearer credential through `AGENT_RELEASE_LAB_REVIEWER_TOKEN` if required by the endpoint. This credential is separate from local governance credentials. A [chat-completions reference](https://developers.openai.com/api/reference/resources/chat) documents the expected request shape. Live vendor access is opt-in and may incur charges. The demo and tests need no account.

Before a call, a SQLite writer transaction reserves the full per-review token budget against the cumulative limit. Concurrent workers share that ledger. Known provider usage settles the reservation to the reported total. Estimated usage keeps at least the reservation, and unknown usage keeps the full reservation. A crash can leave an unresolved reservation and it continues to count. A provider can report more than the reserved allowance. The result is rejected, the overage is recorded, and later calls are blocked when the ledger reaches its limit. This is an application token budget, and remote billing uses the provider's own accounting. A timed-out adapter cannot supply later findings. Its worker may continue until the transport returns, and concurrency limits bound that work.

Run all server workers against the same database and operator-approved budget configuration. Existing review records from before the accounting ledger are preserved and excluded from the new cumulative counter. Use the local `advisory_usage` table to inspect reservations, charges and usage sources.

## Live provider smoke test

The opt-in smoke command exercises one chat-completions model against all five isolated Ledger Finch scenarios. Save a reviewer JSON configuration for the chosen external model and endpoint. Set `AGENT_RELEASE_LAB_REVIEWER_TOKEN` separately if needed. Obtain maintainer authorization for billable calls before supplying `--allow-charges`. Use the provider's applicable rates in USD per million tokens.

```powershell
.\.venv\Scripts\python.exe -m agent_release_lab.reviewers.smoke --allow-charges --config reviewer.json --input-usd-per-million INPUT_RATE --output-usd-per-million OUTPUT_RATE
```

Replace `INPUT_RATE` and `OUTPUT_RATE` with numeric rates. The command emits JSON containing scenario, requested and returned model, structured-output and citation validity, usage source and counts, latency, and estimated USD cost. Unknown usage leaves cost unset. The batch verifies capacity for five reservations before the first call and exits nonzero if any scenario fails. The automated tests exercise the smoke command and all scenarios with local stubs. A live service run requires separate authorization and is pending.

## Reviewer contract

A review request identifies an existing deterministic assessment. The service constructs canonical immutable bytes from its recorded gate result, pinned candidate and baseline, applicable policy controls, and recorded evidence references. It checks the available registry record and artifact against the candidate and evidence fingerprint before including an excerpt of at most 512 bytes. Evidence registered later is outside the assessment snapshot. Unavailable entries remain visible with their identifiers and can neither provide excerpts nor serve as citations.

Providers implement `ReviewerProvider.review(ReviewInput) -> ProviderReply`. The request contains only immutable snapshot bytes, separate instructions, model and call limits. Treat every value in the snapshot, including artifact excerpts, as untrusted data. Server-side validation rejects duplicate keys, unknown fields, invalid categories or severity, ambiguous scalar types, unsupported citation pairs, and uncited findings without explicit uncertainty. Citation pairs contain an evidence ID and its exact record fingerprint. Valid citations establish which registered data a finding refers to. They do not prove that the inference is accurate.

Each accepted finding has a unique ID, risk category, severity, description, evidence citations, suggested remediation, model-reported confidence from 0 to 100, and uncertainty where appropriate. Confidence is uncalibrated. The fake uses deterministic heuristics for contradictions, risk and scope changes, missing tests, and instruction-like text. It is a demonstration and test double for the adapter boundary.

Review records contain the requested and returned model identities, adapter revision, complete non-secret reviewer configuration fingerprint, effective inference parameters, prompt content and fingerprint, input fingerprint, validated output, elapsed time, usage and status. Sampling follows recorded provider defaults. The local registry retains the canonical input for reproducibility. An optional bounded copy of raw provider text lives in a separate table and is unavailable through dashboard routes. A rejected output is represented by a reason and output fingerprint when available. Provider failures produce an unavailable result while existing eligibility and human decisions remain accessible.

## HTTP endpoints

| Request | Purpose |
| --- | --- |
| `GET /` | Local dashboard |
| `GET /v1/demo/ledger-finch/{scenario}` | Read the isolated demonstration. Scenarios are `ready`, `blocked`, `suspicious`, `conflict`, and `approved`. |
| `GET /v1/dashboard/agents` | Scoped agent inventory and owner records |
| `GET /v1/dashboard/agents/{agent_id}/releases` | Candidate and assessment history for that agent |
| `GET /v1/dashboard/assessments/{assessment_id}` | Deterministic assessment, comparison, evidence summary, policy controls, and review records |
| `POST /v1/advisory/reviews` | Run and record a review. Send `{"assessment_id":"…"}` as JSON. |
| `GET /v1/advisory/reviews?assessment_id=…` | List recent reviews for the assessment |
| `GET /v1/advisory/reviews/{review_id}` | Retrieve a scoped review record |

Registry views and advisory endpoints use the existing agent-scoped bearer mechanism. Audit and human decisions use the [governance API](GOVERNANCE_API.md). Candidate history and review lists return the most recent 50 entries. Audit history keeps its existing cursor.

Each displayed candidate shows its latest assessment independently of the recent assessment list. The dashboard and reviewer use the recorded comparison, including administrative changes, and recorded policy requirements. Older assessments without those details remain readable and show the comparison as unavailable. Trust and scope are rechecked in the transaction that stores a review. A trust change during the provider call discards the result.

## Security boundaries

Advisory records are append-only in a separate table. The provider receives no registry object, execution tools, human credentials, or authority to update eligibility, policy, risk or approval. The dashboard renders returned strings as text. Scoped humans still approve through the deterministic governance API, which runs its existing transactional reassessment. Historical approval does not authorize deployment.

A registered external adapter is trusted application code. The in-process interface is a capability boundary for data and model output, not isolation for arbitrary plugin code. External review sends the snapshot, including bounded excerpts, to the configured endpoint. Use synthetic data and review the operator's data handling requirements before enabling an external service. Provider results can be inaccurate or influenced by untrusted data even when they satisfy the schema. Humans evaluate the findings before taking action.
