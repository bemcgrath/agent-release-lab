# Decisions and open questions

## Phase 0 decisions and assumptions

- Target Windows PowerShell and Python 3.12. Use a local, single-instance service and SQLite to keep operating costs low.
- Use strict typed identity payloads and proposed SHA-256 fingerprints. Evidence binds to the full candidate. Policy versions remain independently addressable and are pinned at assessment time.
- Separate deterministic eligibility, advisory findings and human authorization. Keep the deterministic path functional with every provider disabled.
- Use library version ranges for the Phase 0 scaffold. Reproducible experimental runs will record resolved dependency versions and pinned inputs.

## Open decisions

| Decision | Resolve by | Risk until resolved |
| --- | --- | --- |
| Provider-specific verification of immutable model revisions | Before provider integration | A provider may reuse a revision label. Registration relies on the producer's immutable reference or digest. |
| Central producer identity, key rotation automation and attestation revocation | Before shared deployment | Local key provisioning relies on trusted operators and policy changes for revocation. |
| Central human identity and audit tamper evidence | Before shared deployment | Local bearer credentials identify accounts and SQLite administrators can alter history. |
| Reviewer provider, secondary reviewer independence and cost budget | Phase 4 | Model drift, correlated errors and changing costs can confound results. |
| Dataset size, calibration and analysis thresholds | Before Phase 4 measurements | Small or unrealistic synthetic cases can overstate results. |

## Preliminary review decisions

- Pin suite revisions independently from deployment identity. Current policy determines accepted suite revisions and evidence validity. Classify changes by affected field and allow overlapping categories. Record configurable risk rules with the active policy.
- Use the 22-case synthetic dataset and provisional pilot criteria for the initial experiment design. Calibrate against held-out cases before claiming general results.
- Validate Python 3.12 on Windows and Linux in GitHub Actions.
- The maintainer approved [Apache License 2.0](../LICENSE) for permissive reuse and its explicit contributor patent grant. The package declares the SPDX expression `Apache-2.0` and includes the license text.

## Phase 1 decisions

- Hash compact canonical UTF-8 JSON with SHA-256. Include schema defaults and preserve array order and Unicode text. Represent fractional settings with decimal strings to avoid platform-dependent float representations.
- Store canonical records and inert artifact bytes in SQLite. Manifest fingerprints identify deployments, suite IDs and revisions identify immutable suite definitions, and evidence IDs identify individual runs.
- Apply the version 1 field mapping to deployment comparisons. Compare governance snapshots independently so governance changes preserve deployment identity.
- Keep the existing manifest schema and legacy suite fingerprints readable. Introduce manifest schema 2 for hashed operating scope and explicit schema version 1 for new HTTP suite and evidence submissions.
- Store and independently recompute the complete evidence record fingerprint. Require callers to supply a retained fingerprint for HTTP verification. Keep legacy rows without registration fingerprints and fail their verification.
- Use raw JSON intake for HTTP requests so duplicate keys reach the strict parser. Keep artifact bytes inert and expose integrity checks through the local API.

## Phase 2 decisions

- Hash validated policy content independently of YAML formatting. Store immutable policy versions separately from agent-scoped activation, and advance an activation generation for every change.
- Resolve risk by taking the highest result across six trust-attested input dimensions. A candidate's declared boundaries and verified effective boundaries are separate inputs.
- Authenticate local producer and verifier claims with separate HMAC keys pinned by the policy. Authenticate accountable human actors through separately provisioned bearer credentials and agent grants.
- Serialize approval reassessment and audit writes through the SQLite writer transaction. Require fresh assessment after invalidation and separate human release and security approvals for high-risk releases.
- Execute the 22 documented scenarios with synthetic fixture material. Keep provider identity verification, production key custody and external audit anchoring as separate design work.

## Independent Phase 2 review decisions

- Select evidence from the registry by candidate, mandatory check and accepted suites. Inline proofs supply authentication without limiting selection. Keep producer-reported supersessions immutable and signed over both records. Preserve predecessor records and show supersession in assessment reasons.
- Require an agent-scoped, audited bootstrap exception for the exact first candidate. For later comparisons require a baseline with a prior successful approval workflow for the same agent. Preserve audit history from earlier development builds without inferring trusted baselines from their assessments.
- Persist an accountable owner independently of policy and approval roles. Audit owner changes and include the revision in assessment snapshots.
- Record a non-secret trust fingerprint and persistent generation. Changing or restoring trust invalidates pending approvals, even when the change is unrelated to the candidate.
- Treat completed decisions as historical. Defer live deployment authorization and its single-use, target-specific authorization mechanism. The service never reports historical approval as an evaluated deployment authorization.
- Derive an authorized baseline's policy pin from its approving assessment. Trust changes require an explicit local operator command. Protected HTTP reads and decisions verify the active trust revision instead of activating the worker's local configuration.

## Phase 3 decisions

- Pass immutable canonical snapshots and call limits through the provider interface. Keep provider instructions separate from untrusted evidence content. Validate exact citation pairs and require uncertainty for uncited findings.
- Store advisory review output and trace data separately from governance and human decisions. Retain validated findings, and retain a fingerprint and reason for rejected provider output.
- Use a credential-free deterministic provider by default. Make external text-only chat completions opt-in with time, size, usage and concurrency limits.
- Serve the local dashboard with the application. Reuse the existing scoped human-decision endpoint and keep deployment authorization visibly unevaluated.
- Run the Ledger Finch demo against an isolated ephemeral registry using the same gate. Keep comparative experiments and a secondary reviewer for Phase 4.
- Reserve cumulative usage in the shared SQLite registry before provider calls. Charge reported usage when available and retain conservative reservations for estimates, unknown usage and interrupted calls.
- Capture prompt content, adapter revision, effective inference settings and the reviewer configuration digest. Allow opt-in bounded raw output retention and label model confidence as uncalibrated.
- Provide an explicit, billable smoke command over five synthetic scenarios. Keep live calls outside CI and require separate maintainer authorization.
