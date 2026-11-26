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
| Trusted producer registration, evidence authentication and revocation | Phase 2 | An intact artifact may still originate from an untrusted source. |
| Approver identity, role provisioning and audit tamper evidence | Phase 2 local workflow, strengthen before shared deployment | Local database administrators can alter recorded history. |
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
