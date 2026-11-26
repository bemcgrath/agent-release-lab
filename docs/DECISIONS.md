# Decisions and open questions

## Phase 0 decisions and assumptions

- Target Windows PowerShell and Python 3.12. Use a local, single-instance service and SQLite to keep operating costs low.
- Use strict typed identity payloads and proposed SHA-256 fingerprints. Evidence binds to the full candidate. Policy versions remain independently addressable and are pinned at assessment time.
- Separate deterministic eligibility, advisory findings and human authorization. Keep the deterministic path functional with every provider disabled.
- Use library version ranges for the Phase 0 scaffold. Reproducible experimental runs will record resolved dependency versions and pinned inputs.

## Open decisions

| Decision | Resolve by | Risk until resolved |
| --- | --- | --- |
| Canonical serialization, digest format and immutable provider model identifiers | Phase 1 | Different encoders or mutable aliases can produce ambiguous identity. |
| Trusted producer registration, evidence authentication and revocation | Phase 2 | An intact artifact may still originate from an untrusted source. |
| Approver identity, role provisioning and audit tamper evidence | Phase 2 local workflow, strengthen before shared deployment | Local database administrators can alter recorded history. |
| Reviewer provider, secondary reviewer independence and cost budget | Phase 4 | Model drift, correlated errors and changing costs can confound results. |
| Dataset size, calibration and analysis thresholds | Before Phase 4 measurements | Small or unrealistic synthetic cases can overstate results. |
| Open-source license selection | Before distribution as open source | Reuse terms require a maintainer decision. |

## Preliminary review decisions

- Pin suite revisions independently from deployment identity. Current policy determines accepted suite revisions and evidence validity. Classify changes by affected field and allow overlapping categories. Record configurable risk rules with the active policy.
- Use the 22-case synthetic dataset and provisional pilot criteria for the initial experiment design. Calibrate against held-out cases before claiming general results.
- Validate Python 3.12 on Windows and Linux in GitHub Actions.
- Recommend [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) for permissive reuse and its explicit contributor patent grant. The maintainer selects the final license and adds the license text and package metadata after approval.
