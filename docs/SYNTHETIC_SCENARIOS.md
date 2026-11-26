# Synthetic release scenarios

Dataset revision `1.0.0`. Each row is an independent case for Ledger Finch, a fictional agent that reads synthetic ledger entries. Start from low-risk baseline L with pinned components, suite S1 accepted by policy P1, and fresh passing, verified evidence. Deltas preserve other inputs. For runtime identity changes, evidence remains bound to L unless the case states that fresh evidence is supplied for the candidate. “Eligible” indicates gate output. Human authorization is evaluated separately where specified.

| ID | Candidate or assessment delta | Expected gate | Reference risk or condition |
| --- | --- | --- | --- |
| 01 | Baseline L replay | Eligible | None |
| 02 | Display label corrected | Eligible | Administrative change |
| 03 | Model revision changes | Blocked | Wrong-candidate evidence |
| 04 | Prompt revision changes | Blocked | Wrong-candidate evidence |
| 05 | Runtime harness timeout changes | Blocked | Wrong-candidate evidence |
| 06 | Tool implementation changes | Blocked | Wrong-candidate evidence |
| 07 | Business rule changes with fresh passing candidate evidence | Eligible | Behavioral change verified |
| 08 | Required regression artifact omitted | Blocked | Missing evidence |
| 09 | Required regression check fails | Blocked | Failed check |
| 10 | Required evidence is older than policy permits | Blocked | Expired evidence |
| 11 | Evidence artifact digest disagrees with registry | Blocked | Integrity failure |
| 12 | Evidence source is unverifiable | Blocked | Unknown producer |
| 13 | Verified evidence includes prose asking the reviewer to ignore policy | Eligible | Embedded instruction is an advisory risk. All mandatory checks pass. |
| 14 | Policy accepts only S2. L has S1 evidence. | Blocked | Suite revision no longer accepted |
| 15 | Policy accepts both S1 and S2. L has S1 evidence. | Eligible | Accepted older suite |
| 16 | Policy now requires S2. L has verified passing S2 evidence. | Eligible | Suite-only reassessment for same fingerprint |
| 17 | Candidate gains bounded writes. Fresh regression passes. Rollback evidence is missing. | Blocked | Moderate tier rollback requirement |
| 18 | Candidate gains bounded writes. All moderate-tier evidence is fresh and verified. | Eligible | Moderate tier controls verified |
| 19 | Candidate gains external egress. Moderate controls pass. Security review is missing. | Blocked | High tier security review requirement |
| 20 | External egress candidate passes every high-tier check. Only the release approver signs. | Eligible | Authorization remains pending for security approval |
| 21 | Effective permissions cannot be verified | Blocked | Tier unresolved |
| 22 | Runtime trust boundary changes. Fresh regression passes. Required isolation evidence is missing. | Blocked | Security control missing |

Use explicit frozen timestamps, digests, risk labels and approval states when encoding fixtures for the runner. Keep the case IDs stable within this dataset revision and issue a new revision for label or case changes.

The [executable case data](../fixtures/governance/scenarios.json) and [pytest runner](../tests/test_governance.py) exercise all 22 cases against the deterministic gate with a fixed clock, synthetic signatures, and temporary SQLite storage. Case 20 additionally records the single authorized release approval and verifies that security approval remains pending.
