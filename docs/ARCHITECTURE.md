# Architecture

Python 3.12 hosts FastAPI with Pydantic input and output contracts. A local dashboard uses HTML, CSS and JavaScript. SQLite stores immutable records and audit events. YAML provides a human-editable policy and fixture format. pytest covers contracts and workflow invariants.

| Component | Responsibility |
| --- | --- |
| Manifest registry | Validate, fingerprint and store candidate configurations. |
| Policy registry | Register immutable policy revisions and resolve the active policy for assessment. |
| Evaluation suite registry | Resolve independently versioned checks, datasets, runners and scoring settings. |
| Evidence registry | Store exact candidate bindings, artifact hashes and provenance. |
| Comparison engine | Diff explicit baseline and candidate manifests by component. |
| Deterministic engine | Verify policy and evidence and compute eligibility with reason codes. |
| AI reviewer | Return advisory findings, citations and uncertainty via a provider-independent adapter. |
| Synthetic dataset | Supply candidate, evidence, expected eligibility and labeled risks. |
| Experiment runner | Replay identical cases across the four comparison arms and record measurements. |
| Human approval | Enforce approver identity and scope and record the decision for an eligible assessment. |
| Audit history | Persist references and ordered events sufficient to reconstruct each assessment. |

The assessment pins candidate, policy revision and evidence inventory. The reviewer receives a read-only view of that snapshot. The adapter accepts structured context and returns advisory findings, provider/model identifiers, timing and usage. A deterministic fake supports local integration tests. Advisory outputs have no registry, gate or approval write privileges.

Approval rechecks gate inputs and active policy inside the same transaction as the decision and audit write. A policy change or required evidence change calls for reassessment. Use [manifest](RELEASE_MANIFEST.md), [policy](GOVERNANCE_POLICY.md) and [security](SECURITY_MODEL.md) contracts for implementation details.

The comparison classifies changes, the active policy classifies the agent's risk, and the gate combines the applicable requirements. Assessments pin suite revisions independently of candidate identity so policy can retire evidence without changing the deployed candidate. See the [manifest change and suite contracts](RELEASE_MANIFEST.md) and [risk policy](GOVERNANCE_POLICY.md).

The Phase 1 [HTTP API](API.md) exposes the SQLite registries, classified comparison, and evidence verification. A stored evidence fingerprint covers canonical metadata independently of the artifact digest. HTTP verification checks both and requires a fingerprint retained by the caller.

The [Phase 2 governance API](GOVERNANCE_API.md) adds an immutable policy registry, agent-scoped policy activation, deterministic assessments, human decisions, and an append-only audit history. The Phase 1 registry and governance records share one SQLite file. Approval reserves the writer slot before reading the active policy and verifying immutable registry inputs. This prevents a concurrent policy or evidence write from changing those inputs before the decision commits.

Assessment selects candidate evidence from the registry and reconciles authenticated producer reports, including explicit remediation links. Baselines refer to historical authorized releases after a one-time first-release bootstrap. The assessment records the owner, trust generation, policy and baseline authority so approval can check that those prerequisites are still current. Deployment authorization is a separate future boundary.

The [Phase 3 advisory reviewer](ADVISORY_REVIEW.md) builds immutable snapshots from recorded assessments. A provider receives text instructions and JSON bytes with bounded artifact excerpts. Schema and citation validation runs before findings enter the append-only advisory table. The dashboard reads governed state and advisory history separately. Its synthetic demonstration uses the same deterministic workflow and fake provider against an isolated temporary database.

## Target repository layout

Phase 0 establishes the root documentation and packaging files, `docs/`, the `src/agent_release_lab/` package with its FastAPI entry point, `tests/`, and the Python validation workflow. Add planned directories with their first implementation as the [roadmap](ROADMAP.md) progresses.

```text
agent-release-lab/
├── README.md                 Windows setup and project overview
├── AGENTS.md                 Repository instructions
├── pyproject.toml            Package metadata, dependencies and pytest settings
├── .gitignore
├── docs/                     Product, architecture and research specifications
├── src/agent_release_lab/
│   ├── __init__.py
│   ├── main.py               FastAPI entry point
│   ├── manifests/            Candidate identity, registry and comparison
│   ├── governance/           Policies, deterministic assessments and human decisions
│   ├── evidence/             Evidence registration and verification
│   ├── reviewers/            Advisory reviewers and provider adapters
│   ├── web/                  Packaged local dashboard assets
│   └── experiments/          Benchmark execution and scoring
├── schemas/                  Versioned contracts shared with external consumers
├── fixtures/                 Synthetic cases shared by tests and experiments
├── tests/                    Automated validation
└── .github/workflows/        Continuous integration
```
