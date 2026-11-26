# Architecture

Python 3.12 hosts FastAPI with Pydantic input and output contracts. The planned interface uses HTML, CSS and JavaScript served locally. SQLite stores immutable records and audit events. YAML provides a human-editable policy and fixture format. pytest covers contracts and workflow invariants.

| Component | Responsibility |
| --- | --- |
| Manifest registry | Validate, fingerprint and store candidate configurations. |
| Policy registry | Register immutable policy revisions and resolve the active policy for assessment. |
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

## Target repository layout

Phase 0 establishes the root documentation and packaging files, `docs/`, the `src/agent_release_lab/` package with its FastAPI entry point, and `tests/`. Add the remaining directories with their first implementation as the [roadmap](ROADMAP.md) progresses.

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
│   ├── policies/             Versioned policies and deterministic checks
│   ├── evidence/             Evidence registration and verification
│   ├── reviewers/            Advisory reviewers and provider adapters
│   └── experiments/          Benchmark execution and scoring
├── schemas/                  Versioned contracts shared with external consumers
├── fixtures/                 Synthetic cases shared by tests and experiments
├── tests/                    Automated validation
├── web/                      Local HTML, CSS and JavaScript dashboard
└── .github/workflows/        Continuous integration
```
