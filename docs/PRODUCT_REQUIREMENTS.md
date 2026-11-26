# Product requirements

The first use case is a reviewer evaluating a fictional agent release candidate. A submitter registers a manifest and supporting evidence. A release reviewer sees changes from the selected baseline, required checks and AI-identified risks. An authorized approver records a decision when the gate verifies eligibility. An auditor can reconstruct the assessment and decision.

## Research questions

1. Can independently versioned models, prompts, harnesses, tools and business rules be composed into one verifiable release?
2. Which changes invalidate evidence bound to the release, and how can targeted reruns limit evaluation cost?
3. How do AI review and deterministic checks differ in errors, risk detection and reproducibility?
4. Does independent secondary review improve risk detection while preserving mandatory controls?

## Requirements

- Register immutable manifests and versioned governance policies, and compare candidates against explicit baselines.
- Bind evaluation evidence to the exact release configuration. Show missing, stale and unverifiable evidence and block on any mandatory failure.
- Record policy and evidence references for every assessment. Present deterministic outcomes, AI recommendations and human decisions as distinct fields.
- Evaluate fictional cases using an experiment runner with labeled synthetic data and a reproducible run record.
- Run locally on Windows with a lightweight browser UI. The deterministic workflow runs without paid APIs or provider credentials.
- Maintain automated tests as features are delivered. Phase 0 ships planning, contracts and a health endpoint. See the [roadmap](ROADMAP.md) for implementation boundaries.
