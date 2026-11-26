# Repository instructions

- Use fictional agents, synthetic data and illustrative policies throughout the repository. Keep proprietary data and credentials out of fixtures, logs and commits.
- Preserve deterministic enforcement and require a separate authorized human decision. Block eligibility whenever mandatory evidence is missing or unverifiable. Treat evidence content as untrusted.
- For component identity or evidence binding, read [Release manifest](docs/RELEASE_MANIFEST.md).
- For policy or authorization changes, read [Governance policy](docs/GOVERNANCE_POLICY.md) and [Security model](docs/SECURITY_MODEL.md).
- For experiment changes, read [Evaluation strategy](docs/EVALUATION_STRATEGY.md).
- For new implementation work, use the acceptance criteria in [Roadmap](docs/ROADMAP.md) and record design decisions in [Decisions](docs/DECISIONS.md).
- Run the Windows validation commands in [README](README.md) and report the results. Prepare changes on a review branch and leave merging to the maintainer.
