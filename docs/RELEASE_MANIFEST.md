# Release manifest contract

A manifest identifies one release configuration. The proposed v1 identity payload includes a schema version, fictional agent ID and a component mapping with required keys for model, prompt, harness, tools and business rules. Each component has a stable ID and an immutable revision or SHA-256 digest. A mutable model alias alone cannot establish a verifiable identity. Tool entries pin their interface and executable/configuration revisions. Prompts, harness settings and runtime parameters that affect behavior belong in the identity.

Parse the input into a strict typed payload before hashing. Reject unknown or duplicate keys, missing pins and ambiguous scalar types. Phase 1 should specify a canonical UTF-8 JSON encoding and golden vectors. Hash the canonical bytes with SHA-256 to obtain the candidate fingerprint. Human labels, timestamps and the selected comparison baseline are record metadata outside the hash. Any identity field change produces a new candidate fingerprint. Identical registration is idempotent.

## Evidence contract

Each evidence record carries a unique ID, candidate fingerprint, check ID and revision, dataset and runner revisions, execution time, result, artifact digest and source provenance. Evidence is verified against the artifact bytes and the policy's accepted provenance and freshness requirements. A matching digest verifies integrity and policy separately establishes whether the producer is trusted. Evidence for another fingerprint cannot satisfy a mandatory check. A targeted rerun must produce a new record for the new fingerprint.

Compare two candidates using their immutable fingerprints and display changed component pins. A comparison can suggest checks to rerun. Eligibility comes from assessment against the pinned policy.

## Evaluation suite identity

An evaluation suite has its own immutable ID, revision and content fingerprint. Its definition pins check IDs and revisions, dataset revision and digest, runner revision, scoring configuration and thresholds. Register a new suite revision for any change to those inputs. Resolve mutable references before assessment.

The candidate fingerprint covers the deployed configuration. Suite pins belong to the assessment and resulting evidence, outside the candidate fingerprint. If the deployed harness itself changes, its manifest pin changes even if a suite also uses that harness. Each assessment records the policy fingerprint, the suite revisions it resolved and the evidence records it evaluated. Each evidence record pins both the candidate fingerprint and the specific suite fingerprint, in addition to its check, dataset and runner provenance.

Verify that each mandatory record matches the candidate and a suite revision explicitly accepted by the current policy for that check. A new suite version preserves the historical meaning of old evidence. If the current policy retires that version or requires a changed check, run the accepted suite and register fresh evidence. A policy revision can reuse still-valid evidence while requiring a new assessment.

## Change classification

Compare the candidate against an explicit immutable baseline, and compare governance inputs against the prior assessment separately. Classify changes from a versioned field-to-category mapping. Retain every applicable category and combine their controls. Unknown fields or an unverifiable baseline require resolution before automated eligibility.

| Category | Examples | Required review |
| --- | --- | --- |
| Behavioral | Model, prompt, runtime harness, tool implementation, business rule | Pin the changed configuration and rerun applicable behavioral checks. |
| Administrative | Display label, documentation spelling, record timestamp | Record the change. Metadata outside the identity payload preserves the fingerprint and can reuse valid evidence. |
| Security | Trust boundary, sandbox configuration, artifact-signing configuration | Verify the applicable isolation, integrity or provenance controls. Pin runtime-affecting settings. |
| Permission | Tool scope, allowed destination, write capability | Pin effective permissions, reassess risk and verify least privilege and approval scope. Apply security controls when the trust boundary also changes. |
| Governance | Policy activation, accepted suite revisions, approval requirements | Reassess with the active governance inputs and validate evidence against them. |
