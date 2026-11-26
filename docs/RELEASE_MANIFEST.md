# Release manifest contract

A manifest identifies one release configuration. The proposed v1 identity payload includes a schema version, fictional agent ID and a component mapping with required keys for model, prompt, harness, tools and business rules. Each component has a stable ID and an immutable revision or SHA-256 digest. A mutable model alias alone cannot establish a verifiable identity. Tool entries pin their interface and executable/configuration revisions. Prompts, harness settings and runtime parameters that affect behavior belong in the identity.

Parse the input into a strict typed payload before hashing. Reject unknown or duplicate keys, missing pins and ambiguous scalar types. Phase 1 should specify a canonical UTF-8 JSON encoding and golden vectors. Hash the canonical bytes with SHA-256 to obtain the candidate fingerprint. Human labels, timestamps and the selected comparison baseline are record metadata outside the hash. Any identity field change produces a new candidate fingerprint. Identical registration is idempotent.

## Evidence contract

Each evidence record carries a unique ID, candidate fingerprint, check ID and revision, dataset and runner revisions, execution time, result, artifact digest and source provenance. Evidence is verified against the artifact bytes and the policy's accepted provenance and freshness requirements. A matching digest verifies integrity and policy separately establishes whether the producer is trusted. Evidence for another fingerprint cannot satisfy a mandatory check. A targeted rerun must produce a new record for the new fingerprint.

Compare two candidates using their immutable fingerprints and display changed component pins. A comparison can suggest checks to rerun. Eligibility comes from assessment against the pinned policy.
