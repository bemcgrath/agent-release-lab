# Release manifest contract

A manifest identifies one release configuration. The proposed v1 identity payload includes a schema version, fictional agent ID and a component mapping with required keys for model, prompt, harness, tools and business rules. Each component has a stable ID and an immutable revision or SHA-256 digest. A mutable model alias alone cannot establish a verifiable identity. Tool entries pin their interface and executable/configuration revisions. Prompts, harness settings and runtime parameters that affect behavior belong in the identity.

Parse the input into a strict typed payload before hashing. Reject unknown or duplicate keys, missing pins and ambiguous scalar types. Hash the canonical bytes with SHA-256 to obtain the candidate fingerprint. Human labels, timestamps and the selected comparison baseline are record metadata outside the hash. Any identity field change produces a new candidate fingerprint. Identical registration is idempotent.

### Canonical format and Python interfaces

Use `Manifest.from_json`, `EvaluationSuite.from_json` and `Evidence.from_json` for submitted JSON. These constructors reject duplicate keys at every nesting level. The version 1 encoding serializes the validated model with defaults included, keys sorted by Unicode code point, compact JSON separators, and UTF-8 encoding without a BOM or trailing newline. Unicode text is preserved without normalization. Array order is significant. Use integer values or explicit decimal strings for fractional settings and thresholds. Evidence timestamps must include an offset and are normalized to UTC. SHA-256 digests use 64 lowercase hexadecimal characters. Tests pin manifest and suite golden fingerprints.

The deployed tool map is keyed by tool ID. Each tool pins its interface, executable and configuration, and records effective permissions and security settings. The manifest also records runtime and security settings that apply to the agent as a whole. The importer rejects common mutable revision aliases. Producers must supply immutable provider references or verified digests because the local registry cannot establish whether a provider reuses a revision label.

`Registry` in `agent_release_lab.registry` opens a SQLite file. Register manifests and suites first to obtain fingerprints. Then register evidence with the original artifact bytes and recover it with `get_verified_evidence`, supplying the expected candidate and suite fingerprints. Changes to a registered suite ID and revision or evidence ID require a new revision or ID. Use `Registry.compare` to compare stored manifests by fingerprint. Use `compare_manifests` with paired metadata and `compare_governance` with two snapshots for administrative and governance changes. Classification mapping version 1 treats effective tool permission changes as both permission and security changes.

Registry verification checks binding, suite membership and artifact integrity. Phase 2 owns trust, freshness, accepted-suite policy selection and release authorization.

## Schema versions and operating scope

Manifest schema 1 preserves its canonical encoding and fingerprints. Manifest schema 2 adds a required `scope` with a structured purpose identifier, allowed task identifiers, and operating boundaries for tools, data sources, destinations, and write access. These restrictions are identity fields. A scope change alters the manifest fingerprint, and comparison mapping version 2 reports its behavioral, permission, and security categories as applicable. The registry records declared scope. Execution and policy enforcement belong to later phases.

Display labels and prose descriptions are administrative metadata. Supply them separately to comparison. A description edit preserves the deployment fingerprint and does not invalidate existing evidence by itself.

Evaluation suites and evidence use independent `schema_version` fields. Both current contracts use integer version 1. The suite schema version is distinct from its ID and revision. Legacy unversioned suite payloads retain their fingerprints and remain readable. Publishing an explicit version 1 suite with otherwise identical content requires a new suite revision and produces a different fingerprint. A suite schema change has no effect on the deployment fingerprint.

## Evidence contract

Each evidence record carries a unique ID, candidate fingerprint, check ID and revision, dataset and runner revisions, execution time, result, artifact digest and source provenance. Evidence is verified against the artifact bytes and the policy's accepted provenance and freshness requirements. A matching digest verifies integrity and policy separately establishes whether the producer is trusted. Evidence for another fingerprint cannot satisfy a mandatory check. A targeted rerun must produce a new record for the new fingerprint.

At registration, the registry computes SHA-256 over the complete canonical evidence payload, including schema version, binding, execution time, result, artifact digest, producer and source. It stores that record fingerprint separately from the payload. Retrieval and verification independently recompute it, check the registry bindings and verify the artifact bytes against their own digest. For HTTP verification, retain the original registration fingerprint outside the SQLite database and send it as the expected record fingerprint. This detects a payload substitution even if the stored fingerprint was also replaced.

These checks detect altered records and artifacts relative to their original digests. A party that controls both the data and all copies of the reference digests can rewrite them together. A fingerprint does not authenticate a producer or prove that a check actually ran. Existing evidence rows created before fingerprint storage are preserved, but verification fails closed because they have no original registration fingerprint. Re-establish evidence from a trusted source or rerun the check and register under a new evidence ID.

Subsequent phases must authenticate producers, bind their identity to the candidate, suite, check, artifact digest and record fingerprint, and define trust roots, revocation and freshness rules. Provider integrations must resolve aliases to verified immutable revisions or independently verified digests. Merely supplying a revision string does not establish that a provider will continue serving the same model.

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
