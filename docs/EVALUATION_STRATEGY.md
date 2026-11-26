# Evaluation strategy

Run each arm against the same versioned synthetic cases and immutable snapshots. Each case includes candidate and baseline manifests, policy revision, evidence, expected eligibility and labeled risks. Include clean candidates, single-component changes across all five categories, multiple changes, failed checks, stale or wrong-candidate evidence, unverifiable provenance and instruction-like content embedded in evidence. Define reference labels before running any arm and resolve grader disagreements against the written case criteria.

| Arm | Experimental output |
| --- | --- |
| A. AI-only reviewer | Primary reviewer's structured eligibility recommendation. Offline simulation only. |
| B. Deterministic policy engine | Gate eligibility and rule explanations. |
| C. AI reviewer with deterministic release gate | Gate eligibility plus the primary reviewer's advisory findings. |
| D. Hybrid with independent secondary AI reviewer | Gate eligibility plus findings from two isolated reviews. The second reviewer receives the same snapshot and no first-review output. Preserve disagreement for human review. |

No arm grants human authorization. In C and D, gate output is the eligibility signal used for error scoring. Score AI recommendations separately to see advisory disagreements. In D, use the union of distinct cited findings for combined recall and precision. Log primary and secondary outcomes individually.

| Metric | Definition |
| --- | --- |
| Incorrect approvals (false eligibility rate) | For each arm and run, divide the number of reference-blocked cases marked eligible by the total number of reference-blocked cases. Use the AI recommendation in A and the deterministic gate result in B–D. This measures eligibility before any human authorization. |
| Incorrect blocks | Blocked outputs among reference-eligible cases divided by the number of reference-eligible cases. |
| Risk detection | Precision and recall against labeled case risks using cited evidence. Report novel findings after blinded adjudication. |
| Explanation quality | Blinded rubric scoring factual accuracy, citation support and actionable reasoning, each 0–2. |
| Consistency | Pairwise agreement of eligibility outputs across repeated runs per case. Also report risk-set agreement. |
| Latency | Median and p95 wall-clock time per case including verification and both reviewers in D. |
| Cost | Per-case and total model usage and estimated cost under recorded rates. Track local runtime separately. |

Pin dataset, labels, policy, candidate, evidence, adapter, prompts, models, runner and clock inputs. Repeat each arm at least three times with recorded settings and seeds where supported. Hold the primary reviewer constant across A, C and D. Record failures and abstentions separately and publish coverage and denominators. Report results overall and by case category with uncertainty where the sample permits. Compare C with B for added risk detection and D with C for incremental recall, false findings, latency and cost. Treat mandatory gate violations in C or D as failed experiment invariants.
