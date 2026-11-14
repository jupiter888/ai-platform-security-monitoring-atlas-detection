# DET-002 — Query-Volume Evaluation Findings

## Status

Tested within the local scenarios documented below.

The results do not establish production detection effectiveness.

## Monitoring Objective

Identify elevated successful inference querying that may warrant investigation
for resource abuse or output collection.

The rule observes activity volume. It does not directly observe intent,
downstream use of outputs, or model-replication training.

## Implemented Rule

DET-002 version 1.0 generates a finding for at least 20 distinct successful
inference events within 60 seconds for the same authenticated caller and model.

The rule uses collector timestamps and excludes duplicate event IDs.

## Observed Results

| Scenario | Ground truth | Observed result | Operational classification |
|---|---|---|---|
| Approved 20-request batch | Benign | Finding delivered and stored | False positive |
| Burst replication experiment | Authorized adversarial emulation | Finding delivered; 32 supporting events | True positive for the declared scenario |
| Paced replication experiment | Authorized adversarial emulation | No matching finding; peak 18 requests per 60 seconds | False negative for the declared scenario |

The paced experiment completed 36 requests in 122.855 seconds.

Its assessment verified all 36 source events, 26 healthy recorded monitor polls,
a maximum polling gap of approximately 5.005 seconds, and no suppression.

No matching paced-experiment finding was present in the receiver or outbox.

## Selected-Scenario Measurements

Evaluation unit: one declared scenario.

- True positives: 1.
- False positives: 1.
- True negatives: 0.
- False negatives: 1.
- Precision: 1 / (1 + 1) = 0.5.
- Recall: 1 / (1 + 1) = 0.5.

These three deliberately selected scenarios are not a representative sample.
The measurements must not be generalized to production traffic.

## Model-Replication Observation

Both burst and paced experiments used 24 API-labeled training queries and
12 held-out queries.

The separately trained classifier agreed with the target on 9 of 12 held-out
queries, compared with 6 of 12 for the majority-label baseline.

This is limited behavioral imitation on a small synthetic corpus. It is not
proof of complete model extraction, weight theft, or production-level fidelity.

Pacing changed whether DET-002's volume condition was met while preserving
the observed agreement in these runs.

## Interpretation

A fixed short-window volume rule can:

- Flag legitimate batch processing.
- Detect some high-volume adversarial activity.
- Miss lower-rate adversarial activity.

Correct rule execution does not imply adequate threat coverage.

The finding should support investigation rather than automatically establish
malicious intent or authorize containment.

## Evidence

- [Benign batch](../../evidence/public/query-volume-benign-batch.txt)
- [Burst replication experiment](../../evidence/public/model-replication-experiment.json)
- [Burst detection assessment](../../evidence/public/replication-detection-assessment.txt)
- [Two-scenario comparison](../../evidence/public/query-volume-scenario-comparison.json)
- [Paced replication experiment](../../evidence/public/paced-replication-experiment.json)
- [Paced monitor coverage](../../evidence/public/paced-query-monitor.jsonl)
- [Paced assessment](../../evidence/public/paced-query-detection-assessment.json)

## Residual Risks

- Low-rate and distributed querying remain relevant blind spots.
- Collection delay can alter apparent activity timing.
- Credentials can identify an account without establishing its operator's intent.
- No input-diversity or downstream-output-use signal is currently available.
- Monitoring coverage during a run does not prove every internal operation.
- No automatic containment is justified solely by this finding.

## Next Evaluation

Evaluate candidate changes under the separately documented tuning protocol.

Preserve this baseline and report unfavorable results.