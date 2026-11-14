# Query-Volume Detection Tuning Protocol

## Status

Tested within the frozen local evaluation.

The additional 30-request / 180-second condition was implemented as DET-003 alongside DET-002. In four held-out scenarios, DET-003 produced two true positives, one false positive, one true negative, and zero false negatives. The benign bulk workload still triggered a finding. The protocol below records the evaluation design; it is not a request to rerun or modify the original frozen evaluation.

See the [held-out assessment](../../evidence/public/query-volume-holdout-assessment.json).

## Purpose

Evaluate whether an additional observation window improves visibility without
concealing false positives or overstating intent detection.

## Baseline

DET-002 version 1.0:

- Threshold: 20 successful requests.
- Window: 60 seconds.
- Grouping: authenticated caller and model.

Preserve the baseline implementation and its recorded results.

## Candidate

Evaluate an additional sustained-volume condition:

- Threshold: 30 successful requests.
- Window: 180 seconds.
- Same caller/model grouping and event-ID deduplication.

The candidate supplements the baseline. It does not silently replace it.

This candidate was selected after examining the development scenarios.
Improved performance on those scenarios is tuning evidence, not independent
validation.

## Development Analysis

Retrospectively assess the existing approved batch, burst replication, and
paced replication using their original event records.

Report which conditions each rule would satisfy.

Do not present retrospective findings as alerts generated during the original
live runs.

## Held-Out Validation

Before executing new scenarios, freeze:

- Baseline and candidate configurations.
- Scenario definitions and query budgets.
- Request pacing and benign/adversarial ground truth.
- Evaluation units and matching criteria.
- Monitoring-health requirements.
- Delivery and suppression-state prerequisites.

Include:

- Benign routine activity.
- Benign high-volume batch activity.
- Adversarial burst querying.
- Adversarial paced querying.

Use new scenario instances and distinguish them from development evidence.

Do not alter thresholds after seeing held-out outcomes and continue describing
that same set as held out. A further change requires a new evaluation cycle.

## Measurements

For each rule and their combined coverage, report:

- Scenario-level true positives, false positives, and false negatives.
- True negatives where an eligible negative scenario was completed.
- Precision and recall with explicit denominators.
- Detection and delivery timing with clearly defined start and end points.
- Monitoring failures and inconclusive results separately.

Do not infer production performance from the small laboratory sample.

## Acceptance and Tradeoffs

A longer window must be evaluated for:

- Additional visibility into paced activity.
- Alerts on legitimate bulk processing.
- Detection delay.
- Increased query and state requirements.
- Duplicate or overlapping findings.
- Behavior during telemetry loss and delivery outages.

No automatic containment will be introduced solely because a volume threshold
was crossed.

## Governance

The lab operator owns rule configuration and evaluation evidence.

Rule changes require a recorded rationale, regression results, observed
tradeoffs, and a rollback reference to the baseline.

## Residual Limitation

Volume alone cannot establish intent.

Longer windows may move the detection boundary while preserving the underlying
ambiguity between approved activity and abuse.
