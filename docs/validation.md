# Validation

## 1. Environment and Scope

Validation uses a local Python 3.11 environment and Docker monitoring services.

The service performs actual text-classifier inference on synthetic data.
Local opaque credentials identify synthetic clients and operators.

Operational telemetry excludes raw prompts, credentials, and arbitrary submitted
content through bounded event contracts.

## 2. Automated Regression

Latest confirmed baseline: **344 tests passed**.

```bash
python -m unittest discover -s tests -v
```

The baseline covers event contracts, ingestion, buffering, delivery, model
behavior, authentication, authorization, detection, durable storage, operator
workflow, containment, admission, producer permissions, and timestamp policy.

Four coverage-limit tests explicitly demonstrate collection-time behavior and
the loss of duplicate protection after collector replacement or cache eviction.

A test count is not a count of independently validated security controls.

## 3. Selected Integration Results

| Exercise | Result | Evidence |
|---|---|---|
| Authenticated fixture ingestion | 5/5 | E-004 |
| Authenticated fixture delivery to Loki | 3/3 | E-004 |
| Unauthorized producer rejection | 8/8 | E-005 |
| Actual inference monitoring after producer authentication | 8/8 | E-006 |
| Actual operator publication after producer authentication | 4/4 | E-007 |
| Queued-finding recovery | 4/4 | E-009 |
| Actual authentication-failure detection | 9/9 | E-010 |
| Benign credential mistakes and live suppression | 10/10 | E-010 |
| Actual inference admission and recovery | 6/6 | E-011 |
| Actual admission-pressure detection | 8 checks | E-011 |
| Actual operator auditing | 11/11 | E-012 |
| Actual privileged-denial detection | 9/9 | E-012 |
| Timestamp and explicit replay handling | 8/8 | E-013 |
| Verified detector outage visibility | 2/2 | E-014 |
| Detector restart recovery | 3/3 | E-014 |
| Loki query-failure visibility | 3/3 | E-014 |
| Query-failure recovery | 3/3 | E-014 |
| Original security dashboard data paths | 14/14 | E-015 |
| Four additional dashboard panels | 5/5 | E-015 |
| Response-retest preparation | 5/5 | E-016 |
| Response-retest traffic | 7/7 | E-016 |
| Response-retest assessment | 8/8 | E-016 |

Assertion counts describe bounded exercises. Their scope and prerequisites are
recorded in the referenced artifacts.

## 4. Frozen Detection Evaluation

Four selected scenarios generated 124 actual inference requests:

| Scenario | Ground truth | DET-002 | DET-003 |
|---|---|---|---|
| H01 routine research | Benign | No finding | No finding |
| H02 approved bulk processing | Benign | Finding | Finding |
| H03 burst replication | Authorized adversarial emulation | Finding | Finding |
| H04 paced replication | Authorized adversarial emulation | No finding | Finding |

Queued-finding and delivered-finding assessments produced the same selected
scenario counts:

| Rule | TP | FP | TN | FN | Precision | Recall |
|---|---:|---:|---:|---:|---:|---:|
| DET-002 | 1 | 1 | 1 | 1 | 0.50 | 0.50 |
| DET-003 | 2 | 1 | 1 | 0 | 0.67 | 1.00 |

The longer window improved selected-scenario recall but retained a benign false
positive. These are not representative production estimates.

Collection-time threshold-to-detection and threshold-to-receiver-storage
latencies are recorded separately in the assessment.

Source manifest SHA256:

d73eac2f56e2a7161c384d1dec5c5007a22842d87d3a3575d303628a96e5530b

## 5. Model-Imitation Measurement

H03 held-out target agreement was 0.75 against a 0.50 majority-label baseline.

H04 agreement was 0.75 against a 0.4167 majority-label baseline.

Each comparison used 12 held-out queries. Related synthetic vocabulary and small
sample sizes limit generalizability.

Model imitation and detection effectiveness are separate measurements.

## 6. Response Retest

A separate frozen protocol linked an unused H03 finding to a new approved case.

The same six-query sequence was exercised before, during, and after a 60-second
block. Reader queries succeeded before and after, and returned containment
denials during the block.

One Admin control request succeeded in each phase.

All 21 inference requests and five operator requests correlated to distinct
stored events. The original held-out protocol remained unchanged.

This establishes selected query-access restriction and recovery, not renewed
extraction accuracy or production response effectiveness.

See [Response Retest](response-retest.md).

## 7. Telemetry Integrity

Live submissions require source-bound producer credentials.

Live source timestamps are limited to 300 seconds of age and 30 seconds of
future skew. Explicit fixtures use synthetic or replay provenance.

The collector adds collection time. Detection windows use that collection time.

Duplicate protection is bounded and in memory. It does not survive collector
replacement or guarantee rejection after cache eviction.

See [Telemetry Integrity](telemetry-integrity.md).

## 8. Failure Evidence

Incomplete exercises remain preserved:

- The initial holdout preflight failed before inference traffic.
- The initial containment exercise did not capture its unexpected HTTP response.
  Later probes demonstrated rejection of new event reasons by the stale collector.
- The first attempted detector outage did not stop the active process.
  Continued scrape and polling observations were retained.

Successful follow-up exercises use separate evidence artifacts.

## 9. Remaining Review

Dependency and container vulnerability review, sensitive-data review,
documentation-link verification, and clean-start reproducibility checks remain
part of the final audit.

No production security, certification, complete telemetry coverage, or
independent assurance is claimed.

See [Evidence Index](../evidence/README.md) and
[Residual Risks](residual-risks.md).