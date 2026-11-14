# Detection Coverage and Visibility Gaps

## Interpretation

Coverage statements apply to the documented local exercises.
A rule match does not establish malicious intent.

Tested means supporting tests or evidence exist for the stated path.
It does not mean comprehensive threat coverage.

## Detection Coverage

| Rule | Signal | Status | Demonstrated coverage | Principal gap |
|---|---|---|---|---|
| DET-001 | Repeated model-access denials | Tested | Threshold behavior and actual denied requests | Does not identify misuse of permitted access |
| DET-002 | Short-window successful-query volume | Tested | Selected benign, burst, and paced scenarios | Missed selected paced replication; benign bulk workload triggered |
| DET-003 | Sustained successful-query volume | Tested | Frozen held-out scenarios | Benign bulk workload still triggered |
| DET-004 | Aggregate authentication failures | Tested | Actual threshold crossing, delivery, benign mistakes, suppression | Unknown caller attribution and unrelated failures can be combined |
| DET-005 | Repeated admission rejections | Tested | Bounded actual concurrent workload and delivery | Pressure does not establish intent or resource exhaustion |
| DET-006 | Aggregate privileged authorization denials | Tested | Actual denied approval attempts and delivery | Combines operators/cases; excludes other misuse signals |

## Telemetry and Delivery

| Area | Status | Demonstrated behavior | Remaining gap |
|---|---|---|---|
| Producer authentication | Tested | Unauthorized and cross-source submissions rejected | Authorized producers can fabricate permitted claims |
| Provenance | Tested | Fixtures cannot claim live-lab activity | Provenance is not independent proof of event truth |
| Event validation | Tested | Bounded schemas, strict JSON, sensitive-field rejection | No completeness guarantee |
| Live timestamps | Tested | Age and future-skew limits | Clock dependence; collection time remains the detection basis |
| Duplicate handling | Tested | Pending and retained delivered IDs rejected | State is lost on restart and bounded IDs can be evicted |
| Collector delivery | Tested | Failed events retained and delivery recovered | Pending queue is not durable |
| Finding delivery | Tested | Durable outbox, receiver acknowledgment, deduplication | Only already-queued findings are protected |
| Operator audit publication | Tested | Actual operations correlated to Loki | No durable retry; not atomic with state changes |
| Query capacity | Implemented | Bounded response and record limits | Limit exhaustion interrupts evaluation rather than providing full pagination |

## Monitoring Health

| Condition | Status | Evidence scope | Limitation |
|---|---|---|---|
| Detector stopped | Tested | Scrape failure and absent current metrics | No independent monitoring infrastructure |
| Loki unavailable | Tested | Scrape healthy, query unhealthy, successful-poll age increasing | No detection coverage during failed queries |
| Recovery | Tested | Healthy queries and delivery resumed | No guaranteed backfill beyond lookback |
| Dashboard queries | Tested | Sixteen provisioned panels; original and added queries validated | Visual inspection remains distinct from query validation |
| Health notification delivery | Proposed | No validated health-notification policy | Dashboard visibility is not notification delivery |

## Response Coverage

| Area | Status | Demonstrated scope | Remaining gap |
|---|---|---|---|
| Operator roles | Tested | Analyst, approver, responder boundaries | One human operated all principals |
| Scope binding | Tested | Fixed caller, model, action, duration, and policy version | Approval has no separate freshness deadline |
| Containment | Tested | Actual Reader query denial | No cancellation of requests already executing |
| Recovery | Tested | Access restored after expiry | Relies on local clock and policy storage |
| Response retest | Tested | Repeated six-query sequence and unaffected Admin controls | Small query-access experiment, not repeated extraction evaluation |
| Aggregate finding investigation | Implemented | Authenticated finding retrieval | Current targeted case workflow rejects aggregate findings |

## Threat Areas Outside Demonstrated Coverage

- Prompt injection and generative-model safety.
- Training-data poisoning or membership inference.
- Model-artifact tampering.
- Compromised host or privileged administrator.
- Distributed identity abuse and source-network attribution.
- Distributed quotas or admission control.
- Production incident-response coordination.
- Complete attack reconstruction or tamper-resistant evidence storage.

These areas must not be counted as detected or prevented by the laboratory.

## Selected-Scenario Findings

The frozen held-out evaluation used four scenarios and 124 actual requests.

DET-002 produced precision 0.50 and recall 0.50.
DET-003 produced precision approximately 0.67 and recall 1.00.

The longer window improved recall in those scenarios but retained a benign
false positive. These figures are not representative production estimates.

## Evidence References

- [Held-out assessment](../evidence/public/query-volume-holdout-assessment.json)
- [Authentication detection](detection/authentication-failures.md)
- [Admission pressure](detection/admission-pressure.md)
- [Operator activity](detection/operator-activity.md)
- [Telemetry integrity](telemetry-integrity.md)
- [Monitoring resilience](monitoring-resilience.md)
- [Response retest](response-retest.md)