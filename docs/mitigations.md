# Mitigations and Control Register

## Status Definitions

- **Proposed:** Intended work without completed implementation.
- **Implemented:** Present in code or configuration; validation is incomplete.
- **Tested:** Evidence supports the stated validation scope.

Tested does not mean comprehensive coverage or production assurance.

## Control Register

| ID | Control | Status | Implementation | Evidence |
|---|---|---|---|---|
| CTL-001 | Strict bounded inference and operator event contracts | Tested | telemetry/events.py, operator_events.py, ingestion.py | E-003, E-004 |
| CTL-002 | Exclude unexpected content and avoid reflection in handled errors | Tested | Event contracts and API validation | E-006, E-012 |
| CTL-003 | Bounded collector buffer with explicit rejection and no silent eviction | Tested | telemetry/collector.py | E-003 |
| CTL-004 | Reject pending and recently delivered event IDs | Tested | telemetry/collector.py | E-004, E-013; restart and eviction limits in E-003 |
| CTL-005 | Authenticate producers and bind source/provenance permissions | Tested | producer_auth.py, producer_credentials.py, collector.py | E-005, E-006, E-007 |
| CTL-006 | Observe delivery failures, buffering, monitoring outages, and recovery | Tested | Collector worker, detector metrics, Prometheus | E-009, E-014 |
| CTL-007 | Evaluate security detections against explicit scenarios | Tested | Six-rule catalog and continuous evaluator | E-008, E-010, E-011, E-012 |
| CTL-008 | Authorize and verify scoped temporary response | Tested | Case ledger, operator API, containment controller | E-016, E-017 |
| CTL-009 | Authenticate inference callers and authorize model access | Tested | inference/api.py | E-006 |
| CTL-010 | Bound process-local admitted inference work | Tested | inference/admission.py and API integration | E-011 |
| CTL-011 | Enforce operator roles and record accepted/rejected activity | Tested | operator_auth.py, operator_api.py, operator_audit.py | E-012, E-016 |
| CTL-012 | Bound live timestamp age and future skew | Tested | telemetry/time_policy.py | E-013 |
| CTL-013 | Expose bounded operational metrics and dashboard views | Tested | Detector metrics, Prometheus, Grafana definitions | E-014, E-015 |
| CTL-014 | Freeze evaluation and response-retest protocols | Tested | config/evaluation and assessment scripts | E-008, E-016 |
| CTL-015 | Document ownership, review, rollback, and risk decisions | Implemented | governance.md | Technical role enforcement is tested; organizational process is not independently validated |

Paths without a directory prefix are within src/telemetry or src/detection as
appropriate.

## Detection Rules

| Rule | Signal | Status |
|---|---|---|
| DET-001 | Repeated model-access denials | Tested |
| DET-002 | Short-window successful-query volume | Tested |
| DET-003 | Sustained successful-query volume | Tested |
| DET-004 | Aggregate authentication failures | Tested |
| DET-005 | Repeated inference-admission rejections | Tested |
| DET-006 | Aggregate privileged-operation authorization denials | Tested |

See [Coverage Register](coverage-register.md) for prerequisites and blind spots.

## Interpretation

- Event schemas are not general-purpose secret detectors.
- Producer authentication is not independent event-truth verification.
- In-memory duplicate handling is not durable replay prevention.
- Collector acceptance is not durable storage acknowledgment.
- Delivery acknowledgment is not analyst review or case closure.
- Query-volume findings do not establish replication intent.
- Admission pressure does not establish malicious denial of service.
- Separate operator credentials do not establish independent human approval.
- Console fallback does not provide durable operator-audit delivery.

## Related Documentation

- [Evidence Index](../evidence/README.md)
- [Telemetry Integrity](telemetry-integrity.md)
- [Monitoring Resilience](monitoring-resilience.md)
- [Governance](governance.md)
- [Residual Risks](residual-risks.md)