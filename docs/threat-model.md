# Threat Model

## 1. Scope

A standalone local AI service connects authenticated inference requests to
telemetry collection, security detection, durable finding delivery,
investigation, approved containment, and recovery validation.

The classifier runs inside the inference API. Both exposed model names use the
same classifier with different authorization policies.

There is no separate inference backend endpoint in the current architecture.

## 2. Assets

- Model-query access and inference availability.
- Client, operator, receiver, and producer credentials.
- Event integrity, attribution, provenance, and collection timestamps.
- Detection configuration and evaluation protocols.
- Findings, delivery acknowledgments, case history, and execution records.
- Investigation evidence and published research claims.

## 3. Trust Boundaries

| Boundary | Relationship | Current controls |
|---|---|---|
| TB-01 | Producer to collector | Producer authentication and source/provenance permissions |
| TB-02 | Submitted bytes to validated event | Strict bounded contracts and JSON parsing |
| TB-03 | Validated event to buffer | Capacity limits and retained-ID duplicate rejection |
| TB-04 | Collector to Loki | Bounded delivery attempts, buffering, and recovery |
| TB-05 | Events to findings and receiver | Six rules, durable outbox, authenticated receiver |
| TB-06 | Finding to response | Operator roles, persisted scope, approval, execution guards |
| TB-07 | Client to inference | Authentication, model authorization, admission, containment |
| TB-08 | Monitoring user to Grafana | Authenticated dashboard access and local service exposure |
| TB-09 | Application to private state | Local filesystem permissions and bounded SQLite stores |

These are local laboratory controls, not workload identity attestation or
protection against host administrator compromise.

## 4. Threat Register

| ID | Threat | Controls | Validation scope |
|---|---|---|---|
| MON-001 | Malformed or oversized telemetry disrupts ingestion | CTL-001, CTL-003 | Parser and actual HTTP tests |
| MON-002 | Sensitive submitted content enters telemetry or handled errors | CTL-002 | Schema restrictions and canary exercises |
| MON-003 | Replayed events inflate activity | CTL-004, CTL-012 | Retained-ID rejection, timestamp policy, explicit replay isolation |
| MON-004 | Event bursts exhaust collector capacity | CTL-003, CTL-006 | Local capacity and failed-delivery tests |
| MON-005 | An unauthorized producer claims trusted source or provenance | CTL-005 | Actual unauthorized and cross-source submissions |
| MON-006 | Missing, delayed, or unavailable telemetry hides activity | CTL-006, CTL-013 | Outages, recovery, collection-time tests, documented gaps |
| MON-007 | Weak rules miss activity or produce misleading alerts | CTL-007, CTL-014 | Frozen evaluation with benign, burst, and paced scenarios |
| MON-008 | A finding causes unauthorized or excessive response | CTL-008, CTL-011 | Role, scope, execution, expiry, and response retest |
| MON-009 | Invalid identity or unauthorized model access | CTL-009, CTL-007 | Actual API rejection and DET-001/DET-004 exercises |
| MON-010 | Permitted queries support model-behavior replication | CTL-007, CTL-008 | Controlled replication, detection assessment, query-access containment |
| MON-011 | Concurrent requests consume inference capacity | CTL-010, CTL-007 | Bounded admission and actual pressure detection |
| MON-012 | Privileged operator misuse is not observable | CTL-011, CTL-007 | Operator audit correlation and DET-006 |

Control effectiveness is limited to the documented tests. Known gaps remain.

## 5. Attacker Capabilities and Assumptions

The model includes:

- A local process submitting arbitrary collector requests.
- A caller with invalid or valid inference credentials.
- An authenticated caller requesting an unauthorized model.
- A permitted caller collecting outputs or creating admission pressure.
- An operator attempting actions outside its role or workflow state.

Producer credentials restrict submissions but cannot establish the truthfulness
of a compromised authorized producer.

The laboratory assumes its operating system and privileged administrator remain
trusted. All data and identities are controlled laboratory resources.

## 6. Framework Interpretation

Selected replication behavior is mapped to versioned MITRE ATLAS references.
Generic authorization failures and capacity exercises are not forced into
unsupported technique mappings.

See [Framework Mapping](research/framework-mapping.md).

## 7. Traceability

[Mitigations](mitigations.md) → [Validation](validation.md) →
[Evidence](../evidence/README.md) → [Residual Risks](residual-risks.md).

## 8. Direct Storage Bypass

MON-013: Direct writes to unauthenticated Loki can bypass collector producer
authentication and validation. Host-local processes and Compose-network peers
with Loki reachability may fabricate detector inputs.

Authenticated storage ingress is Proposed. The current treatment is restricted
exposure and an explicit trusted-storage assumption, not prevention of local
forgery. See [Telemetry Integrity](telemetry-integrity.md).
