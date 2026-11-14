# Residual Risks

## Interpretation

Controls reduce selected risks within a local laboratory.
Documenting a limitation does not resolve it or constitute formal acceptance.

Accountable owner: project owner. Reassessment conditions are defined below.

## Risk Register

| ID | Residual risk | Existing treatment | Reassessment trigger |
|---|---|---|---|
| RR-001 | An authorized producer can fabricate permitted events | Source-bound credentials and strict contracts | New producer, host, or deployment boundary |
| RR-002 | Collector termination loses pending events | Buffer-drain procedure and bounded delivery retries | Need for durable event ingestion |
| RR-003 | Queue saturation rejects telemetry and can affect applications | Capacity limits, explicit rejection, metrics | Higher load or sustained operation |
| RR-004 | Duplicate state is lost on restart or cache eviction | Pending/recent-ID checks and live timestamp limits | Durable anti-replay requirement |
| RR-005 | Clock changes affect acceptance and detection windows | UTC validation and bounded source-time skew | Multi-host deployment or clock incident |
| RR-006 | Detection misses activity outside thresholds or lookback | Held-out evaluation and documented blind spots | New workload, attack pattern, or outage duration |
| RR-007 | Sequential collector HTTP handling permits local blocking | Loopback exposure and socket timeout | Untrusted host workloads or production use |
| RR-008 | Bounded schemas are not general-purpose secret detection | Synthetic identities, field restrictions, canaries, publication review | New fields, logs, or data source |
| RR-009 | Selected local tests do not establish production assurance | Explicit provenance and evidence scope | Any external deployment |
| RR-010 | Benign activity triggers volume and authentication findings | Contextual investigation and explicit false-positive evidence | Changed workload or response automation |
| RR-011 | Durable outbox capacity can be exhausted | Bounded storage with explicit errors and no silent eviction | Extended runtime or larger finding volume |
| RR-012 | Operator audit publication is not durable or atomic with changes | Actual-result preservation, delivery header, console fallback, case ledger | Audit-loss intolerance |
| RR-013 | Local credentials and SQLite state share host trust | Private storage permissions and separate credentials | Host compromise or multi-user operation |
| RR-014 | Admission is process-local and does not bound all HTTP work | Two protected in-flight slots and explicit rejections | Multiple workers or sustained hostile load |
| RR-015 | Containment affects legitimate target activity and cannot cancel in-flight work | Fixed scope, approval, 60-second expiry, recovery checks | Broader response actions |
| RR-016 | Approval has no separate freshness deadline | Persisted scope and single execution | Longer-lived cases or production workflow |
| RR-017 | Separate credentials do not provide independent human review | Technical role separation and explicit disclosure | Multiple human operators |
| RR-018 | Aggregate findings cannot use the targeted case workflow | Authenticated retrieval; target invention prohibited | General investigation-case requirement |
| RR-019 | Monitoring shares local infrastructure with the application | Scrape, processing health, freshness, outage exercises | Availability or independent-monitoring requirement |
| RR-020 | No validated health-notification delivery policy | Grafana visibility and explicit Proposed status | Unattended operation |
| RR-021 | Frozen scenarios and small classifier limit generalization | Separate development/held-out results and disclosed denominators | Different model, vocabulary, or workload |
| RR-022 | Vulnerability and sensitive-data review is not yet complete | Final audit pending | Before publication |

## Important Distinctions

- Collector acceptance is not durable Loki storage.
- Receiver acknowledgment is not analyst review.
- Healthy scrape status is not healthy detection processing.
- A rule match is not proof of malicious intent.
- A longer observation window does not determine intent.
- Timestamp restrictions are not durable replay prevention.
- Queued-finding recovery is not offline detection coverage.
- Local response recovery is not a production availability guarantee.

## Related Analysis

- [Coverage Register](coverage-register.md)
- [Telemetry Integrity](telemetry-integrity.md)
- [Monitoring Resilience](monitoring-resilience.md)
- [Governance](governance.md)

## RR-023 — Direct Loki Ingestion Bypasses Collector Controls

Loki's HTTP API is unauthenticated. A process with direct access can fabricate
stored live-lab telemetry without passing collector authentication or validation.

Owner: project owner.
Current treatment: loopback host publication, isolated lab operation, and explicit
trusted-storage assumptions. These do not prevent host-local or network-peer forgery.
Authenticated storage ingress: Proposed.
Reassess before introducing untrusted local workloads or any external deployment.
