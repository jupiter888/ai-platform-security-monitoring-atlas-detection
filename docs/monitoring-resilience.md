# Monitoring Health and Resilience

## Threat Model

An unavailable or impaired monitoring pipeline can conceal security activity.

A reachable metrics endpoint does not establish that detection queries,
finding delivery, or telemetry collection are functioning correctly.

## Mitigations

| Control | Status | Validation scope |
|---|---|---|
| Detector scrape monitoring | Tested | Prometheus observes detector availability |
| Query-cycle health | Tested | Loki outage produces unhealthy query status |
| Completed-poll freshness | Tested | Completed polls remain observable during query failure |
| Successful-poll freshness | Tested | Last successful poll ages during query failure |
| Persistent delivery backlog | Tested | Outbox state survives detector restart |
| Grafana monitoring dashboard | Tested | All 12 panel queries execute through Grafana |
| Automated health notifications | Proposed | No notification policy validated for these health signals |

Metric counters are process-local and reset on restart. Outbox gauges reflect
persisted SQLite records.

Delivery-cycle health can remain healthy when there are no pending deliveries.
It does not prove a recent successful delivery attempt.

## Validation

### Detector Process Outage

The healthy baseline showed a successful scrape, fresh polling, and no pending
findings.

The first attempted outage did not stop the active detector. Recorded scrape
health remained 1, and successful-poll timestamps continued advancing. That
attempt remains preserved as incomplete.

After identifying and stopping the Project 10 detector process, the metrics port
was confirmed closed. Prometheus then reported scrape health 0 and no current
successful-poll timestamp series.

Following restart, scrape and processing health recovered, polling was fresh,
and the outbox retained 12 acknowledged records with zero pending findings.

### Loki Query Failure

Loki was stopped while the detector remained running.

Prometheus continued scraping the detector. Query-cycle health became unhealthy,
completed polls continued, and successful-poll age exceeded 15 seconds.

Delivery-cycle health remained healthy with no pending findings.

After Loki restarted, readiness returned, detector query and delivery cycles
were healthy, successful polling was fresh, and the backlog remained zero.

### Grafana Data Paths

Authenticated query execution passed for all 12 dashboard panels.
Unauthenticated data querying was rejected.

The actual containment request ID was retrieved through the Grafana Loki data
source.

## Evidence

- [Detector metrics regression](../evidence/public/detector-metrics-regression.txt)
- [Dashboard data-path validation](../evidence/public/security-dashboard-validation.json)
- [Healthy baseline](../evidence/public/detector-outage-baseline.json)
- [Initial incomplete outage attempt](../evidence/public/detector-outage-observation.json)
- [Verified detector outage](../evidence/public/detector-outage-verified.json)
- [Detector restart recovery](../evidence/public/detector-outage-recovery.json)
- [Loki query failure](../evidence/public/detector-query-failure.json)
- [Loki query recovery](../evidence/public/detector-query-failure-recovery.json)

The regression suite contained 246 passing tests at this stage.

## Residual Risks

- These exercises demonstrate local failure visibility, not high availability.
- No attack traffic was generated during the outage exercises.
- Monitoring downtime can create detection gaps beyond the configured lookback.
- Persisted finding delivery does not provide replay of unobserved source events.
- Metrics and logs share local infrastructure and administrative dependencies.
- No independent external monitor or health-notification delivery was validated.
- Grafana data-path checks do not replace visual layout review.
- The detector query limit and bounded storage remain capacity constraints.