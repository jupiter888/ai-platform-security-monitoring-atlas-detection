# Telemetry Integrity & Coverage

## Threat Model

An unauthorized local process may attempt to inject security events, impersonate
another producer, promote fixture activity to live provenance, replay events,
or manipulate timestamps.

Telemetry loss, queue saturation, delayed delivery, and monitoring downtime can
also affect detection coverage.

## Mitigations

| Control | Status | Validation scope |
|---|---|---|
| Producer authentication | Tested | Local HTTP rejection and application publication |
| Producer source binding | Tested | Gateway and operator credentials are not interchangeable |
| Fixture provenance restriction | Tested | Fixture credentials cannot submit live-lab events |
| Strict bounded event contracts | Tested | Inference and operator schemas |
| Collector-owned collection time | Tested | Submitted collection-time fields rejected |
| Live timestamp limits | Tested | Boundary tests and actual HTTP rejection |
| Pending-event duplicate rejection | Tested | Retained in-memory state |
| Recently delivered ID rejection | Tested | Bounded in-memory cache |
| Bounded buffering without silent eviction | Tested | Local buffer and delivery tests |
| Failed-delivery retention and recovery | Tested | Local tests and earlier pipeline exercises |
| Durable replay protection | Proposed | Not implemented |

## Producer Permissions

| Producer | Permitted source | Permitted provenance |
|---|---|---|
| Gateway | gateway | live-lab |
| Operator | operator | live-lab |
| Fixture | Supported inference and operator sources | synthetic, replay |

Credentials are generated and stored outside the project directory.
Application and fixture publishers use separate credentials.

Authentication precedes request-body parsing. Source and provenance authorization
precede buffer admission.

Producer credentials authorize event categories. They do not independently prove
that an authorized producer's statements are true.

## Timestamp Policy

Live-lab events are accepted when source time is:

- No more than 300 seconds before collection time.
- No more than 30 seconds after collection time.

The boundaries are inclusive.

Synthetic and replay fixtures are exempt from live age restrictions but remain
subject to schema validation and producer permissions.

Timestamp acceptance is enforced at HTTP ingestion. Historical parsing and
evaluation do not apply the current wall clock to stored records.

Detection uses collection time. Accepted delayed events can therefore contribute
to a current collection-time window even when their source times differ.

## Validation

The regression suite reached 344 passing tests.

Selected live results:

- Authenticated fixture ingestion: 5/5 passed.
- Authenticated fixture delivery to Loki: 3/3 passed.
- Unauthorized producer rejection: 8/8 passed.
- Actual inference monitoring after authentication rollout: 8/8 passed.
- Actual operator publication after authentication rollout: 4/4 passed.
- Timestamp and replay validation: 8/8 passed.

The timestamp exercise rejected stale and excessively future live claims.
An explicitly labeled historical replay was stored with its original source
timestamp and a new UTC collection timestamp.

The live detector query excluded that replay record.

Offline coverage-limit tests additionally demonstrated:

- A new collector buffer does not retain earlier event IDs.
- A delivered ID can be accepted again after duplicate-cache eviction.
- Delayed and out-of-order source times do not replace collection-time semantics.
- Records outside the collection-time rule window do not enter that window.

These limitation tests must not be presented as durable replay prevention.

## Evidence

- [Producer enforcement regression](../evidence/public/collector-producer-enforcement-regression.txt)
- [Authenticated publisher regression](../evidence/public/authenticated-publishers-regression.txt)
- [Fixture ingestion](../evidence/public/authenticated-collector-validation.txt)
- [Fixture delivery](../evidence/public/authenticated-loki-delivery-validation.txt)
- [Producer rejection](../evidence/public/live-producer-rejection-validation.json)
- [Authenticated inference monitoring](../evidence/public/authenticated-inference-monitoring.txt)
- [Authenticated operator publication](../evidence/public/authenticated-operator-publication.json)
- [Timestamp regression](../evidence/public/telemetry-time-policy-regression.txt)
- [Live timestamp and replay validation](../evidence/public/live-timestamp-replay-validation.json)
- [Coverage-limit regression](../evidence/public/telemetry-coverage-limits-regression.txt)

## Residual Risks

- Producer credentials are bearer secrets on a shared local host.
- A compromised authorized producer can fabricate permitted event categories.
- Loopback HTTP is not encrypted transport or workload identity attestation.
- Pending collector events and duplicate state are lost on termination.
- Duplicate-cache eviction permits later acceptance of the same event ID.
- Timestamp limits bound event age; they do not provide durable anti-replay state.
- System-clock changes can affect timestamp acceptance and detection windows.
- FIFO delivery can be obstructed by an event repeatedly rejected downstream.
- Collector saturation rejects new events and can affect application availability.
- Collector acceptance does not guarantee durable Loki storage.
- Monitoring outages can leave activity outside the detector lookback window.
- Durable finding delivery protects queued findings, not unobserved events.
- Operator audit publication lacks durable retry and is not atomic with case
  changes.
- These exercises do not establish complete telemetry collection or production
  availability.

## Direct Storage Trust Boundary

Producer authentication is enforced at the collector's /events endpoint.
Loki is configured with auth_enabled: false and has a loopback-published HTTP
port. Its HTTP API is also reachable by peers on the Compose network.

A process able to write directly to Loki can bypass producer authentication,
timestamp checks, and collector-assigned collection time, and can fabricate
records matching the detector's live-lab selector. Schema checks in the detector
do not independently authenticate those stored records.

Status: Proposed — authenticated and authorized storage ingress.

The current lab assumes trusted access to Loki and trusted local storage.
Loopback publication reduces remote exposure but does not authenticate local
processes. No direct-ingestion attack exercise is claimed by this configuration
review. Collector credential tests establish endpoint enforcement, not
end-to-end telemetry integrity.
