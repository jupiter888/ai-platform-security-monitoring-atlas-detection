# AI Platform Security Monitoring & MITRE ATLAS Detection

MONITORING | MITRE ATLAS | DETECTION | CONTAINMENT

## Overview

A standalone local AI security laboratory connecting actual model inference to
telemetry collection, detection, durable finding delivery, investigation,
approved containment, and recovery.

The project evaluates detection effectiveness using controlled benign and
adversarial scenarios. It records false positives, missed activity, operational
failures, and visibility limitations alongside successful results.

## Implemented Architecture

An authenticated FastAPI service runs an actual text classifier trained on
synthetic examples.

Security events flow through a validating collector into Loki. A continuous
detection worker queries those events, evaluates rules, and persists findings in
a durable outbox before delivery to an authenticated receiver.

Prometheus collects operational metrics. Grafana provides visibility into
inference decisions, detection health, finding delivery, and containment events.

An operator API separates analyst, approver, and responder roles. Approved
containment temporarily blocks one caller/model pair before model execution.

The classifier runs inside the inference API process. Both exposed model names
use the same classifier with different access policies.

## Threat Model

Selected threats include:

- Repeated attempts to access unauthorized models.
- Excessive or suspicious use of authorized inference access.
- Output-based model replication through permitted queries.
- Unauthorized investigation or response operations.
- Telemetry loss, malformed events, duplicate delivery, and monitoring outages.
- False confidence caused by incomplete coverage or misleading health signals.

All identities, credentials, datasets, and scenarios are controlled laboratory
resources. Scenario ground truth is kept separate from detection inputs.

## Mitigations and Control Status

| Capability | Status | Demonstrated scope |
|---|---|---|
| Inference authentication and model authorization | Tested | Actual local API requests |
| Bounded event validation and sensitive-field exclusion | Tested | Automated tests and canary exercises |
| Collector buffering and Loki delivery | Tested | Local ingestion and recovery exercises |
| Repeated model-access denial detection | Tested | DET-001 threshold and live request validation |
| Short-window successful-query volume detection | Tested | DET-002 controlled scenarios |
| Sustained successful-query volume detection | Tested | DET-003 frozen held-out scenarios |
| Durable finding delivery and deduplication | Tested | Receiver and outbox recovery exercises |
| Investigation and response authorization | Tested | Separate synthetic operator principals |
| Scoped temporary containment and expiry | Tested | Actual inference denial and recovery |
| Prometheus and Grafana monitoring | Tested | Metrics, dashboard queries, and failure exercises |
| Repeated authentication-failure detection | Tested | DET-004 threshold, benign mistakes, suppression, and delivery |
| Inference admission-pressure controls | Tested | Two-slot process-local admission, DET-005, and recovery |
| Central monitoring of privileged operator attempts | Tested | Operator audit correlation and DET-006 |
| MITRE ATLAS mappings | Implemented | Versioned research mapping; not comprehensive technique coverage |

**Proposed** means intended work. **Implemented** means code or configuration
exists with incomplete validation. **Tested** means evidence supports the stated
scope; it does not establish production assurance.

## Validation Results

The confirmed regression baseline is **344 passing tests**, also passing in a fresh Python 3.11 development environment installed from the hashed lockfile.

Selected integration results include:

| Exercise | Result |
|---|---|
| Actual inference activity correlated to Loki | 8/8 checks passed |
| Durable queued-finding recovery | 4/4 checks passed |
| Controlled containment and automatic recovery | 11/11 checks passed |
| Containment exercise request correlation in Loki | 5/5 checks passed |
| Grafana security dashboard data paths | 14/14 checks passed |
| Verified detector outage visibility | 2/2 checks passed |
| Detector restart recovery | 3/3 checks passed |
| Loki query-failure visibility | 3/3 checks passed |
| Query-failure recovery | 3/3 checks passed |

Check counts describe specific validation assertions, not independent security
controls.

### Detection Effectiveness

A frozen held-out evaluation generated 124 actual inference requests across
four selected scenarios:

- A small benign workload.
- A larger benign workload.
- Burst adversarial querying.
- Paced adversarial querying.

| Rule | True positives | False positives | True negatives | False negatives | Precision | Recall |
|---|---:|---:|---:|---:|---:|---:|
| DET-002 | 1 | 1 | 1 | 1 | 0.50 | 0.50 |
| DET-003 | 2 | 1 | 1 | 0 | 0.67 | 1.00 |

The longer observation window detected the selected paced scenario, but still
flagged the benign bulk workload. Request volume alone did not distinguish
intent.

These four scenarios are not representative of a production population.
Their metrics must not be interpreted as general detection-performance estimates.

### Model-Replication Research

Controlled experiments trained a separate classifier using labels obtained
through actual inference requests.

In the frozen evaluation, both replication scenarios reached 75% target agreement on 12 held-out queries each. The majority-label baselines were 50% for H03 and approximately 41.7% for H04.

This demonstrates limited imitation in a small laboratory experiment. It does
not establish complete extraction, production-model theft, or equivalent model
quality.

## Monitoring Visualization

File-provisioned Grafana dashboards include:

- Collector ingestion and delivery metrics.
- Detector scrape health and processing freshness.
- Durable finding backlog and acknowledgment activity.
- Actual inference decisions.
- Containment and policy-check events.

The security operations dashboard contains 16 panels. After plugin hardening, all 16 panel queries passed; the validation also checked dashboard provisioning and rejection of unauthenticated data queries (18 checks total).
The recorded containment request ID was retrieved through its Loki data source.

Operational metrics distinguish a stopped detector from a reachable detector
whose event queries are failing.

## Evidence

Evidence includes actual API response observations, event and finding
identifiers, persisted delivery receipts, frozen evaluation artifacts,
investigation timelines, and failure/recovery observations.

Incomplete exercises are retained separately from successful follow-up
exercises. Synthetic events and actual local application activity are labeled
distinctly.

Key reports:

- [Held-out detection assessment](evidence/public/query-volume-holdout-assessment.json)
- [Containment and recovery](evidence/public/live-containment-recovery-validation.json)
- [Containment event correlation](evidence/public/containment-loki-correlation.json)
- [Grafana data-path validation](evidence/public/security-dashboard-validation.json)
- [Verified detector outage](evidence/public/detector-outage-verified.json)
- [Detector recovery](evidence/public/detector-outage-recovery.json)
- [Query failure](evidence/public/detector-query-failure.json)
- [Query recovery](evidence/public/detector-query-failure-recovery.json)

## Documentation

1. [Threat Model](docs/threat-model.md)
2. [Mitigations and Control Register](docs/mitigations.md)
3. [Validation](docs/validation.md)
4. [Evidence Index](evidence/README.md)
5. [Residual Risks](docs/residual-risks.md)

Focused validation documents:

- [Containment Validation](docs/containment-validation.md)
- [Monitoring Resilience](docs/monitoring-resilience.md)

The final audit includes dependency reproducibility, unresolved container findings, source review, evidence sanitization, and clean service startup. Completion is recorded separately for each check.

## Local Validation

With the project virtual environment active:

```bash
python -m unittest discover -s tests -v
```

Live exercises require the relevant application processes and monitoring
containers. Their results must be evaluated within the documented prerequisites
and observation windows.

## Residual Risks

- Threshold-based rules do not establish malicious intent.
- Monitoring downtime can leave activity outside the detector's lookback window.
- Durable delivery protects queued findings, not events never observed.
- Local credentials, SQLite files, and telemetry producers remain trust
  dependencies.
- Collector producer authentication and live timestamp limits are tested; direct unauthenticated Loki access remains a separate host-local trust boundary.
- Role separation uses distinct lab principals operated by one researcher.
- Containment can interrupt legitimate activity by the selected caller.
- The small classifier and selected scenarios limit generalizability.
- No production availability, compliance certification, or comprehensive attack
  coverage is claimed.

## Dependency and Container Review

Hash-pinned installation sets are provided in requirements-runtime.lock and
requirements-dev.lock. Both candidates were audited with no known vulnerabilities
reported at audit time. Fresh installation, dependency checks, runtime imports,
and the 344-test development regression passed on macOS with Python 3.11.

Compose pins the exact scanned monitoring images by repository digest.
Unresolved vendor dependency findings remain in the monitoring containers.
Disabling unused Grafana plugins does not remediate dependencies in active plugins.

See [Container Dependency Review](docs/validation/container-dependency-review.md).

Collector authentication applies to its ingestion endpoint. Loki itself is
unauthenticated and reachable through a loopback-published port and the Compose
network. Direct Loki writes can bypass collector validation and impersonate
live telemetry. The lab therefore assumes trusted access to storage endpoints;
it does not claim end-to-end authenticated or tamper-resistant telemetry.

## Architecture and Operations

- [System Architecture and Trust Boundaries](docs/architecture.md)
- [Local Startup, Shutdown, and Optional Cleanup](docs/operations.md)

## Licensing

Original Python code and tests in src/, scripts/, and tests/ are licensed under
the [MIT License](CODE-LICENSE.md).

Original documentation, research, evaluation protocols, dashboards, and evidence
are [All Rights Reserved](LICENSE.md). Third-party materials retain their
respective licenses.
