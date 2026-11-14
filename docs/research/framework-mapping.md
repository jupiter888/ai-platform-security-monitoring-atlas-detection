# Research and Framework Mapping

**Review date:** November 14, 2026
**Scope:** Standalone local AI security monitoring laboratory

## Interpretation

The mappings below are the project author's interpretation of demonstrated
behavior and defensive architecture.

An adversary-technique mapping describes an exercised behavior, not proof of
malicious intent. A defensive mapping does not establish that a technique is
comprehensively prevented.

Control status and experimental evidence remain separate from framework
terminology.

## MITRE ATLAS Reference

Content release: v2026.10.

Primary sources:

- [Versioned release](https://github.com/mitre-atlas/atlas-data/releases/tag/v2026.10)
- [Authoritative data repository](https://github.com/mitre-atlas/atlas-data)
- [ATLAS knowledge base](https://atlas.mitre.org/)

ATLAS terminology changes over time. This document records the reviewed content
release rather than describing identifiers and names as permanently current.

### Selected Behavior Mappings

| Reference | Project interpretation | Evidence | Limitation |
|---|---|---|---|
| AML.T0040 — AI Model Inference API Access | Controlled experiments use authorized inference access as the interface for collecting target predictions | Actual API activity and replication experiments | Ordinary authorized API use is not inherently adversarial |
| AML.T0135 — Outputs from AI Models | Replication experiments collect observable model outputs | Query records and target predictions in experiment artifacts | Output collection does not establish unauthorized exfiltration |
| AML.T0005.001 — Replicate Behavior from Model Outputs | A separate classifier is trained from labels obtained through target queries | Burst and paced replication experiments, including held-out scenarios | Limited behavioral imitation; no complete extraction or production-model theft claim |

The controlled H03 experiment achieved 0.75 held-out agreement with the target,
against a 0.50 majority-label baseline.

The controlled H04 experiment also achieved 0.75 agreement, against a
0.4167 majority-label baseline.

These measurements describe small, selected synthetic experiments. They are
not population-level estimates of model-replication effectiveness.

The official MITRE D3FEND reference also describes inference API access and
replication behavior:

- [Inference API access](https://d3fend.mitre.org/offensive-technique/attack/AML.T0040/)
- [Replication sub-technique](https://d3fend.mitre.org/offensive-technique/attack/AML.T0005.001/)

The latter may display older terminology; the ATLAS content release above
provides the versioned name used in this document.

### Defensive Alignment

| Reference | Local implementation | Status | Scope |
|---|---|---|---|
| AML.M0024 — AI Telemetry Logging and Monitoring | Validated events, Loki storage, continuous detection, Prometheus metrics, Grafana dashboards, and investigation correlation | Tested | Selected local security and operational paths |

This is architectural alignment with the mitigation concept. It is not a claim
that every ATLAS mitigation relationship or attack path has been validated.

### Behaviors Without a Forced Technique Mapping

| Local behavior | Treatment |
|---|---|
| Repeated model-access denials | Authorization monitoring; denied access alone does not establish a completed adversary technique |
| Aggregate authentication failures | Identity-abuse signal with unknown attribution; no credential-compromise claim |
| Authorized admission-pressure exercise | Capacity-control validation; no demonstrated service-level denial of service |
| Rejected privileged operator attempts | Role and workflow boundary validation; no successful privilege-escalation claim |
| Detector and Loki outages | Monitoring-resilience exercises |
| Producer authentication and timestamp checks | Telemetry-integrity controls |

DET-002 and DET-003 detect successful-query volume. They do not establish
replication intent or verify that a replica was trained.

The model-imitation experiment and the detection evaluation are separate
measurements.

## NIST AI RMF Mapping

Reference: NIST AI RMF 1.0.

Primary sources:

- [Framework publication](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-ai-rmf-10)
- [Framework PDF](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf)
- [Companion Playbook](https://www.nist.gov/itl/ai-risk-management-framework/nist-ai-rmf-playbook)

This is a function-level mapping. It does not assert full subcategory coverage.

| Function | Supporting project activity | Evidence and limitation |
|---|---|---|
| GOVERN | Operator roles, approval boundaries, audit records, change-review and ownership procedures | Role enforcement is tested; separate credentials were operated by one researcher |
| MAP | Defined classifier, interfaces, trust dependencies, permitted scenarios, and coverage gaps | Context is a controlled local lab, not an organizational deployment assessment |
| MEASURE | Frozen evaluation, threshold checks, false-positive and false-negative analysis, latency measurements, telemetry canaries, and outage exercises | Results apply to selected scenarios and documented observation windows |
| MANAGE | Approved scoped containment, expiry, recovery, response retesting, and explicit residual-risk treatment | Local response behavior is tested; production incident management is not demonstrated |

## Research Findings

- Successful-query volume can identify activity associated with replication
  without identifying intent.
- A benign bulk workload triggered both evaluated query-volume rules.
- Paced activity evaded the shorter window in the selected held-out scenario.
- The longer window improved selected-scenario recall but retained a benign
  false positive.
- A reachable metrics endpoint did not establish healthy detection queries.
- Durable finding delivery protected queued findings, not activity never observed.
- Scoped containment blocked the selected query access and recovered after expiry.
- Producer credentials constrain source claims but do not independently establish
  event truthfulness.

## Evidence

- [Held-out assessment](../../evidence/public/query-volume-holdout-assessment.json)
- [Response retest](../../evidence/public/containment-retest-assessment.json)
- [Monitoring resilience](../monitoring-resilience.md)
- [Telemetry integrity](../telemetry-integrity.md)
- [Operator monitoring](../detection/operator-activity.md)

## Residual Risks

- Framework mappings are interpretive and version-dependent.
- Technique labels do not establish attack success or detection completeness.
- Small deterministic scenarios limit generalizability.
- No regulatory compliance, certification, or independent assurance is claimed.
