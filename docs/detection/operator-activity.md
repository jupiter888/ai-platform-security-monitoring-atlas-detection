# Operator Activity Monitoring and Privileged Denial Detection

## Threat Model

A caller may attempt unauthorized investigation or containment operations,
supply misleading identity claims, or bypass required workflow stages.

Authorized operators can also make mistakes. A denied operation does not by
itself establish malicious intent.

## Mitigations

| Control | Status | Scope |
|---|---|---|
| Separate operator event contract | Tested | Strict parsing and Loki encoding |
| Authentication-derived operator attribution | Tested | Actual operator API activity |
| Unattributed authentication failures | Tested | No invented operator identity |
| Submitted-content exclusion | Tested | Schema tests and live canary |
| HTTP-to-audit correlation | Tested | Server-generated request IDs |
| Publication failure reporting | Tested | Local API tests |
| Repeated privileged authorization-denial detection | Tested | DET-006 local and live exercises |
| Durable retry of operator audit publication | Proposed | Not implemented |

Supported operations are case creation, reading, benign closure, containment
request, approval, and execution.

The initial live audit exercise covered case creation, reading, benign closure, and rejected approval and request operations. The later frozen response retest also correlated successful case creation, containment request, approval, execution, and final reading to five stored operator events. See [Response Retest](../response-retest.md).

## Audit Publication Semantics

Operator events are published after the operation result is known.

If publication fails, the response retains the operation's actual result and
includes X-Audit-Delivery: unavailable. A sanitized console fallback is emitted.

X-Audit-Delivery: buffered means the collector accepted the event. It does not
establish durable Loki storage.

Accepted state transitions remain recorded in the case ledger. Central audit
publication is not atomic with those transitions.

## DET-006 Configuration

| Property | Value |
|---|---|
| Version | 1.0 |
| Classification | aggregate_privileged_authorization_denials |
| Threshold | Three distinct events |
| Window | 60 seconds |
| Source | operator |
| Provenance | live-lab |
| Reason | authorization_denied |
| Outcome | denied |
| Operations | Containment request, approval, execution |
| Severity | Medium |

The rule aggregates qualifying denials across operators and cases.

Source events retain authenticated operator references. The aggregate finding
does not identify an inference caller or model target and cannot open the
current caller-specific response case.

Authentication failures, state conflicts, successful operations, and
noncontainment operations do not count toward DET-006.

## Validation

The regression suite reached 308 passing tests.

The live operator-audit exercise passed 11 checks, including correlation of eight
actual requests to Loki, submitted-content exclusion, and unchanged containment
eligibility after rejected operations.

The separate privileged-denial exercise passed nine checks:

1. The closed case, observation window, and cooldown were clear.
2. Two analyst approval attempts returned HTTP 403.
3. Two correlated denials remained below threshold.
4. A third approval attempt returned HTTP 403.
5. Three denials produced an evidence-linked finding.
6. Continuous delivery and durable acknowledgment were verified.
7. Source operator attribution was preserved without an inference target.
8. Caller-specific case creation from the aggregate finding was rejected.
9. The original case, transition history, and execution records were unchanged.

The negative threshold check was a one-shot evaluation.
The positive check additionally verified the running monitor and receiver.

No containment was requested, approved, or executed by that exercise.

## Evidence

- [Operator event contract regression](../../evidence/public/operator-event-contract-regression.txt)
- [Publisher regression](../../evidence/public/operator-publisher-regression.txt)
- [Operator API audit regression](../../evidence/public/operator-audit-regression.txt)
- [Live operator auditing](../../evidence/public/live-operator-audit.json)
- [Detection regression](../../evidence/public/operator-detection-regression.txt)
- [Live privileged-denial detection](../../evidence/public/live-operator-denial-detection.json)

## Residual Risks

- Aggregation can combine unrelated operators or cases.
- Low-volume misuse can remain below threshold.
- Authorized mistakes can trigger the rule.
- Suppression can hide subsequent qualifying activity during the cooldown.
- Operator-event publication has no durable retry queue.
- Console fallback is not guaranteed persistent evidence.
- Publication failure does not roll back completed state changes.
- Telemetry producer authentication remains a trust dependency.
- The current targeted case workflow cannot manage aggregate findings.
- Role separation does not demonstrate independent human review.
