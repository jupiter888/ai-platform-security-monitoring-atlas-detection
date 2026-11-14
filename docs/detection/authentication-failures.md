# DET-004 — Aggregate Authentication Failures

## Threat Model

Repeated invalid credentials can indicate unauthorized access attempts,
misconfigured clients, expired credentials, or ordinary operator mistakes.

The available telemetry does not establish a shared caller identity or intent.
This rule aggregates gateway activity without attributing failures to a person,
application, IP address, or attacker.

## Mitigation and Detection

**Status: Tested — selected local paths.**

| Property | Configuration |
|---|---|
| Rule ID | DET-004 |
| Version | 1.0 |
| Classification | aggregate_authentication_failures |
| Severity | Medium |
| Threshold | Five distinct events |
| Window | 60 seconds |
| Source | Gateway |
| Provenance | live-lab |
| Reason | authentication_failed |
| Outcome | denied |
| Caller attribution | Unknown |
| Finding model target | not-applicable |

Missing credentials are a separate signal and do not count toward this rule.

Evaluation uses collection timestamps with an exclusive lower boundary and
inclusive upper boundary. Identical duplicate records do not increase the count.
Conflicting records sharing an event ID are rejected.

The finding preserves source event identifiers. Its fingerprint is deterministic
for the ordered evidence set.

## Response Restrictions

The finding can be retrieved from the authenticated finding receiver.

It cannot open the current caller-specific response case because no supported
caller/model containment target exists.

This restriction prevents aggregate authentication activity from being converted
into an invented caller identity or an unsupported containment action.

A general investigation workflow for unattributed findings remains to be added.

## Validation

The regression suite reached 260 tests after monitor integration.

Local tests cover:

- Below-threshold and threshold behavior.
- Aggregation across requested models.
- Exclusion of missing credentials, synthetic events, and replay events.
- Window boundaries and future collection timestamps.
- Duplicate and conflicting event handling.
- Stable evidence ordering.
- Rejection of invented identity or model attribution.
- Finding-store persistence and outbox suppression.
- Rejection of caller-specific case creation.

The live exercise passed nine checks:

1. Observation window and delivery cooldown were clear.
2. Four invalid-credential requests returned HTTP 401.
3. All four requests correlated to unattributed authentication events.
4. Four events produced no finding in one-shot threshold evaluation.
5. The fifth invalid-credential request returned HTTP 401.
6. Five events produced one evidence-linked finding.
7. The continuous monitor delivered the finding to durable storage.
8. The stored finding retained unknown identity and no model target.
9. Caller-specific case creation was rejected.

The below-threshold live check was a one-shot evaluation.
Continuous delivery was verified for the positive threshold case.

## Evidence

- [Regression](../../evidence/public/authentication-monitor-regression.txt)
- [Live authentication detection](../../evidence/public/live-authentication-detection.json)

## Residual Risks

- Aggregate failures may combine unrelated callers.
- Low-volume attempts can remain below threshold.
- Benign credential mistakes or configuration failures can trigger the rule.
- No source-network attribution or distributed-attack distinction is available.
- Collection-time evaluation can differ from source-time activity.
- Producer trust and telemetry completeness remain dependencies.
- A declared benign credential-misconfiguration scenario crossed the threshold.
  Treating that finding as malicious activity would be an operational false
  positive; no population-level false-positive rate is established.
- Suppression can also hide additional unrelated failures because the rule
  aggregates gateway activity without caller attribution.

## Benign Activity and Live Suppression

A separate controlled benign scenario passed ten checks:

- Two invalid-credential requests were rejected.
- A corrected credential successfully invoked inference.
- Two failures remained below threshold.
- Three further misconfigured requests brought the count to five.
- The resulting finding was delivered and acknowledged.
- A sixth failure produced a distinct six-event candidate.
- The continuous monitor explicitly logged that candidate as suppressed.
- The suppressed candidate was absent from the outbox while the original
  acknowledgment remained.

The successful authenticated retry did not erase earlier authentication
failures. The rule measures aggregate failure volume, not credential-recovery
state or intent.

Evidence:
[Benign authentication and suppression](../../evidence/public/authentication-benign-suppression.json).
