# Controlled Containment and Recovery Validation

## Threat Model

An authenticated caller may use permitted model access for activity requiring
investigation and a temporary response.

Query-volume detections do not establish malicious intent. Approved research
batches can also trigger findings, so detection alone does not authorize
containment.

## Mitigations

| Control | Status | Scope |
|---|---|---|
| Analyst requests containment | Tested | Authenticated local operator API |
| Distinct approver authorizes stored scope | Tested | Separate synthetic operator principal |
| Responder executes approved containment | Tested | Responder-only execution endpoint |
| Fixed response scope | Tested | One caller and model for 60 seconds |
| Inference enforcement | Tested | Access checked before model invocation |
| Single execution | Tested | Repeated execution preserves original expiry |
| Automatic recovery | Tested | Access becomes available after expiry |
| Policy lookup failure handling | Tested | Local tests verify fail-closed behavior |
| Security-event correlation | Tested | Five live inference requests verified in Loki |

Role separation uses distinct lab credentials operated by the same researcher.
It does not demonstrate independent human approval.

## Validation

The local regression suite passed 240 tests before the live exercise.

The successful live exercise passed 11 checks:

1. Persisted approval matched the intended scope.
2. Reader inference succeeded before containment.
3. Admin inference succeeded before containment.
4. Analyst execution was rejected.
5. The responder executed the approved scope.
6. The response duration was exactly 60 seconds.
7. Contained Reader inference returned HTTP 403 without prediction output.
8. Admin access to the restricted model remained available.
9. Repeated execution did not extend containment.
10. Reader inference recovered after expiry.
11. The case retained its execution history.

Five inference observations were separately correlated to Loki using their
response request IDs, expected caller, model, reason, and outcome.

### Initial Incomplete Exercise

The first exercise recorded containment execution but failed its inference
denial assertion. Its unexpected HTTP response was not captured.

Subsequent compatibility probes demonstrated that the running collector rejected
both newly introduced event reasons with HTTP 400. After restarting the
collector, both reasons were accepted with HTTP 202.

This supports a stale collector event contract as the explanation for the failed
check, but does not reconstruct the original HTTP response conclusively.

The incomplete report was preserved. A separate case and evidence report were
used for the successful exercise.

## Evidence

- [Operator execution regression](../evidence/public/operator-execution-regression.txt)
- [Initial incomplete exercise](../evidence/public/live-containment-validation.json)
- [Recovery exercise preparation](../evidence/public/containment-recovery-preparation.json)
- [Live containment and recovery](../evidence/public/live-containment-recovery-validation.json)
- [Loki request correlation](../evidence/public/containment-loki-correlation.json)

These results demonstrate controlled local API activity. They do not establish
Azure or Databricks response integration.

## Residual Risks

- Containment affects all matching requests, including legitimate activity by
  the contained caller.
- Requests already executing are not canceled.
- The access check and model invocation are separate operations; this is not
  an atomic admission-and-execution boundary.
- Local SQLite state and operator credentials remain privileged dependencies.
- Expiry depends on the system clock.
- Approval has no separately enforced freshness deadline.
- Accepted case transitions are recorded, but rejected operator attempts have
  not been demonstrated as centrally ingested security events.
- Collector acceptance is required for the inference response; telemetry
  incompatibility or unavailability can therefore affect API availability.
- Request correlation does not establish tamper-resistant or complete logging.
- Distributed enforcement, independent human approval, and production response
  effectiveness have not been demonstrated.