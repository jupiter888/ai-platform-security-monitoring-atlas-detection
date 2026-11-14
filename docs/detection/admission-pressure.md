# Inference Admission Control and Pressure Detection

## Threat Model

Concurrent authorized requests can consume inference capacity and affect
availability for other callers.

Admission pressure can arise from legitimate workloads, misconfigured clients,
or intentional abuse. Rejections alone do not establish malicious intent.

## Mitigations

### Process-Local Admission Control

**Status: Tested — local tests and actual API activity.**

The inference API admits at most two requests per process into the protected
policy-checking and inference path.

Authentication, model authorization, and basic request validation occur before
admission. Excess authorized requests receive:

- HTTP 503.
- A bounded capacity-unavailable response.
- Retry-After: 1.
- A concurrency_exceeded event correlated through X-Request-ID.

Rejected requests do not enter the protected model-execution path.

Admitted requests retain their slot through policy checking, model execution,
and successful-event publication. A finally block releases the slot on success
or failure.

The retry hint does not reserve future capacity or guarantee that retrying after
one second will succeed.

### DET-005 — Repeated Admission Rejections

**Status: Tested — selected local paths.**

| Property | Configuration |
|---|---|
| Rule ID | DET-005 |
| Version | 1.0 |
| Classification | repeated_inference_admission_rejections |
| Threshold | Three distinct events |
| Window | 60 seconds |
| Grouping | Authenticated caller and requested model |
| Source | Gateway |
| Provenance | live-lab |
| Reason | concurrency_exceeded |
| Outcome | unavailable |
| Severity | Medium |

Evaluation uses collection timestamps and distinct event IDs.

The rule identifies pressure on the admission boundary. It does not measure
resource utilization, establish service saturation, or determine intent.

## Validation

The regression suite reached 272 passing tests.

Admission tests cover:

- Invalid limit configuration.
- Bounded, nonblocking capacity.
- Rejection before additional model execution.
- Recovery after admitted work completes.
- Capacity release after policy failure, containment denial, telemetry failure,
  and model exception.
- Authentication and authorization before admission.

Rule tests cover threshold behavior, finding validation, exclusion of unrelated
denials, and continuous-evaluator integration. Existing shared detector tests
cover additional window and duplicate-handling behavior.

### Actual Admission Exercise

One burst of eight concurrent requests produced:

- Two HTTP 200 responses.
- Six HTTP 503 capacity rejections.

A subsequent recovery request succeeded.

All nine responses correlated to matching Loki events.
The exercise passed six checks.

### Actual Detection Exercise

A separate eight-request burst again produced two successful predictions and
six capacity rejections. Recovery inference succeeded.

Eight validation checks confirmed:

- A clear observation window and cooldown.
- Expected HTTP statuses and response contracts.
- Recovery after the burst.
- Correlation of all nine responses to Loki.
- A matching DET-005 condition.
- Continuous finding delivery and receiver agreement.
- An explicit live enqueue diagnostic.

A live finding may contain only the rejection events available when the
threshold was crossed. Its supporting event IDs were verified as belonging to
the exercise.

No containment was executed.

## Evidence

- [Admission regression](../../evidence/public/inference-admission-regression.txt)
- [Actual admission exercise](../../evidence/public/live-inference-admission.json)
- [Pressure-rule regression](../../evidence/public/admission-pressure-regression.txt)
- [Actual pressure detection](../../evidence/public/live-admission-pressure-detection.json)

## Residual Risks

- The admission limit is process-local. Multiple worker processes multiply
  available slots.
- The gate does not bound all HTTP connections, request parsing, authentication
  work, rejected-request telemetry, or web-server task queues.
- The limit is global to the process, not a per-caller fairness policy.
- A caller can occupy capacity needed by other callers.
- Telemetry publication extends slot occupancy and introduces an availability
  dependency.
- Model execution has no new hard execution deadline or cancellation mechanism.
- The exercises do not establish sustained-load capacity, production throughput,
  or denial-of-service resistance.
- Authorized workloads can trigger DET-005.
- Distributed admission control and cost enforcement are not implemented.