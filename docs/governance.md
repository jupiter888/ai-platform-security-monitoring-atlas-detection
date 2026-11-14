# Monitoring and Response Governance

## Purpose

Define responsibility for monitoring, detection changes, response authorization,
evidence handling, and residual-risk decisions in the local laboratory.

## Status

**Implemented:** This documented operating procedure.

**Tested:** Selected technical role boundaries, case transitions, audit
publication, containment, and recovery.

A complete organizational governance process and independent human approval
have not been demonstrated.

## Ownership and Authority

| Responsibility | Accountable role | Authority |
|---|---|---|
| Lab operation | Project owner | Start, stop, configure, and maintain the local lab |
| Detection engineering | Rule owner | Propose rule changes and prepare validation evidence |
| Rule review | Designated reviewer | Review rationale, evidence, trade-offs, and rollback |
| Investigation | Analyst | Review findings, record dispositions, request scoped containment |
| Containment approval | Approver | Approve the persisted caller/model/action/duration scope |
| Response execution | Responder | Execute an eligible approved action |
| Residual-risk acceptance | Project owner | Accept documented risks for the controlled lab scope |
| Publication review | Project owner | Approve sanitized artifacts and accurate public claims |

The project owner currently performs the human responsibilities.
Separate credentials enforce technical roles but do not create independent
human review.

Rule ownership and review are procedural responsibilities. They are not
implemented as authenticated rule-management API roles.

## Rule-Change Procedure

Before changing a rule:

1. Record the observed problem and supporting evidence.
2. Identify the proposed rule version, threshold, window, grouping, severity,
   suppression behavior, and telemetry prerequisites.
3. State the expected benefit and possible new false positives or blind spots.
4. Preserve the previous configuration and evaluation results.
5. Define acceptance criteria and rollback conditions before generating traffic.
6. Run relevant automated checks and controlled integration exercises.
7. Evaluate against development scenarios.
8. Use a separately frozen evaluation set for any new held-out claim.
9. Record the review outcome and residual risks.
10. Activate the change deliberately and verify startup configuration, monitoring
    health, finding delivery, and affected dashboards.

Do not retune against a completed held-out set and present subsequent results
as independent held-out validation.

A threshold change does not erase prior false-positive or false-negative results.

## Rollback

Rollback is appropriate when a change causes:

- Unexpected authorization or response behavior.
- Finding delivery failures.
- Unacceptable alert volume for the declared lab workload.
- Query-capacity problems or degraded monitoring freshness.
- Event-contract incompatibility.
- Regression failures or evidence inconsistency.

Rollback procedure:

1. Stop the affected producer or detector without deleting persistent evidence.
2. Restore the reviewed prior configuration or code version.
3. Restart affected services in dependency order.
4. Verify healthy collection, queries, and delivery.
5. Run the relevant regression and bounded integration checks.
6. Record the failed change, rollback reason, and verification result.

Do not activate an old version that bypasses a newer required authentication or
event-contract boundary. Compatibility must be reviewed before rollback.

No Git-based rollback workflow is claimed as tested at this stage.

## Event-Contract Changes

Contract changes affect multiple running processes.

Required sequence:

1. Update validators, producers, fixtures, and isolated tests.
2. Run relevant regression checks.
3. Pause affected producers when necessary.
4. Drain the in-memory collector buffer.
5. Activate collector support before updated producers.
6. Verify synthetic compatibility using fixture credentials.
7. Restart affected application producers.
8. Verify actual application activity through to Loki.
9. Preserve incomplete exercises and compatibility failures.

Restarting a process reloads its imported contract. Editing source files alone
does not update a running service.

## Response Authorization

A finding is evidence for investigation, not automatic proof of malicious intent.

Before requesting containment, the analyst should review:

- Supporting event IDs and timestamps.
- Caller attribution and model scope.
- Scenario context and plausible benign explanations.
- Prior related findings and suppression.
- Telemetry completeness and monitoring health.
- Expected impact on legitimate activity.

The approver reviews the persisted action, target, duration, and policy version.

The responder executes the approved scope using a distinct principal.
The implemented action lasts 60 seconds and is single-execution per case.

Aggregate findings without an inference caller/model target cannot open the
current targeted response case.

## Response Completion

Confirm:

1. The approved target was restricted.
2. Supporting denial events correlate to actual requests.
3. Selected unaffected access remained available.
4. Repeated execution did not extend the original block.
5. Access recovered after expiry.
6. Case history and operator audit records match the response sequence.

The case remains containment_executed after expiry. That state records historical
execution; it does not indicate that the block is still active.

## Evidence Handling

- Use synthetic data and laboratory identities.
- Keep credentials and private runtime databases outside the project directory.
- Exclude raw prompts, credentials, tokens, and arbitrary submitted content from
  operational telemetry.
- Preserve original failed and incomplete reports.
- Create separately identified follow-up evidence rather than overwriting failures.
- Record protocol hashes and preserve frozen evaluation inputs.
- Review source, configuration, reports, visualizations, and metadata before
  publication.

Public evidence is a selected, sanitized record. It is not a complete export of
runtime databases or all operational logs.

## Retention and Cleanup

Configured Loki and Prometheus retention is 24 hours.
Actual deletion timing is controlled by the respective storage mechanisms.

The collector queue and duplicate cache are in memory and disappear on restart.

Finding, outbox, case, and execution records persist in private SQLite files.
No automatic retention cleanup has been implemented for those files.

Use clean startup and shutdown procedures that preserve evidence by default.
Delete persistent data only through a separately reviewed cleanup procedure.

## Residual-Risk Acceptance

A risk record should identify:

- The affected asset or control.
- The observed limitation.
- Supporting evidence.
- Likely impact within the lab scope.
- Existing safeguards.
- The accepting authority.
- Conditions requiring reassessment.

Documentation of a limitation is not, by itself, a formal acceptance decision.

Any acceptance in this project applies only to the controlled local laboratory.
It does not authorize use of the same design for production or employer systems.

## Evidence

- [Operator monitoring](detection/operator-activity.md)
- [Containment validation](containment-validation.md)
- [Response retest](response-retest.md)
- [Telemetry integrity](telemetry-integrity.md)
- [Monitoring resilience](monitoring-resilience.md)
- [Research mappings](research/framework-mapping.md)