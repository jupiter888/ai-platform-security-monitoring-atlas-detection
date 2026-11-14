# DET-001 — Repeated Unauthorized Model Access

## Status

Tested within the local laboratory.

The continuous monitor evaluates DET-001 and uses a durable outbox to deliver findings to the authenticated local receiver. Receiver storage is not external notification delivery or analyst review.

## Threat

An authenticated caller repeatedly requests a model outside its assigned
authorization scope.

Possible explanations include access probing, a misconfigured client,
an outdated integration, or deliberate abuse.

## Detection Logic

Generate a finding when five or more distinct qualifying events occur within
60 seconds for the same caller reference and model.

Qualifying events require:

- Source: gateway.
- Provenance: live-lab.
- Reason: model_access_denied.
- Outcome: denied.
- A non-null synthetic authenticated caller reference.
- A recognized model.

The rule uses collector collection time. The lower window boundary is
exclusive and the upper boundary is inclusive.

## Evidence and Correlation

Findings contain rule identity, version, caller reference, model, event count,
window, timestamps, and contributing event IDs.

Repeated entries with the same event ID count once. Conflicting event content
under the same ID produces an evaluation error.

## Preventive Control

Model authorization denies the request before model invocation.

This rule detects repeated denied requests. It does not replace authorization
or establish that unauthorized inference succeeded.

## Validation

Automated tests cover threshold boundaries, grouping, duplicates, conflicting
duplicates, event order, timestamps, and excluded activity.

Evidence file:

[Detection regression](../../evidence/public/detection-regression.txt)

## Investigation

1. Review contributing event IDs and request correlation identifiers.
2. Confirm the caller's expected model permissions.
3. Determine whether the pattern is an approved test or integration error.
4. Review adjacent successful and denied requests.
5. Record the response decision and authorization before containment.

## Residual Risks

- Five requests is an initial lab threshold, not an empirically tuned limit.
- Low-rate probing can remain below the threshold.
- Benign client retries can trigger the rule.
- Distributed identities can divide activity across groups.
- Producer credentials authenticate collector submissions; direct Loki writes remain outside that enforcement boundary.
- Collection delay can distort the apparent request timing.
- Repeated evaluations can produce overlapping findings.
- The durable outbox provides group suppression and finding deduplication; these do not prevent every overlapping or semantically duplicate finding.
- Replay and synthetic fixtures are excluded from this initial live rule.
- The rule does not establish attacker intent.

## MITRE ATLAS

No technique mapping is asserted solely from repeated authorization failures.
A mapping requires a concrete AI attack objective and supporting evidence.
