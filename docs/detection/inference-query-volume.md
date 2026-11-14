# DET-002 — Elevated Inference Query Volume

## Status

Tested within the documented local scenarios.

Continuous evaluation, durable outbox delivery, and authenticated receiver storage are connected. The frozen four-scenario evaluation recorded one true positive, one false positive, one true negative, and one false negative for DET-002. See [Validation](../validation.md) and the [held-out assessment](../../evidence/public/query-volume-holdout-assessment.json).

## Threat and Monitoring Objective

Repeated access to an inference API may support abusive resource consumption
or collection of model outputs.

Legitimate batch processing can produce the same volume pattern.

This rule identifies elevated successful query volume. It does not establish
model extraction, service degradation, or malicious intent.

## Detection Logic

Generate a finding for 20 or more distinct successful inference events within
60 seconds for the same authenticated caller reference and model.

Required telemetry:

- Source: gateway.
- Provenance: live-lab.
- Reason: inference_succeeded.
- Outcome: allowed.
- A recognized model and non-null caller reference.
- Event ID and collector timestamp.

The rule uses collection time. Duplicate event IDs count once.

## Validation Criteria

- Verify threshold, grouping, time boundaries, and duplicate handling.
- Execute actual model queries through the authenticated API.
- Exercise below-threshold benign traffic.
- Exercise a legitimate batch that crosses the threshold.
- Exercise controlled repeated querying with a declared adversarial objective.
- Record scenario-level true positives, false positives, and false negatives.
- Evaluate tuning on a separate scenario set.

Ground-truth scenario labels must not be supplied to the detection rule.

## Residual Risks

- The threshold is an initial laboratory value.
- Volume alone cannot distinguish approved batches from abuse.
- Low-rate activity and distributed identities may evade the rule.
- The rule does not measure input diversity or output collection.
- It does not establish successful model replication.
- Collection delay can distort apparent request timing.
- Monitoring failed inference attempts requires additional signals.

## MITRE ATLAS

An indicator is not itself proof of a technique.

Technique mappings will accompany concrete controlled attack scenarios and
their observed outcomes. No extraction or denial-of-service coverage is
claimed solely from crossing this threshold.
