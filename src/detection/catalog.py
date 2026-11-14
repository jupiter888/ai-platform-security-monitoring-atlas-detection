"""
Project 10 — Immutable detection rule definitions.

Thresholds are laboratory configurations, not production baselines.
"""

from dataclasses import dataclass
from types import MappingProxyType


@dataclass(frozen=True)
class DetectionRule:
    rule_id: str
    version: str
    reason: str
    outcome: str
    classification: str
    severity: str
    threshold: int
    window_seconds: int


MODEL_ACCESS_RULE = DetectionRule(
    rule_id="DET-001",
    version="1.0",
    reason="model_access_denied",
    outcome="denied",
    classification="repeated_model_access_denials",
    severity="medium",
    threshold=5,
    window_seconds=60,
)

QUERY_VOLUME_RULE = DetectionRule(
    rule_id="DET-002",
    version="1.0",
    reason="inference_succeeded",
    outcome="allowed",
    classification="elevated_inference_query_volume",
    severity="medium",
    threshold=20,
    window_seconds=60,
)

SUSTAINED_QUERY_RULE = DetectionRule(
    rule_id="DET-003",
    version="1.0",
    reason="inference_succeeded",
    outcome="allowed",
    classification="sustained_inference_query_volume",
    severity="medium",
    threshold=30,
    window_seconds=180,
)

AUTH_FAILURE_RULE = DetectionRule(
    rule_id="DET-004",
    version="1.0",
    reason="authentication_failed",
    outcome="denied",
    classification="aggregate_authentication_failures",
    severity="medium",
    threshold=5,
    window_seconds=60,
)


ADMISSION_PRESSURE_RULE = DetectionRule(
    rule_id="DET-005",
    version="1.0",
    reason="concurrency_exceeded",
    outcome="unavailable",
    classification="repeated_inference_admission_rejections",
    severity="medium",
    threshold=3,
    window_seconds=60,
)


OPERATOR_DENIAL_RULE = DetectionRule(
    rule_id="DET-006",
    version="1.0",
    reason="authorization_denied",
    outcome="denied",
    classification="aggregate_privileged_authorization_denials",
    severity="medium",
    threshold=3,
    window_seconds=60,
)


RULES = MappingProxyType({
    MODEL_ACCESS_RULE.rule_id: MODEL_ACCESS_RULE,
    QUERY_VOLUME_RULE.rule_id: QUERY_VOLUME_RULE,
    SUSTAINED_QUERY_RULE.rule_id: SUSTAINED_QUERY_RULE,
    AUTH_FAILURE_RULE.rule_id: AUTH_FAILURE_RULE,
    ADMISSION_PRESSURE_RULE.rule_id: ADMISSION_PRESSURE_RULE,
    OPERATOR_DENIAL_RULE.rule_id: OPERATOR_DENIAL_RULE,
})