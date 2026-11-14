"""
Freeze the query-volume held-out verification protocol.

Contains synthetic queries and evaluator-only ground truth.
Does not initialize Git, access credentials, or send requests.
"""

import hashlib
import json
import random
import re
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from src.detection.catalog import QUERY_VOLUME_RULE
from src.emulation.replication import (
    HELDOUT_QUERIES,
    TRAINING_QUERIES,
)


PREFIXES = (
    "Compare research on",
    "Summarize studies of",
    "Explain observations about",
    "Describe evidence concerning",
    "Outline an investigation of",
    "Review scientific findings about",
    "Identify research questions about",
    "Discuss measurements related to",
    "Prepare a short overview of",
    "Describe an experiment involving",
    "Explain the mechanisms behind",
    "Summarize the main features of",
)

TOPICS = (
    "galaxy observations with telescopes",
    "planetary orbits around stars",
    "stellar explosions and supernova light",
    "comet motion through the solar system",
    "water absorption by plant roots",
    "photosynthesis in green leaves",
    "flower pollination and pollen transfer",
    "seed germination and stem growth",
    "mineral composition of volcanic rocks",
    "earthquake faults in the crust",
    "sediment erosion and rock layers",
    "tectonic plate movement near the mantle",
)


def main():
    directory = Path("config/evaluation")
    directory.mkdir(parents=True, exist_ok=True)

    manifest_path = directory / "query-volume-holdout.json"
    hash_path = directory / "query-volume-holdout.sha256"

    if manifest_path.exists() or hash_path.exists():
        raise RuntimeError(
            "Existing frozen protocol preserved; no files overwritten"
        )

    development = json.loads(
        Path(
            "evidence/public/model-replication-experiment.json"
        ).read_text(encoding="utf-8")
    )
    model_version = development["target_model_version"]
    if re.fullmatch(r"[0-9a-f]{16}", model_version) is None:
        raise RuntimeError("Invalid target model version")

    pool = [
        f"{prefix} {topic}."
        for prefix in PREFIXES
        for topic in TOPICS
    ]

    if len(pool) != len(set(pool)):
        raise RuntimeError("Duplicate generated query")

    development_queries = set(TRAINING_QUERIES + HELDOUT_QUERIES)
    if development_queries.intersection(pool):
        raise RuntimeError("Exact development query reused")

    random.Random(20261113).shuffle(pool)

    definitions = [
        ("H01", "routine-research", "benign", 12, 0.25),
        ("H02", "approved-bulk-processing", "benign", 40, 0.25),
        (
            "H03",
            "burst-replication",
            "authorized-adversarial-emulation",
            36,
            0.25,
        ),
        (
            "H04",
            "paced-replication",
            "authorized-adversarial-emulation",
            36,
            3.5,
        ),
    ]

    scenarios = []
    offset = 0

    for scenario_id, name, truth, count, spacing in definitions:
        queries = pool[offset:offset + count]
        offset += count

        if len(queries) != count:
            raise RuntimeError("Insufficient unique queries")

        adversarial = truth == "authorized-adversarial-emulation"

        scenarios.append({
            "scenario_id": scenario_id,
            "name": name,
            "ground_truth": truth,
            "request_count": count,
            "spacing_after_response_seconds": spacing,
            "replica_training_queries": 24 if adversarial else 0,
            "replica_evaluation_queries": 12 if adversarial else 0,
            "queries": queries,
        })

    manifest = {
        "protocol_version": "1.0",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "purpose": "predeclared-heldout-verification",
        "target_model": "research-model",
        "expected_target_model_version": model_version,
        "caller_ref": "lab-caller-reader",
        "maximum_total_requests": 124,
        "minimum_inter_scenario_quiet_seconds": 190,
        "baseline_rule": asdict(QUERY_VOLUME_RULE),
        "candidate_rule": {
            "rule_id": "DET-003",
            "version": "1.0",
            "reason": "inference_succeeded",
            "outcome": "allowed",
            "classification": "sustained_inference_query_volume",
            "severity": "medium",
            "threshold": 30,
            "window_seconds": 180,
        },
        "scenarios": scenarios,
        "evaluation_requirements": [
            "Verify manifest hash before execution",
            "Verify expected target model version",
            "Confirm services and continuous monitoring are healthy",
            "Confirm no pending findings or active scenario suppression",
            "Isolate scenarios using the declared quiet interval",
            "Keep ground truth out of detector inputs",
            "Correlate actual request IDs and source events",
            "Evaluate each rule and combined coverage separately",
            "Preserve failures and inconclusive runs",
            "Do not tune thresholds against these outcomes",
        ],
        "limitations": [
            "Small deterministic verification set",
            "New instances, not a statistically independent blind benchmark",
            "Related vocabulary across development and held-out queries",
            "No population-level performance claim",
            "Finding volume does not establish intent",
        ],
    }

    raw = (
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n"
    ).encode("utf-8")
    digest = hashlib.sha256(raw).hexdigest()

    with manifest_path.open("xb") as handle:
        handle.write(raw)

    with hash_path.open("x", encoding="utf-8") as handle:
        handle.write(f"{digest}  {manifest_path.name}\n")

    print("Frozen scenarios:", len(scenarios))
    print("Maximum total inference requests:", offset)
    print("Unique held-out queries:", len({
        query
        for scenario in scenarios
        for query in scenario["queries"]
    }))
    print("Manifest SHA256:", digest)
    print("No traffic generated; live rules unchanged.")

if __name__ == "__main__":
    main()