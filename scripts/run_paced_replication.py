"""
Project 10 — Paced variant of the model-replication experiment.

Reuses the same oracle, query corpus, and replica evaluation.
Changes request pacing only.

Detection outcome is assessed separately using source events,
monitor coverage, and stored findings.
"""

import json
import sqlite3
import time
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

from src.emulation.replication import (
    HELDOUT_QUERIES,
    MAX_QUERY_BUDGET,
    TRAINING_QUERIES,
    InferenceOracle,
    evaluate_replica,
)


INTERVAL_SECONDS = 3.5


def verify_monitoring_state():
    path = (
        Path.home()
        / ".local/share/project10/monitoring/outbox.sqlite3"
    )
    if not path.is_file():
        raise RuntimeError("Existing outbox database is required")

    with closing(sqlite3.connect(
        path.as_uri() + "?mode=ro",
        uri=True,
    )) as connection:
        rows = connection.execute(
            "SELECT payload_json, delivered_at FROM finding_outbox"
        ).fetchall()

    now = datetime.now(timezone.utc)

    for payload, delivered_at in rows:
        finding = json.loads(payload)

        if (
            finding["rule_id"] != "DET-002"
            or finding["caller_ref"] != "lab-caller-reader"
            or finding["model"] != "research-model"
        ):
            continue

        if delivered_at is None:
            raise RuntimeError(
                "A DET-002 finding is pending; resolve it before this run"
            )

        age = (
            now - datetime.fromisoformat(delivered_at)
        ).total_seconds()

        if age < 65:
            raise RuntimeError(
                "Wait until at least 65 seconds after the last "
                "DET-002 delivery, then retry"
            )


def main():
    destination = Path(
        "evidence/public/paced-replication-experiment.json"
    )
    if destination.exists():
        raise RuntimeError(
            "Paced report already exists; preserved without overwriting"
        )

    if len(TRAINING_QUERIES) + len(HELDOUT_QUERIES) != MAX_QUERY_BUDGET:
        raise RuntimeError("Unexpected query budget")

    verify_monitoring_state()

    credential_path = (
        Path.home()
        / ".config/project10/credentials/inference-clients.json"
    )
    credentials = json.loads(
        credential_path.read_text(encoding="utf-8")
    )
    oracle = InferenceOracle(credentials["reader_key"])

    started_at = datetime.now(timezone.utc).isoformat()
    started_clock = time.monotonic()
    training = []
    heldout = []
    completed = 0

    print(
        "Starting 36 real inference requests at 3.5-second spacing.",
        flush=True,
    )
    print(
        "Keep the collector, API, receiver, monitor, and Docker running.",
        flush=True,
    )

    for observations, queries in (
        (training, TRAINING_QUERIES),
        (heldout, HELDOUT_QUERIES),
    ):
        for text in queries:
            observations.append(oracle.query(text))
            completed += 1

            if completed % 6 == 0:
                print(
                    f"Completed {completed}/{MAX_QUERY_BUDGET} requests",
                    flush=True,
                )

            if completed < MAX_QUERY_BUDGET:
                time.sleep(INTERVAL_SECONDS)

    responses = training + heldout
    if len({item["request_id"] for item in responses}) != MAX_QUERY_BUDGET:
        raise RuntimeError("Repeated request correlation identifier")

    versions = {item["model_version"] for item in responses}
    if len(versions) != 1:
        raise RuntimeError("Target model changed during the experiment")

    evaluation = evaluate_replica(
        [item["text"] for item in training],
        [item["label"] for item in training],
        [item["text"] for item in heldout],
        [item["label"] for item in heldout],
    )

    report = {
        "scenario": "paced-output-based-model-replication",
        "ground_truth": "authorized-adversarial-emulation",
        "data_provenance": "synthetic-research-queries",
        "started_at": started_at,
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(
            time.monotonic() - started_clock, 3
        ),
        "target_model": "research-model",
        "target_model_version": next(iter(versions)),
        "query_budget": MAX_QUERY_BUDGET,
        "requests_completed": len(responses),
        "minimum_spacing_after_response_seconds": INTERVAL_SECONDS,
        "suppression_inactive_at_preflight": True,
        "training_queries": len(training),
        "heldout_queries": len(heldout),
        "evaluation": evaluation,
        "training_observations": training,
        "heldout_observations": heldout,
        "limitations": [
            "Same small query corpus as the burst experiment",
            "Not an independent generalization benchmark",
            "No complete model extraction or production accuracy claim",
            "Actual collection-window volume requires separate verification",
            "Detection absence requires monitoring-health evidence",
        ],
    }

    destination.write_text(
        json.dumps(report, indent=2) + "\n",
        encoding="utf-8",
    )

    print(json.dumps({
        "requests_completed": len(responses),
        "elapsed_seconds": report["elapsed_seconds"],
        "heldout_target_agreement": evaluation[
            "heldout_target_agreement"
        ],
        "majority_baseline_agreement": evaluation[
            "majority_baseline_agreement"
        ],
        "detection_outcome": "not-yet-assessed",
    }, indent=2))
    print("Paced experiment report saved.", flush=True)

if __name__ == "__main__":
    main()