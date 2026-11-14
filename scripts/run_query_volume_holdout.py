"""
Project 10 — Execute the frozen held-out query-volume protocol.

Generates actual local inference requests only.
Detection effectiveness is assessed separately after execution.

No automatic retries of inference requests.
Partial or failed runs are preserved, not silently overwritten.
"""

import hashlib
import json
import sqlite3
import time
from contextlib import closing
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlencode
from urllib.request import ProxyHandler, Request, build_opener

from src.detection.catalog import QUERY_VOLUME_RULE, SUSTAINED_QUERY_RULE
from src.emulation.replication import InferenceOracle, evaluate_replica
from src.telemetry.loki import NoRedirects


EXPECTED_MANIFEST_HASH = (
    "d73eac2f56e2a7161c384d1dec5c5007a22842d87d3a3575d303628a96e5530b"
)
REPORT_PATH = Path("evidence/public/query-volume-holdout-run.json")
POST_TRAFFIC_OBSERVATION_SECONDS = 20


def now():
    return datetime.now(timezone.utc).isoformat()


def save_report(report):
    temporary = REPORT_PATH.with_suffix(".json.tmp")
    temporary.write_text(
        json.dumps(report, indent=2) + "\n",
        encoding="utf-8",
    )
    temporary.replace(REPORT_PATH)


def get_json(opener, url):
    with opener.open(Request(url), timeout=10) as response:
        raw = response.read(1_048_577)
        if response.status != 200 or len(raw) > 1_048_576:
            raise RuntimeError("Unexpected service response")
        return json.loads(raw)


def verify_services(opener, expected_version):
    for endpoint, field in (
        ("http://127.0.0.1:8100/health", "detail"),
        ("http://127.0.0.1:8300/health", "status"),
    ):
        if get_json(opener, endpoint).get(field) != "ok":
            raise RuntimeError("Required service is not healthy")

    health = get_json(opener, "http://127.0.0.1:8200/health")
    if (
        health.get("status") != "ok"
        or health.get("model_version") != expected_version
    ):
        raise RuntimeError("Target model health or version mismatch")

    with opener.open(
        "http://127.0.0.1:3100/ready",
        timeout=10,
    ) as response:
        if response.status != 200:
            raise RuntimeError("Loki is not ready")


def verify_monitor():
    path = Path("evidence/public/holdout-monitor.jsonl")
    raw = path.read_bytes()
    if len(raw) > 20_971_520:
        raise RuntimeError("Monitor log exceeds runner limit")

    records = []
    lines = raw.decode("utf-8").splitlines()

    for index, line in enumerate(lines):
        if not line.strip():
            continue
        try:
            records.append(json.loads(line))
        except ValueError:
            if index != len(lines) - 1:
                raise RuntimeError("Malformed monitor log") from None

    starts = [
        record for record in records
        if record.get("event") == "detection_monitor_started"
    ]
    polls = [
        record for record in records
        if record.get("event") == "detection_poll"
    ]

    if (
        not starts
        or starts[-1].get("rule_ids") != [
            "DET-001", "DET-002", "DET-003"
        ]
        or starts[-1].get("lookback_seconds") != 180
        or not polls
    ):
        raise RuntimeError("Expected three-rule monitor is not recorded")

    latest = polls[-1]
    age = (
        datetime.now(timezone.utc)
        - datetime.fromisoformat(latest["timestamp"])
    ).total_seconds()

    if (
        not 0 <= age <= 15
        or latest.get("status") != "ok"
        or latest.get("query_status") != "ok"
        or latest.get("delivery_status") != "ok"
    ):
        raise RuntimeError("Monitor is not recently healthy")


def recent_event_count(opener):
    parameters = urlencode({
        "query": (
            '{job="p10-security",source="gateway",provenance="live-lab"}'
        ),
        "start": str(time.time_ns() - 180_000_000_000),
        "end": str(time.time_ns()),
        "direction": "forward",
        "limit": "500",
    })
    payload = get_json(
        opener,
        "http://127.0.0.1:3100/loki/api/v1/query_range?" + parameters,
    )
    if payload.get("status") != "success":
        raise RuntimeError("Quiet-window query failed")

    return sum(
        len(stream["values"])
        for stream in payload["data"]["result"]
    )


def delivery_state_clear():
    path = (
        Path.home()
        / ".local/share/project10/monitoring/outbox.sqlite3"
    )
    if not path.is_file():
        raise RuntimeError("Existing outbox database required")

    with closing(sqlite3.connect(
        path.as_uri() + "?mode=ro",
        uri=True,
    )) as connection:
        rows = connection.execute(
            "SELECT delivered_at FROM finding_outbox"
        ).fetchall()

    current = datetime.now(timezone.utc)
    for (delivered_at,) in rows:
        if delivered_at is None:
            return False

        age = (
            current - datetime.fromisoformat(delivered_at)
        ).total_seconds()
        if age < 65:
            return False

    return True


def wait_for_isolation(opener):
    started = time.monotonic()
    last_notice = -30

    while True:
        verify_monitor()
        if recent_event_count(opener) == 0 and delivery_state_clear():
            return

        elapsed = time.monotonic() - started
        if elapsed >= 240:
            raise RuntimeError("Isolation or delivery state did not clear")

        if elapsed - last_notice >= 30:
            print(
                "Waiting for a clear observation window and delivery state...",
                flush=True,
            )
            last_notice = elapsed

        time.sleep(5)


def wait_quietly(seconds):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        remaining = max(0, int(deadline - time.monotonic()))
        print(f"Inter-scenario quiet interval: {remaining}s remaining",
              flush=True)
        time.sleep(min(30, max(0, deadline - time.monotonic())))


def main():
    if REPORT_PATH.exists():
        raise RuntimeError(
            "Existing held-out run preserved; do not overwrite or rerun blindly"
        )

    manifest_path = Path("config/evaluation/query-volume-holdout.json")
    raw = manifest_path.read_bytes()

    if hashlib.sha256(raw).hexdigest() != EXPECTED_MANIFEST_HASH:
        raise RuntimeError("Frozen manifest hash mismatch")

    manifest = json.loads(raw)

    if (
        asdict(QUERY_VOLUME_RULE) != manifest["baseline_rule"]
        or asdict(SUSTAINED_QUERY_RULE) != manifest["candidate_rule"]
        or manifest["maximum_total_requests"] != 124
        or sum(
            scenario["request_count"]
            for scenario in manifest["scenarios"]
        ) != 124
    ):
        raise RuntimeError("Frozen protocol and implementation differ")

    queries = [
        query
        for scenario in manifest["scenarios"]
        for query in scenario["queries"]
    ]
    if len(queries) != 124 or len(set(queries)) != 124:
        raise RuntimeError("Unexpected held-out query set")

    credentials = json.loads(
        (
            Path.home()
            / ".config/project10/credentials/inference-clients.json"
        ).read_text(encoding="utf-8")
    )
    oracle = InferenceOracle(credentials["reader_key"])
    opener = build_opener(ProxyHandler({}), NoRedirects())

    report = {
        "status": "in_progress",
        "manifest_sha256": EXPECTED_MANIFEST_HASH,
        "started_at": now(),
        "expected_model_version": manifest["expected_target_model_version"],
        "maximum_total_requests": 124,
        "inference_requests_attempted": 0,
        "post_traffic_observation_seconds": POST_TRAFFIC_OBSERVATION_SECONDS,
        "scenarios": [],
        "detection_outcome": "not-yet-assessed",
    }
    stage = "preflight"
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)

    # Reserve the output name before generating any traffic.
    with REPORT_PATH.open("x", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)

    try:
        verify_services(opener, manifest["expected_target_model_version"])
        verify_monitor()
        wait_for_isolation(opener)

        for index, scenario in enumerate(manifest["scenarios"]):
            stage = scenario["scenario_id"]

            if index:
                wait_quietly(
                    manifest["minimum_inter_scenario_quiet_seconds"]
                )
                wait_for_isolation(opener)

            verify_services(
                opener,
                manifest["expected_target_model_version"],
            )
            verify_monitor()

            result = {
                "scenario_id": scenario["scenario_id"],
                "name": scenario["name"],
                "ground_truth": scenario["ground_truth"],
                "status": "in_progress",
                "started_at": now(),
                "observations": [],
            }
            report["scenarios"].append(result)
            save_report(report)

            print(
                f"Starting {stage}: {scenario['request_count']} predictions",
                flush=True,
            )

            for number, text in enumerate(scenario["queries"], start=1):
                if report["inference_requests_attempted"] >= 124:
                    raise RuntimeError("Global inference budget reached")

                report["inference_requests_attempted"] += 1
                save_report(report)

                observation = oracle.query(text)
                if observation["model_version"] != (
                    manifest["expected_target_model_version"]
                ):
                    raise RuntimeError("Target model changed during execution")

                result["observations"].append(observation)
                save_report(report)

                if number % 6 == 0 or number == scenario["request_count"]:
                    print(
                        f"{stage}: {number}/{scenario['request_count']} completed",
                        flush=True,
                    )

                if number < scenario["request_count"]:
                    time.sleep(scenario["spacing_after_response_seconds"])

            result["traffic_completed_at"] = now()

            training_count = scenario["replica_training_queries"]
            if training_count:
                training = result["observations"][:training_count]
                heldout = result["observations"][training_count:]

                if len(heldout) != scenario["replica_evaluation_queries"]:
                    raise RuntimeError("Unexpected replica evaluation split")

                result["replica_evaluation"] = evaluate_replica(
                    [item["text"] for item in training],
                    [item["label"] for item in training],
                    [item["text"] for item in heldout],
                    [item["label"] for item in heldout],
                )

            time.sleep(POST_TRAFFIC_OBSERVATION_SECONDS)
            verify_monitor()

            result["status"] = "traffic_completed"
            result["observation_completed_at"] = now()
            save_report(report)
            print(
                f"{stage}: traffic complete; detection assessment pending",
                flush=True,
            )

        identifiers = [
            item["request_id"]
            for scenario in report["scenarios"]
            for item in scenario["observations"]
        ]
        if len(identifiers) != 124 or len(set(identifiers)) != 124:
            raise RuntimeError("Unexpected request correlation coverage")

        report["status"] = "traffic_completed"
        report["completed_at"] = now()
        save_report(report)

        print("Held-out traffic execution completed: 4 scenarios, 124 requests.")
        print("Detection effectiveness has not yet been assessed.")

    except (Exception, KeyboardInterrupt) as error:
        report["status"] = "incomplete"
        report["stopped_at"] = now()
        report["failure_stage"] = stage
        report["failure_type"] = type(error).__name__
        save_report(report)
        print(
            f"Run incomplete at {stage}; partial evidence preserved. "
            "Do not rerun or change the frozen protocol.",
            flush=True,
        )
        raise SystemExit(1) from None

if __name__ == "__main__":
    main()