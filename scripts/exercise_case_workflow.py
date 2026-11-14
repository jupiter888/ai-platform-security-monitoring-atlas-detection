"""
Project 10 — Live case disposition and scoped approval exercise.

Prepare and approve are separate operator stages.
Credentials remain outside evidence and terminal output.
Neither stage executes containment.
"""

import argparse
import hashlib
import json
from pathlib import Path

from scripts.validate_inference_monitoring import request_json
from src.detection.cases import (
    CONTAINMENT_ACTION,
    CONTAINMENT_POLICY_VERSION,
    CONTAINMENT_SECONDS,
)
from src.telemetry.loki import NoRedirects
from urllib.request import ProxyHandler, Request, build_opener


REPORT = Path("evidence/public/operator-workflow-exercise.json")


def save(report):
    temporary = REPORT.with_suffix(".json.tmp")
    temporary.write_text(
        json.dumps(report, indent=2) + "\n",
        encoding="utf-8",
    )
    temporary.replace(REPORT)


def operator(configuration, role):
    matches = [
        (subject, definition)
        for subject, definition in configuration.items()
        if definition["role"] == role
    ]
    if len(matches) != 1:
        raise RuntimeError("Expected one configured principal per role")
    return matches[0]


def scope(case):
    return {
        field: case[field]
        for field in (
            "caller_ref",
            "model",
            "containment_action",
            "containment_seconds",
            "containment_policy_version",
        )
    }


def verify_scope(case):
    if scope(case) != {
        "caller_ref": "lab-caller-reader",
        "model": "research-model",
        "containment_action": CONTAINMENT_ACTION,
        "containment_seconds": CONTAINMENT_SECONDS,
        "containment_policy_version": CONTAINMENT_POLICY_VERSION,
    }:
        raise RuntimeError("Unexpected containment scope")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("stage", choices=("prepare", "approve"))
    args = parser.parse_args()

    configuration = json.loads(
        (
            Path.home()
            / ".config/project10/credentials/operators.json"
        ).read_text(encoding="utf-8")
    )
    opener = build_opener(ProxyHandler({}), NoRedirects())

    if args.stage == "prepare":
        if REPORT.exists():
            raise RuntimeError("Existing workflow evidence preserved")

        raw = Path(
            "evidence/public/query-volume-holdout-assessment.json"
        ).read_bytes()
        assessment = json.loads(raw)

        selected = {}
        for scenario_id, name in (("H02", "benign"), ("H04", "containment")):
            scenario = next(
                item for item in assessment["scenarios"]
                if item["scenario_id"] == scenario_id
            )
            rule = scenario["rules"]["DET-003"]
            if (
                scenario["assessment_status"] != "assessed"
                or not rule["finding_delivered"]
            ):
                raise RuntimeError("Validated finding evidence required")
            selected[name] = rule["finding_ids"][0]

        if selected["benign"] == selected["containment"]:
            raise RuntimeError("Distinct scenario findings required")

        report = {
            "status": "preparation_in_progress",
            "source_assessment_sha256": hashlib.sha256(raw).hexdigest(),
            "selected_findings": selected,
            "checks": [],
            "cases": {},
            "response_executed": False,
            "principal_scope": (
                "Distinct simulated principals operated by one lab operator"
            ),
        }
        REPORT.parent.mkdir(parents=True, exist_ok=True)
        with REPORT.open("x", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2)

    else:
        report = json.loads(REPORT.read_text(encoding="utf-8"))
        if report["status"] != "prepared_approval_pending":
            raise RuntimeError("Workflow is not awaiting approval")

    def call(label, method, path, role, expected, payload=None):
        report["current_operation"] = label
        save(report)

        headers = {}
        if role is not None:
            _, definition = operator(configuration, role)
            headers["Authorization"] = f'Bearer {definition["key"]}'

        data = None
        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"

        status, _, body = request_json(
            opener,
            Request(
                "http://127.0.0.1:8400" + path,
                data=data,
                headers=headers,
                method=method,
            ),
        )
        if status != expected:
            raise RuntimeError("Unexpected workflow HTTP result")

        report["checks"].append({
            "stage": args.stage,
            "check": label,
            "role": role,
            "http_status": status,
        })
        save(report)
        print(f"PASS: {label} — HTTP {status}")
        return body

    try:
        if args.stage == "prepare":
            benign_id = report["selected_findings"]["benign"]
            containment_id = report["selected_findings"]["containment"]

            call(
                "Unauthenticated case creation denied",
                "POST", "/cases", None, 401,
                {"finding_id": benign_id},
            )
            call(
                "Approver cannot create analyst case",
                "POST", "/cases", "approver", 403,
                {"finding_id": benign_id},
            )

            benign = call(
                "Analyst opens benign-activity case",
                "POST", "/cases", "analyst", 201,
                {"finding_id": benign_id},
            )
            report["cases"]["benign"] = benign
            save(report)

            benign_path = f'/cases/{benign["case_id"]}'
            benign = call(
                "Analyst records approved benign activity",
                "POST", benign_path + "/close-benign", "analyst", 200,
                {"disposition": "approved_activity"},
            )
            if benign["state"] != "closed_benign":
                raise RuntimeError("Benign case did not close")
            report["cases"]["benign"] = benign
            save(report)

            call(
                "Closed benign case cannot request containment",
                "POST", benign_path + "/request-containment",
                "analyst", 409,
                {"purpose": "controlled_exercise"},
            )

            case = call(
                "Analyst opens controlled-exercise case",
                "POST", "/cases", "analyst", 201,
                {"finding_id": containment_id},
            )
            verify_scope(case)
            report["cases"]["containment"] = case
            save(report)

            case_path = f'/cases/{case["case_id"]}'
            call(
                "Approval cannot skip the request stage",
                "POST", case_path + "/approve-containment",
                "approver", 409,
                {"purpose": "controlled_exercise"},
            )
            call(
                "Target override rejected",
                "POST", case_path + "/request-containment",
                "analyst", 400,
                {
                    "purpose": "controlled_exercise",
                    "caller_ref": "lab-caller-admin",
                },
            )

            case = call(
                "Analyst requests scoped controlled containment",
                "POST", case_path + "/request-containment",
                "analyst", 200,
                {"purpose": "controlled_exercise"},
            )
            if case["state"] != "containment_requested":
                raise RuntimeError("Containment request state mismatch")
            verify_scope(case)
            report["cases"]["containment"] = case
            save(report)

            call(
                "Analyst cannot approve",
                "POST", case_path + "/approve-containment",
                "analyst", 403,
                {"purpose": "controlled_exercise"},
            )
            call(
                "Responder cannot approve",
                "POST", case_path + "/approve-containment",
                "responder", 403,
                {"purpose": "controlled_exercise"},
            )

            observed = call(
                "Responder can inspect the requested case",
                "GET", case_path, "responder", 200,
            )
            if observed != case:
                raise RuntimeError("Case view changed unexpectedly")

            report["status"] = "prepared_approval_pending"
            save(report)

            print(json.dumps({
                "case_id": case["case_id"],
                "state": case["state"],
                "requester": case["requester"],
                **scope(case),
                "response_executed": False,
            }, indent=2))
            print("Live workflow preparation: 12/12 passed")
            print("Approval pending; no containment executed.")

        else:
            report["status"] = "approval_in_progress"
            save(report)
            expected = report["cases"]["containment"]
            case_path = f'/cases/{expected["case_id"]}'

            current = call(
                "Approver retrieves the requested scope",
                "GET", case_path, "approver", 200,
            )
            verify_scope(current)
            approver_subject, _ = operator(configuration, "approver")

            if (
                current["state"] != "containment_requested"
                or scope(current) != scope(expected)
                or current["finding_id"] != expected["finding_id"]
                or approver_subject in {
                    current["opened_by"], current["requester"]
                }
            ):
                raise RuntimeError("Approval prerequisites not satisfied")

            approved = call(
                "Distinct approver approves the persisted scope",
                "POST", case_path + "/approve-containment",
                "approver", 200,
                {"purpose": "controlled_exercise"},
            )
            if (
                approved["state"] != "containment_approved"
                or approved["approver"] != approver_subject
                or scope(approved) != scope(expected)
            ):
                raise RuntimeError("Approved scope mismatch")

            report["cases"]["containment"] = approved
            report["status"] = "approved_no_execution"
            save(report)
            print("Live workflow approval: 2/2 passed")
            print("Approval recorded; no containment executed.")

    except (Exception, KeyboardInterrupt) as error:
        report["status"] = "incomplete"
        report["failure_type"] = type(error).__name__
        save(report)
        print("Workflow incomplete; evidence preserved. Do not rerun blindly.")
        raise SystemExit(1) from None

if __name__ == "__main__":
    main()