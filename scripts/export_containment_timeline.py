"""Export a deterministic SVG from verified containment-retest evidence."""

import hashlib
import json
from datetime import datetime, timedelta
from pathlib import Path
from xml.etree import ElementTree as ET


PROTOCOL_HASH = (
    "067d0a0f225647b6b599c90dfefcde132d18470153d4f31744d17dc89fd13a83"
)
NS = "http://www.w3.org/2000/svg"
ET.register_namespace("", NS)

WHITE = "#f2f4f8"
MUTED = "#9ba7b5"
GRID = "#28313d"
GREEN = "#70efc0"
AMBER = "#ffbd69"
PURPLE = "#b9a4ff"


def main():
    protocol_raw = Path(
        "config/evaluation/containment-retest.json"
    ).read_bytes()
    if hashlib.sha256(protocol_raw).hexdigest() != PROTOCOL_HASH:
        raise RuntimeError("Frozen protocol integrity check failed")

    protocol = json.loads(protocol_raw)
    assessment_path = Path(
        "evidence/public/containment-retest-assessment.json"
    )
    assessment = json.loads(assessment_path.read_text())
    execution = json.loads(
        Path("evidence/public/containment-retest-execution.json").read_text()
    )
    if (
        assessment.get("status") != "passed"
        or assessment.get("protocol_sha256") != PROTOCOL_HASH
        or execution.get("status")
            != "traffic_completed_pending_correlation"
        or execution["case_id"] != assessment["case_id"]
    ):
        raise RuntimeError("Expected verified, matching retest evidence")

    inference = assessment["inference_events"]
    operators = assessment["operator_events"]
    if (
        len(inference) != 21
        or len(operators) != 5
        or len({
            item["event_id"] for item in inference + operators
        }) != 26
    ):
        raise RuntimeError("Unexpected evidence counts")

    def timestamp(value):
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
            raise RuntimeError("Expected UTC evidence timestamps")
        return parsed

    def clock(value):
        return timestamp(value).strftime("%H:%M:%S.%f")[:-3] + " UTC"

    phases = {}
    for name in ("before", "during", "after"):
        reader = sorted(
            [
                item for item in inference
                if item["phase"] == name
                and item["caller_ref"] == protocol["caller_ref"]
            ],
            key=lambda item: item["query_index"],
        )
        admin = [
            item for item in inference
            if item["phase"] == name
            and item["caller_ref"]
                == protocol["admin_control"]["caller_ref"]
        ]
        reason = (
            "containment_enforced"
            if name == "during" else "inference_succeeded"
        )
        if (
            len(reader) != 6
            or [item["query_index"] for item in reader] != list(range(6))
            or any(item["reason"] != reason for item in reader)
            or len(admin) != 1
            or admin[0]["reason"] != "inference_succeeded"
        ):
            raise RuntimeError("Phase evidence differs from protocol")
        phases[name] = (reader, admin)

    expected_operations = [
        "case_open",
        "containment_request",
        "containment_approve",
        "containment_execute",
        "case_read",
    ]
    if (
        [item["operation"] for item in operators] != expected_operations
        or any(
            item["reason"] != "operation_succeeded"
            or item["case_ref"] != assessment["case_id"]
            for item in operators
        )
    ):
        raise RuntimeError("Operator evidence differs from expected workflow")

    receipt = execution["execution_receipt"]
    active_start = timestamp(receipt["started_at"])
    active_end = timestamp(receipt["expires_at"])
    if (active_end - active_start).total_seconds() != 60:
        raise RuntimeError("Expected a 60-second execution")

    event_times = [timestamp(item["event_time"]) for item in inference]
    origin = min(event_times)
    finish = max(event_times)
    span = (finish - origin).total_seconds()
    if span <= 0:
        raise RuntimeError("Invalid timeline span")

    svg = ET.Element(
        f"{{{NS}}}svg",
        {
            "width": "1440",
            "height": "1040",
            "viewBox": "0 0 1440 1040",
            "role": "img",
            "aria-labelledby": "title description",
        },
    )

    def element(tag, **attributes):
        return ET.SubElement(
            svg, f"{{{NS}}}{tag}",
            {key.replace("_", "-"): str(value)
             for key, value in attributes.items()},
        )

    ET.SubElement(svg, f"{{{NS}}}title", {"id": "title"}).text = (
        "Project 10 — Evidence-linked containment and recovery"
    )
    ET.SubElement(
        svg, f"{{{NS}}}desc", {"id": "description"}
    ).text = (
        "Verified local response retest. Six Reader queries succeeded before "
        "containment, six were denied during the 60-second block, and six "
        "succeeded after expiry. Admin controls succeeded in every phase. "
        "All 26 inference and operator request IDs correlated to Loki."
    )

    def text(x, y, value, size=16, color=WHITE, anchor="start"):
        node = element(
            "text", x=x, y=y, fill=color,
            font_family="ui-monospace, Menlo, Consolas, monospace",
            font_size=size, text_anchor=anchor,
        )
        node.text = str(value)
        return node

    def line(x1, y1, x2, y2, color=GRID, **extra):
        return element(
            "line", x1=x1, y1=y1, x2=x2, y2=y2,
            stroke=color, stroke_width=1, **extra,
        )

    def circle(x, y, color, radius=7):
        return element("circle", cx=x, cy=y, r=radius, fill=color)

    element("rect", width=1440, height=1040, fill="#090d13")
    text(50, 54, "PROJECT 10 / AI SECURITY OPERATIONS", 17, MUTED)
    text(50, 108, "CONTROLLED CONTAINMENT → VERIFIED RECOVERY", 30)
    text(
        50, 145,
        "Actual local API activity · frozen protocol · synthetic lab identities",
        16, MUTED,
    )
    text(50, 178, "CASE " + assessment["case_id"], 14, MUTED)
    text(1390, 54, "26 / 26 REQUESTS CORRELATED", 17, GREEN, "end")

    # Actual source-event time on a linear axis.
    left, right = 300, 1360

    def x_at(value):
        return left + (
            (value - origin).total_seconds() / span
        ) * (right - left)

    x_start = x_at(active_start)
    x_end = x_at(active_end)
    element(
        "rect", x=x_start, y=242,
        width=x_end - x_start, height=218,
        fill=AMBER, fill_opacity=0.08,
    )
    line(x_start, 236, x_start, 460, AMBER, stroke_dasharray="4 5")
    line(x_end, 236, x_end, 460, AMBER, stroke_dasharray="4 5")
    text(x_start, 224, "ACTIVATE", 13, AMBER)
    text(x_end, 224, "EXPIRE / 60 s", 13, AMBER, "end")

    for index in range(5):
        elapsed = span * index / 4
        x = left + (right - left) * index / 4
        line(x, 247, x, 460, GRID)
        text(x, 486, f"+{elapsed:.1f}s", 13, MUTED, "middle")

    labels = {
        "before": ("BEFORE", GREEN, "6 ALLOWED"),
        "during": ("DURING", AMBER, "6 DENIED"),
        "after": ("AFTER", GREEN, "6 ALLOWED"),
    }
    for index, name in enumerate(("before", "during", "after")):
        y = 280 + index * 70
        label, color, summary = labels[name]
        reader, admin = phases[name]
        times = [timestamp(item["event_time"]) for item in reader]
        mean = sum((value - origin).total_seconds() for value in times) / 6
        x = left + mean / span * (right - left)
        line(left, y, right, y)
        text(50, y + 5, label, 17, color)
        circle(x, y, color, 8)
        anchor = "end" if x > (left + right) / 2 else "start"
        offset = -15 if anchor == "end" else 15
        text(x + offset, y - 12, summary, 14, color, anchor)
        admin_x = x_at(timestamp(admin[0]["event_time"]))
        circle(admin_x, y + 20, PURPLE, 5)

    text(
        50, 520,
        "Linear elapsed time. Reader markers summarize each phase at its mean "
        "source-event time; purple markers are Admin controls.",
        13, MUTED,
    )

    text(50, 566, "REPEATED QUERY OUTCOMES", 18)
    text(
        50, 591,
        "The same six-query sequence in each phase. Columns below are categorical.",
        13, MUTED,
    )

    for index, name in enumerate(("before", "during", "after")):
        x = 50 + index * 455
        label, color, _ = labels[name]
        element(
            "rect", x=x, y=610, width=430, height=130,
            fill="#111822", stroke=GRID,
        )
        text(x + 18, 638, label, 17, color)
        text(x + 18, 673, "READER", 13, MUTED)
        for query_index in range(6):
            cx = x + 135 + query_index * 44
            circle(cx, 668, color, 9)
            text(cx, 691, str(query_index + 1), 11, MUTED, "middle")
        text(x + 18, 722, "ADMIN", 13, MUTED)
        circle(x + 135, 717, PURPLE, 7)
        text(x + 155, 722, "ALLOWED", 13, PURPLE)

    text(50, 790, "AUDITED OPERATOR WORKFLOW", 18)
    text(
        50, 814,
        "Ordered workflow cards; spacing is categorical. Timestamps are actual UTC source times.",
        13, MUTED,
    )
    names = {
        "case_open": "OPEN CASE",
        "containment_request": "REQUEST",
        "containment_approve": "APPROVE",
        "containment_execute": "EXECUTE",
        "case_read": "VERIFY CASE",
    }
    for index, event in enumerate(operators):
        x = 50 + index * 273
        element(
            "rect", x=x, y=833, width=250, height=100,
            fill="#111822", stroke=GRID,
        )
        text(x + 14, 860, names[event["operation"]], 16)
        text(x + 14, 887, event["actor_role"].upper(), 13, PURPLE)
        text(x + 14, 913, clock(event["event_time"]), 12, MUTED)

    text(
        50, 971,
        "Evidence: containment-retest-assessment.json · 21 inference decisions + 5 operator events",
        13, MUTED,
    )
    text(50, 997, "Protocol SHA256: " + PROTOCOL_HASH, 12, MUTED)
    text(
        1390, 1022,
        "Local query-access validation; no production or extraction-efficacy claim.",
        12, MUTED, "end",
    )

    destination = Path(
        "evidence/public/visualizations/containment-timeline.svg"
    )
    destination.parent.mkdir(parents=True, exist_ok=True)
    encoded = ET.tostring(svg, encoding="utf-8", xml_declaration=True)
    ET.fromstring(encoded)

    if destination.exists():
        if destination.read_bytes() != encoded:
            raise RuntimeError("Existing export differs; preserve it for review")
    else:
        with destination.open("xb") as handle:
            handle.write(encoded)

    viewer = destination.parent / "containment-timeline.html"
    html = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Project 10 — Containment and Recovery</title>
<style>
* { box-sizing: border-box; }
html { color-scheme: dark; background: #090d13; }
body {
  margin: 0;
  padding: 16px;
  color: #9ba7b5;
  font: 14px/1.6 ui-monospace, Menlo, Consolas, monospace;
}
main { width: 100%; max-width: 1440px; margin: 0 auto; }
img { display: block; width: 100%; height: auto; }
p { padding: 0 12px; }
a { color: #70efc0; }
</style>
</head>
<body>
<main>
<img src="containment-timeline.svg" width="1440" height="1040"
     alt="Evidence-linked containment timeline with repeated query outcomes
          and the authorized operator workflow">
<p>
Standalone evidence visualization.
<a href="../containment-retest-assessment.json">View the assessment</a>
·
<a href="containment-timeline.svg">Open the original SVG</a>
</p>
</main>
</body>
</html>
"""
    if viewer.exists() and viewer.read_text(encoding="utf-8") != html:
        raise RuntimeError("Existing viewer differs; preserve it for review")
    viewer.write_text(html, encoding="utf-8")
    print("Responsive viewer:", viewer)

    print("PASS: frozen protocol and assessment verified")
    print("PASS: 21 inference decisions and five operator events represented")
    print("PASS: standalone SVG generated without external assets")
    print("Export:", destination)
    print("SVG SHA256:", hashlib.sha256(encoded).hexdigest())

if __name__ == "__main__":
    main()