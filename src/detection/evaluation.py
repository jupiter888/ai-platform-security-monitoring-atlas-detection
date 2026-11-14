"""
Monitoring evaluation helpers.

Window counting uses the same exclusive lower boundary as detection.
Coverage checks assess recorded polls, not unobservable process behavior.
"""

from datetime import timedelta

from src.detection.model_access import utc_timestamp


def peak_window_count(timestamps, window_seconds=60):
    if type(window_seconds) is not int or window_seconds < 1:
        raise ValueError("Invalid evaluation window")

    for timestamp in timestamps:
        utc_timestamp(timestamp.isoformat())

    ordered = sorted(timestamps)
    left = 0
    peak = 0

    for right, timestamp in enumerate(ordered):
        while (
            timestamp - ordered[left]
        ).total_seconds() >= window_seconds:
            left += 1

        peak = max(peak, right - left + 1)

    return peak


def assess_monitor_coverage(
    polls,
    *,
    started_at,
    completed_at,
    maximum_gap_seconds=10,
):
    utc_timestamp(started_at.isoformat())
    utc_timestamp(completed_at.isoformat())

    if completed_at < started_at or maximum_gap_seconds <= 0:
        raise ValueError("Invalid coverage interval")

    ordered = sorted(
        (
            (utc_timestamp(poll["timestamp"]), poll)
            for poll in polls
        ),
        key=lambda item: item[0],
    )

    before = [item for item in ordered if item[0] <= started_at]
    after = [item for item in ordered if item[0] >= completed_at]

    if not before or not after:
        return {
            "coverage_complete": False,
            "reason": "missing_bracketing_polls",
        }

    lower = before[-1][0]
    upper = after[0][0]
    selected = [
        item for item in ordered
        if lower <= item[0] <= upper
    ]

    gaps = [
        (current[0] - previous[0]).total_seconds()
        for previous, current in zip(selected, selected[1:])
    ]
    largest_gap = max(gaps, default=0)

    healthy = all(
        poll.get("status") == "ok"
        and poll.get("query_status") == "ok"
        and poll.get("delivery_status") == "ok"
        for _, poll in selected
    )

    suppression_observed = any(
        poll.get("findings_suppressed", 0) > 0
        for _, poll in selected
    )

    return {
        "coverage_complete": (
            healthy and largest_gap <= maximum_gap_seconds
        ),
        "reason": (
            "healthy_recorded_coverage"
            if healthy and largest_gap <= maximum_gap_seconds
            else "poll_errors_or_excessive_gap"
        ),
        "poll_count": len(selected),
        "largest_poll_gap_seconds": largest_gap,
        "maximum_allowed_gap_seconds": maximum_gap_seconds,
        "suppression_observed": suppression_observed,
    }