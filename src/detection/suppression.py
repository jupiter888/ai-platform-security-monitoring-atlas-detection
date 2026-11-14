"""
Bounded, process-local finding suppression.

State is recorded only after the output sink confirms acceptance.
Restarting the process clears suppression state.
"""

from datetime import timedelta

from src.detection.model_access import utc_timestamp


class FindingSuppression:
    def __init__(self, capacity=128, cooldown_seconds=60):
        if type(capacity) is not int or capacity < 1:
            raise ValueError("Invalid suppression capacity")
        if type(cooldown_seconds) is not int or cooldown_seconds < 1:
            raise ValueError("Invalid suppression cooldown")

        self.capacity = capacity
        self.cooldown_seconds = cooldown_seconds
        self.entries = {}

    def publish(self, findings, *, as_of, sink):
        utc_timestamp(as_of.isoformat())

        self.entries = {
            key: expires
            for key, expires in self.entries.items()
            if expires > as_of
        }

        emitted = 0
        suppressed = 0

        for finding in findings:
            key = (
                finding["rule_id"],
                finding["rule_version"],
                finding["caller_ref"],
                finding["model"],
            )

            if key in self.entries:
                suppressed += 1
                continue

            if len(self.entries) >= self.capacity:
                raise RuntimeError("Suppression state capacity reached")

            if sink(finding) is not True:
                raise RuntimeError("Finding output was not accepted")

            self.entries[key] = as_of + timedelta(
                seconds=self.cooldown_seconds
            )
            emitted += 1

        return emitted, suppressed