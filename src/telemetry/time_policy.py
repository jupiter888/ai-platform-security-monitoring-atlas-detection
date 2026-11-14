"""Live-ingestion timestamp limits; historical parsing remains independent."""

from datetime import datetime, timedelta

from src.telemetry.ingestion import InvalidTelemetry


MAX_LIVE_AGE_SECONDS = 300
MAX_FUTURE_SKEW_SECONDS = 30


def validate_live_timestamp(collected):
    if collected.event.provenance != "live-lab":
        return

    try:
        source_time = datetime.fromisoformat(collected.event.event_time)
        collection_time = datetime.fromisoformat(collected.collected_at)
        for timestamp in (source_time, collection_time):
            if (
                timestamp.tzinfo is None
                or timestamp.utcoffset() != timedelta(0)
            ):
                raise ValueError

        age = (collection_time - source_time).total_seconds()
        if (
            age > MAX_LIVE_AGE_SECONDS
            or age < -MAX_FUTURE_SKEW_SECONDS
        ):
            raise ValueError

    except (ValueError, TypeError, OverflowError):
        raise InvalidTelemetry("Invalid live telemetry timestamp") from None