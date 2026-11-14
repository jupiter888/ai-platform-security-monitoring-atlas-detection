"""Producer credentials bound to source and provenance permissions."""

import hmac
import re
from types import MappingProxyType

from src.telemetry.events import SecurityEvent
from src.telemetry.operator_events import OperatorEvent


PROFILES = MappingProxyType({
    "gateway": (
        frozenset({"gateway"}),
        frozenset({"live-lab"}),
    ),
    "operator": (
        frozenset({"operator"}),
        frozenset({"live-lab"}),
    ),
    "fixture": (
        frozenset({"gateway", "operator", "backend", "collector"}),
        frozenset({"synthetic", "replay"}),
    ),
})


class ProducerAuthenticator:
    def __init__(self, configuration):
        if (
            not isinstance(configuration, dict)
            or set(configuration) != set(PROFILES)
        ):
            raise ValueError("Invalid producer credential configuration")

        values = list(configuration.values())
        if any(
            not isinstance(value, str)
            or re.fullmatch(r"[0-9a-f]{64}", value) is None
            for value in values
        ):
            raise ValueError("Invalid producer credential configuration")

        if len(set(values)) != len(values):
            raise ValueError("Producer credentials must be distinct")

        self._entries = tuple(configuration.items())

    def authenticate(self, authorization_values):
        if (
            not isinstance(authorization_values, (list, tuple))
            or len(authorization_values) != 1
            or not isinstance(authorization_values[0], str)
        ):
            return None

        scheme, separator, token = authorization_values[0].partition(" ")
        if (
            not separator
            or scheme.lower() != "bearer"
            or re.fullmatch(r"[0-9a-f]{64}", token) is None
        ):
            return None

        producer = None
        for name, expected in self._entries:
            if hmac.compare_digest(token, expected):
                producer = name
        return producer

    def permits(self, producer, event):
        if (
            not isinstance(producer, str)
            or not isinstance(event, (SecurityEvent, OperatorEvent))
        ):
            return False

        profile = PROFILES.get(producer)
        if profile is None:
            return False

        sources, provenance = profile
        return (
            event.source in sources
            and event.provenance in provenance
        )