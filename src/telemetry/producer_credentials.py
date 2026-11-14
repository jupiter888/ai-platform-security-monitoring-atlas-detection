"""Load producer credentials without exposing configuration contents."""

import json
import stat
from pathlib import Path

from src.telemetry.producer_auth import PROFILES, ProducerAuthenticator


def unique_configuration(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("Duplicate configuration field")
        result[name] = value
    return result


def load_producer_key(producer):
    if not isinstance(producer, str) or producer not in PROFILES:
        raise RuntimeError("Invalid producer role")

    path = (
        Path.home()
        / ".config/project10/credentials/telemetry-producers.json"
    )
    try:
        information = path.lstat()
        if (
            not stat.S_ISREG(information.st_mode)
            or information.st_mode & 0o077
        ):
            raise ValueError("Unsafe credential file")

        with path.open("rb") as handle:
            raw = handle.read(4097)
        if len(raw) > 4096:
            raise ValueError("Invalid credential file")

        configuration = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=unique_configuration,
        )
        ProducerAuthenticator(configuration)
        return configuration[producer]
    except (OSError, ValueError, TypeError, RecursionError):
        raise RuntimeError(
            "Producer credentials unavailable or invalid"
        ) from None