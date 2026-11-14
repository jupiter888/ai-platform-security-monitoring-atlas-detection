"""
Server-side credential-to-operator binding.

Caller-supplied role or subject claims are not used.
"""

import hmac
import re

from src.detection.cases import Actor


class OperatorAuthenticator:
    def __init__(self, configuration, forbidden_keys=()):
        if (
            not isinstance(configuration, dict)
            or not 3 <= len(configuration) <= 16
        ):
            raise ValueError("Invalid operator configuration")

        entries = []
        keys = set()
        roles = set()

        for subject, definition in configuration.items():
            if (
                not isinstance(definition, dict)
                or set(definition) != {"role", "key"}
            ):
                raise ValueError("Invalid operator definition")

            actor = Actor(subject, definition["role"])
            key = definition["key"]

            if (
                not isinstance(key, str)
                or re.fullmatch(r"[0-9a-f]{64}", key) is None
                or key in keys
                or key in forbidden_keys
            ):
                raise ValueError("Invalid operator credential")

            keys.add(key)
            roles.add(actor.role)
            entries.append((key, actor))

        if roles != {"analyst", "approver", "responder"}:
            raise ValueError("Required operator roles missing")

        self.entries = tuple(entries)

    def authenticate(self, authorization):
        if not isinstance(authorization, str):
            return None

        scheme, separator, token = authorization.partition(" ")
        if (
            not separator
            or scheme.lower() != "bearer"
            or re.fullmatch(r"[0-9a-f]{64}", token) is None
        ):
            return None

        matched = None
        for key, actor in self.entries:
            if hmac.compare_digest(token, key):
                matched = actor

        return matched