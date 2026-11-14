"""Producer identity and source/provenance authorization tests."""

import unittest
from uuid import uuid4

from src.telemetry.events import create_event
from src.telemetry.operator_events import create_operator_event
from src.telemetry.producer_auth import ProducerAuthenticator


CONFIG = {
    "gateway": "a" * 64,
    "operator": "b" * 64,
    "fixture": "c" * 64,
}


class ProducerAuthTests(unittest.TestCase):
    def setUp(self):
        self.auth = ProducerAuthenticator(CONFIG)

    def gateway_event(self, provenance="live-lab", source="gateway"):
        return create_event(
            provenance=provenance,
            source=source,
            model="research-model",
            reason="authentication_failed",
        )

    def operator_event(self, provenance="live-lab"):
        return create_operator_event(
            operation="case_read",
            reason="authentication_failed",
            request_id=str(uuid4()),
            provenance=provenance,
        )

    def test_valid_credentials_resolve_distinct_producers(self):
        for producer, key in CONFIG.items():
            with self.subTest(producer=producer):
                self.assertEqual(
                    self.auth.authenticate([f"Bearer {key}"]),
                    producer,
                )

    def test_missing_malformed_and_duplicate_headers_are_rejected(self):
        for values in (
            [],
            None,
            ["Bearer short"],
            ["Bearer " + "é" * 64],
            ["Basic " + "a" * 64],
            ["Bearer " + "a" * 64, "Bearer " + "a" * 64],
            [123],
        ):
            with self.subTest(values=values):
                self.assertIsNone(self.auth.authenticate(values))

    def test_unknown_credential_is_rejected(self):
        self.assertIsNone(
            self.auth.authenticate(["Bearer " + "d" * 64])
        )

    def test_live_sources_are_bound_to_their_producer(self):
        gateway = self.gateway_event()
        operator = self.operator_event()
        self.assertTrue(self.auth.permits("gateway", gateway))
        self.assertTrue(self.auth.permits("operator", operator))
        self.assertFalse(self.auth.permits("gateway", operator))
        self.assertFalse(self.auth.permits("operator", gateway))

    def test_fixture_credential_cannot_claim_live_activity(self):
        self.assertFalse(
            self.auth.permits("fixture", self.gateway_event())
        )
        self.assertFalse(
            self.auth.permits("fixture", self.operator_event())
        )

    def test_fixture_provenance_cannot_be_claimed_by_live_producers(self):
        for provenance in ("synthetic", "replay"):
            with self.subTest(provenance=provenance):
                gateway = self.gateway_event(provenance)
                operator = self.operator_event(provenance)
                self.assertTrue(self.auth.permits("fixture", gateway))
                self.assertTrue(self.auth.permits("fixture", operator))
                self.assertFalse(self.auth.permits("gateway", gateway))
                self.assertFalse(self.auth.permits("operator", operator))

    def test_invalid_configuration_fails_without_key_reflection(self):
        configurations = (
            {},
            {**CONFIG, "extra": "d" * 64},
            {**CONFIG, "operator": CONFIG["gateway"]},
            {**CONFIG, "fixture": "credential-secret-canary"},
        )
        for configuration in configurations:
            with self.subTest(configuration_fields=list(configuration)):
                with self.assertRaises(ValueError) as caught:
                    ProducerAuthenticator(configuration)
                self.assertNotIn(
                    "credential-secret-canary", str(caught.exception)
                )

    def test_unknown_producer_or_unvalidated_object_is_denied(self):
        self.assertFalse(
            self.auth.permits("unknown", self.gateway_event())
        )
        self.assertFalse(self.auth.permits(None, self.gateway_event()))
        self.assertFalse(self.auth.permits("gateway", {}))

if __name__ == "__main__":
    unittest.main()