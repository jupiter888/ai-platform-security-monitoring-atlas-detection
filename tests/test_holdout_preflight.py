"""
Held-out runner service-health contract tests.
"""

import unittest
from unittest.mock import MagicMock, patch

from scripts.run_query_volume_holdout import verify_services


VERSION = "0123456789abcdef"


class HoldoutPreflightTests(unittest.TestCase):
    def setUp(self):
        self.opener = MagicMock()
        self.opener.open.return_value.__enter__.return_value.status = 200
        self.responses = {
            "http://127.0.0.1:8100/health": {"detail": "ok"},
            "http://127.0.0.1:8300/health": {"status": "ok"},
            "http://127.0.0.1:8200/health": {
                "status": "ok",
                "model_version": VERSION,
            },
        }

    def verify(self):
        with patch(
            "scripts.run_query_volume_holdout.get_json",
            side_effect=lambda _opener, url: self.responses[url],
        ):
            verify_services(self.opener, VERSION)

    def test_actual_service_health_contracts_are_accepted(self):
        self.verify()

    def test_unhealthy_collector_is_rejected(self):
        self.responses["http://127.0.0.1:8100/health"] = {
            "detail": "unavailable"
        }
        with self.assertRaises(RuntimeError):
            self.verify()

    def test_unhealthy_receiver_is_rejected(self):
        self.responses["http://127.0.0.1:8300/health"] = {
            "status": "unavailable"
        }
        with self.assertRaises(RuntimeError):
            self.verify()

    def test_changed_target_model_is_rejected(self):
        self.responses["http://127.0.0.1:8200/health"][
            "model_version"
        ] = "fedcba9876543210"

        with self.assertRaises(RuntimeError):
            self.verify()

if __name__ == "__main__":
    unittest.main()