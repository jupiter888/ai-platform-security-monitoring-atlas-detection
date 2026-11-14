"""
Model-replication experiment boundaries and data separation tests.
"""

import io
import json
import unittest
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError
from uuid import uuid4

from src.emulation.replication import (
    HELDOUT_QUERIES,
    MAX_QUERY_BUDGET,
    ORACLE_ENDPOINT,
    TRAINING_QUERIES,
    InferenceOracle,
    evaluate_replica,
)


class ReplicationTests(unittest.TestCase):
    def setUp(self):
        self.opener = MagicMock()
        self.response = (
            self.opener.open.return_value.__enter__.return_value
        )
        self.response.status = 200
        self.request_id = str(uuid4())
        self.response.headers = {"X-Request-ID": self.request_id}
        self.prediction = {
            "model": "research-model",
            "model_version": "0123456789abcdef",
            "label": "astronomy",
            "score": 0.7,
        }
        self.response.read.return_value = json.dumps(
            self.prediction
        ).encode("utf-8")
        self.oracle = InferenceOracle("a" * 64, opener=self.opener)

    def test_query_budget_is_fixed_and_bounded(self):
        self.assertEqual(MAX_QUERY_BUDGET, 36)
        self.assertEqual(len(TRAINING_QUERIES), 24)
        self.assertEqual(len(HELDOUT_QUERIES), 12)

    def test_training_and_heldout_queries_are_distinct(self):
        combined = TRAINING_QUERIES + HELDOUT_QUERIES
        self.assertEqual(len(combined), len(set(combined)))

    def test_valid_response_preserves_correlation(self):
        result = self.oracle.query("Synthetic research query")
        self.assertEqual(result["request_id"], self.request_id)
        self.assertEqual(result["label"], "astronomy")

    def test_invalid_prediction_values_are_rejected(self):
        for field, value in (
            ("label", "unrecognized-class"),
            ("score", float("inf")),
            ("model_version", "invalid-version"),
        ):
            with self.subTest(field=field):
                payload = dict(self.prediction)
                payload[field] = value
                self.response.read.return_value = json.dumps(
                    payload
                ).encode("utf-8")

                with self.assertRaises(RuntimeError):
                    self.oracle.query("Synthetic query")

    def test_rejected_request_does_not_expose_upstream_body(self):
        self.opener.open.side_effect = HTTPError(
            ORACLE_ENDPOINT,
            401,
            "Synthetic rejection",
            {},
            io.BytesIO(b"synthetic-secret-canary"),
        )
        with self.assertRaises(RuntimeError) as raised:
            self.oracle.query("Synthetic query")

        self.assertNotIn("synthetic-secret-canary", str(raised.exception))

    def test_destination_and_model_are_fixed(self):
        self.oracle.query("Synthetic query")
        request = self.opener.open.call_args.args[0]

        self.assertEqual(request.full_url, ORACLE_ENDPOINT)
        self.assertEqual(
            json.loads(request.data)["model"],
            "research-model",
        )
        self.assertEqual(
            self.opener.open.call_args.kwargs["timeout"],
            10,
        )

    def test_heldout_labels_are_not_used_for_training(self):
        texts = ["star telescope", "plant roots", "rock minerals"]
        labels = ["astronomy", "botany", "geology"]

        with patch("src.emulation.replication.Pipeline") as factory:
            model = factory.return_value
            model.predict.return_value = ["astronomy"]

            evaluate_replica(
                texts,
                labels,
                ["distant galaxy"],
                ["geology"],
            )

            model.fit.assert_called_once_with(texts, labels)


    def test_single_class_training_is_explicitly_rejected(self):
        with self.assertRaises(ValueError):
            evaluate_replica(
                ["star", "planet"],
                ["astronomy", "astronomy"],
                ["galaxy"],
                ["astronomy"],
            )

if __name__ == "__main__":
    unittest.main()