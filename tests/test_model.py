"""
Model inference contract tests.

Predictive quality is evaluated separately on held-out examples.
"""

import math
import unittest

from src.inference.model import (
    MAX_TEXT_LENGTH,
    MODEL_VERSION,
    ResearchClassifier,
)


class ModelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.model = ResearchClassifier()

    def test_returns_valid_class(self):
        prediction = self.model.predict("Observe distant planets")
        self.assertIn(
            prediction.label,
            {"astronomy", "botany", "geology"},
        )

    def test_returns_finite_probability(self):
        prediction = self.model.predict("Study plant roots")
        self.assertTrue(math.isfinite(prediction.score))
        self.assertGreaterEqual(prediction.score, 0)
        self.assertLessEqual(prediction.score, 1)

    def test_version_is_attached(self):
        prediction = self.model.predict("Examine volcanic rock")
        self.assertEqual(prediction.model, "research-model")
        self.assertEqual(prediction.model_version, MODEL_VERSION)

    def test_prediction_does_not_return_input(self):
        text = "synthetic-input-canary"
        result = self.model.predict(text).to_dict()

        self.assertEqual(
            set(result),
            {"model", "model_version", "label", "score"},
        )
        self.assertNotIn(text, str(result))

    def test_empty_input_is_rejected(self):
        for text in ("", " ", "\n\t"):
            with self.subTest(text=text):
                with self.assertRaises(ValueError):
                    self.model.predict(text)

    def test_oversized_input_is_rejected(self):
        with self.assertRaises(ValueError):
            self.model.predict("x" * (MAX_TEXT_LENGTH + 1))

    def test_non_text_input_is_rejected(self):
        for value in (None, 1, [], {}):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    self.model.predict(value)

    def test_repeated_prediction_is_consistent(self):
        text = "Plants use sunlight and water"
        self.assertEqual(
            self.model.predict(text),
            self.model.predict(text),
        )

if __name__ == "__main__":
    unittest.main()