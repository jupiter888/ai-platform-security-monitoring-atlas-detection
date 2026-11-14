"""
Initial held-out model evaluation.

Small synthetic evaluation set, not a generalization benchmark.
"""

import json

from sklearn.metrics import accuracy_score, confusion_matrix

from src.inference.model import (
    MODEL_VERSION,
    TRAINING_DATA,
    ResearchClassifier,
)


EVALUATION_DATA = (
    ("A telescope collects light from a galaxy", "astronomy"),
    ("Scientists observe planets around distant stars", "astronomy"),
    ("A comet passes near the sun", "astronomy"),

    ("Sunlight helps green leaves perform photosynthesis", "botany"),
    ("Plant roots obtain nutrients and water", "botany"),
    ("Flowers produce pollen for reproduction", "botany"),

    ("A volcano produces lava and volcanic rock", "geology"),
    ("An earthquake moves the ground along a fault", "geology"),
    ("Sediment accumulates in layers and forms rock", "geology"),
)


def main():
    training_texts = {text for text, _ in TRAINING_DATA}
    evaluation_texts = [text for text, _ in EVALUATION_DATA]

    if training_texts.intersection(evaluation_texts):
        raise RuntimeError("Training and evaluation texts overlap")

    model = ResearchClassifier()
    expected = [label for _, label in EVALUATION_DATA]
    predicted = [
        model.predict(text).label
        for text in evaluation_texts
    ]
    classes = ["astronomy", "botany", "geology"]

    result = {
        "model": "research-model",
        "model_version": MODEL_VERSION,
        "training_examples": len(TRAINING_DATA),
        "evaluation_examples": len(EVALUATION_DATA),
        "data_provenance": "synthetic",
        "accuracy": float(accuracy_score(expected, predicted)),
        "confusion_matrix": confusion_matrix(
            expected,
            predicted,
            labels=classes,
        ).tolist(),
        "class_order": classes,
        "matrix_rows": "expected",
        "matrix_columns": "predicted",
        "limitations": [
            "Small hand-authored dataset",
            "Related vocabulary across training and evaluation",
            "No production accuracy or calibrated-confidence claim",
            "Not an attack-detection evaluation",
        ],
    }
    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    main()