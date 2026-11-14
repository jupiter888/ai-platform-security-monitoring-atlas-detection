"""
Project 10 — Bounded local model-replication experiment.

The oracle exposes only the authenticated local inference API.
A separate classifier learns from returned labels.

No imports from src.inference or access to target model artifacts.
"""

import hashlib
import json
import math
import re
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import ProxyHandler, Request, build_opener
from uuid import UUID

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import accuracy_score
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline

from src.telemetry.loki import NoRedirects


ORACLE_ENDPOINT = "http://127.0.0.1:8200/v1/inference"
MAX_QUERY_BUDGET = 36
REQUEST_INTERVAL_SECONDS = 0.25
CLASSES = frozenset({"astronomy", "botany", "geology"})

TRAINING_QUERIES = (
    "Study stars using a telescope",
    "Describe planets orbiting a star",
    "Observe the light of a galaxy",
    "Investigate the orbit of a moon",
    "Study a comet in the solar system",
    "Observe a supernova with a telescope",
    "Measure light from stars and planets",
    "Investigate gas between stars in a galaxy",

    "Study roots growing in soil",
    "Describe how leaves use sunlight",
    "Investigate flowering plants and pollen",
    "Observe seeds growing into plants",
    "Study water uptake by tree roots",
    "Investigate photosynthesis in green leaves",
    "Describe pollination between flowers",
    "Observe plant stems and seed growth",

    "Study minerals in a rock sample",
    "Investigate earthquakes near a fault",
    "Describe lava from a volcano",
    "Observe layers of sedimentary rock",
    "Study movement of tectonic plates",
    "Investigate erosion of rock formations",
    "Describe cooling magma and minerals",
    "Study the crust and mantle of Earth",
)

HELDOUT_QUERIES = (
    "Compare telescope observations of two galaxies",
    "Explain why a planet has an orbital period",
    "Investigate a bright stellar explosion",
    "Describe the path of an icy comet",

    "Compare pollen production in flowering plants",
    "Explain how roots obtain dissolved nutrients",
    "Investigate leaf growth under different light",
    "Describe the development of a seedling",

    "Compare minerals in volcanic rock samples",
    "Explain displacement along an earthquake fault",
    "Investigate sediment transported by erosion",
    "Describe motion at a tectonic plate boundary",
)


class InferenceOracle:
    def __init__(self, reader_key, opener=None):
        if (
            not isinstance(reader_key, str)
            or re.fullmatch(r"[0-9a-f]{64}", reader_key) is None
        ):
            raise ValueError("Invalid oracle credential")

        self.reader_key = reader_key
        self.opener = (
            opener
            if opener is not None
            else build_opener(ProxyHandler({}), NoRedirects())
        )

    def query(self, text):
        if (
            not isinstance(text, str)
            or not text.strip()
            or len(text) > 2000
        ):
            raise ValueError("Invalid oracle input")

        request = Request(
            ORACLE_ENDPOINT,
            data=json.dumps({
                "model": "research-model",
                "prompt": text,
            }).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.reader_key}",
            },
            method="POST",
        )

        try:
            with self.opener.open(request, timeout=10) as response:
                status = response.status
                request_id = response.headers.get("X-Request-ID", "")
                raw = response.read(4097)
        except HTTPError as error:
            error.close()
            raise RuntimeError("Oracle request was rejected") from None
        except (URLError, OSError):
            raise RuntimeError("Oracle transport unavailable") from None

        if status != 200 or len(raw) > 4096:
            raise RuntimeError("Unexpected oracle response")

        try:
            result = json.loads(raw)
        except ValueError:
            raise RuntimeError("Invalid oracle JSON") from None

        if (
            not isinstance(result, dict)
            or set(result) != {
                "model", "model_version", "label", "score"
            }
            or result["model"] != "research-model"
            or not isinstance(result["model_version"], str)
            or re.fullmatch(
                r"[0-9a-f]{16}", result["model_version"]
            ) is None
            or not isinstance(result["label"], str)
            or result["label"] not in CLASSES
            or type(result["score"]) not in (int, float)
            or not math.isfinite(result["score"])
            or not 0 <= result["score"] <= 1
        ):
            raise RuntimeError("Invalid oracle prediction contract")

        try:
            parsed = UUID(request_id)
        except ValueError:
            raise RuntimeError("Invalid oracle correlation identifier") from None

        if parsed.version != 4 or str(parsed) != request_id:
            raise RuntimeError("Invalid oracle correlation identifier")

        return {
            "text": text,
            "request_id": request_id,
            **result,
        }


def evaluate_replica(training_texts, training_labels, test_texts, target_labels):
    if (
        len(training_texts) != len(training_labels)
        or len(test_texts) != len(target_labels)
        or not training_texts
        or not test_texts
        or len(set(training_labels)) < 2
    ):
        raise ValueError("Insufficient or inconsistent experiment data")

    if set(training_texts).intersection(test_texts):
        raise ValueError("Training and held-out queries overlap")

    replica = Pipeline([
        ("tfidf", TfidfVectorizer(ngram_range=(1, 2))),
        ("classifier", MultinomialNB(alpha=0.5)),
    ])
    replica.fit(training_texts, training_labels)
    predictions = [str(value) for value in replica.predict(test_texts)]

    majority_label = Counter(training_labels).most_common(1)[0][0]
    baseline = [majority_label] * len(test_texts)

    return {
        "heldout_target_agreement": float(
            accuracy_score(target_labels, predictions)
        ),
        "majority_baseline_agreement": float(
            accuracy_score(target_labels, baseline)
        ),
        "replica_predictions": predictions,
        "target_predictions": list(target_labels),
        "training_label_counts": dict(Counter(training_labels)),
    }


def main():
    total = len(TRAINING_QUERIES) + len(HELDOUT_QUERIES)

    if total != MAX_QUERY_BUDGET:
        raise RuntimeError("Unexpected experiment query budget")
    if len(set(TRAINING_QUERIES + HELDOUT_QUERIES)) != total:
        raise RuntimeError("Experiment queries are not unique")

    credential_path = (
        Path.home()
        / ".config/project10/credentials/inference-clients.json"
    )
    credentials = json.loads(
        credential_path.read_text(encoding="utf-8")
    )
    oracle = InferenceOracle(credentials["reader_key"])
    started_at = datetime.now(timezone.utc).isoformat()

    training = []
    heldout = []

    for destination, queries in (
        (training, TRAINING_QUERIES),
        (heldout, HELDOUT_QUERIES),
    ):
        for text in queries:
            destination.append(oracle.query(text))
            time.sleep(REQUEST_INTERVAL_SECONDS)

    responses = training + heldout
    if len({item["request_id"] for item in responses}) != total:
        raise RuntimeError("Repeated request correlation identifier")

    versions = {item["model_version"] for item in responses}
    if len(versions) != 1:
        raise RuntimeError("Target model changed during the experiment")

    evaluation = evaluate_replica(
        [item["text"] for item in training],
        [item["label"] for item in training],
        [item["text"] for item in heldout],
        [item["label"] for item in heldout],
    )

    dataset_fingerprint = hashlib.sha256(
        json.dumps({
            "training": TRAINING_QUERIES,
            "heldout": HELDOUT_QUERIES,
        }, sort_keys=True).encode("utf-8")
    ).hexdigest()

    report = {
        "scenario": "controlled-output-based-model-replication",
        "ground_truth": "authorized-adversarial-emulation",
        "data_provenance": "synthetic-research-queries",
        "started_at": started_at,
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "target_model": "research-model",
        "target_model_version": next(iter(versions)),
        "query_budget": MAX_QUERY_BUDGET,
        "requests_completed": len(responses),
        "training_queries": len(training),
        "heldout_queries": len(heldout),
        "query_set_fingerprint": dataset_fingerprint,
        "evaluation": evaluation,
        "training_observations": training,
        "heldout_observations": heldout,
        "limitations": [
            "Small hand-authored query set",
            "Researcher-designed queries are not a blind attack benchmark",
            "Target labels are not ground-truth topic labels",
            "Agreement is not production accuracy or complete model extraction",
            "No target weights or training artifacts were accessed",
            "Detection effectiveness is evaluated separately",
        ],
    }

    destination = Path(
        "evidence/public/model-replication-experiment.json"
    )
    destination.write_text(
        json.dumps(report, indent=2) + "\n",
        encoding="utf-8",
    )

    print(json.dumps({
        "requests_completed": len(responses),
        "training_queries": len(training),
        "heldout_queries": len(heldout),
        "target_model_version": next(iter(versions)),
        "heldout_target_agreement": evaluation[
            "heldout_target_agreement"
        ],
        "majority_baseline_agreement": evaluation[
            "majority_baseline_agreement"
        ],
        "training_label_counts": evaluation["training_label_counts"],
    }, indent=2))
    print("Experiment report saved; detection outcome not yet evaluated.")

if __name__ == "__main__":
    main()