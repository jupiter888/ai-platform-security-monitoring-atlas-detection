"""
Project 10 — Small research-topic classification model.

Actual learned inference over a deliberately small synthetic corpus.
Not a general-purpose research assistant or production classifier.
"""

import hashlib
import json
from dataclasses import asdict, dataclass

import sklearn
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline


MODEL_NAME = "research-model"
MAX_TEXT_LENGTH = 2000

TRAINING_DATA = (
    ("Stars produce energy through nuclear fusion", "astronomy"),
    ("Planets orbit stars in planetary systems", "astronomy"),
    ("Galaxies contain stars and interstellar gas", "astronomy"),
    ("Telescopes observe distant stars and galaxies", "astronomy"),
    ("The moon orbits a planet", "astronomy"),
    ("Comets travel through the solar system", "astronomy"),
    ("Astronomers measure the light of distant planets", "astronomy"),
    ("A supernova is an explosion of a massive star", "astronomy"),

    ("Plants absorb sunlight through their leaves", "botany"),
    ("Roots take up water and nutrients from soil", "botany"),
    ("Flowers support plant reproduction and pollination", "botany"),
    ("Seeds develop into new plants", "botany"),
    ("Photosynthesis converts light into chemical energy", "botany"),
    ("Trees grow roots stems and leaves", "botany"),
    ("Botanists study flowering plants and seed growth", "botany"),
    ("Pollen is transferred between flowers", "botany"),

    ("Rocks contain minerals formed by geological processes", "geology"),
    ("Volcanoes release molten rock and ash", "geology"),
    ("Earthquakes occur along faults in the crust", "geology"),
    ("Sedimentary rocks form from layers of sediment", "geology"),
    ("Tectonic plates move across the mantle", "geology"),
    ("Erosion breaks down rocks and transports sediment", "geology"),
    ("Geologists examine minerals and rock formations", "geology"),
    ("Magma cools to form igneous rock", "geology"),
)

MODEL_CONFIG = {
    "vectorizer": "tfidf",
    "ngram_range": [1, 2],
    "classifier": "multinomial-naive-bayes",
    "alpha": 0.5,
}

MODEL_VERSION = hashlib.sha256(
    json.dumps(
        {
            "training_data": TRAINING_DATA,
            "configuration": MODEL_CONFIG,
            "scikit_learn_version": sklearn.__version__,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
).hexdigest()[:16]


@dataclass(frozen=True)
class Prediction:
    model: str
    model_version: str
    label: str
    score: float

    def to_dict(self):
        return asdict(self)


class ResearchClassifier:
    def __init__(self):
        texts = [text for text, _ in TRAINING_DATA]
        labels = [label for _, label in TRAINING_DATA]

        self.pipeline = Pipeline([
            (
                "tfidf",
                TfidfVectorizer(
                    ngram_range=(1, 2),
                    sublinear_tf=True,
                ),
            ),
            (
                "classifier",
                MultinomialNB(alpha=0.5),
            ),
        ])
        self.pipeline.fit(texts, labels)

    def predict(self, text: str) -> Prediction:
        if not isinstance(text, str):
            raise ValueError("Input must be text")

        if not text.strip() or len(text) > MAX_TEXT_LENGTH:
            raise ValueError("Invalid input length")

        probabilities = self.pipeline.predict_proba([text])[0]
        selected = int(probabilities.argmax())
        label = str(self.pipeline.classes_[selected])

        return Prediction(
            model=MODEL_NAME,
            model_version=MODEL_VERSION,
            label=label,
            score=float(probabilities[selected]),
        )