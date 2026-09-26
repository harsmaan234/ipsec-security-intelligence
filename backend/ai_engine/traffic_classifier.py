from __future__ import annotations

from pathlib import Path
from typing import Any

import joblib
import numpy as np

from ml.datasets.build_dataset import FEATURE_COLUMNS
from ml.training.shap_explainer import explain_predictions


DEFAULT_MODEL_PATH = Path("ml/models/traffic_random_forest.joblib")


class TrafficClassifier:
    """
    Loads the trained traffic-classification model and performs
    metadata-based encrypted traffic inference.

    The classifier:
    - does not inspect plaintext,
    - does not decrypt ESP,
    - does not determine deterministic IPsec properties,
    - does not modify security assessment or security score.

    Its output is explicitly marked as INFERRED.
    """

    def __init__(
        self,
        model_path: str | Path = DEFAULT_MODEL_PATH,
    ) -> None:
        self.model_path = Path(model_path)

        if not self.model_path.exists():
            raise FileNotFoundError(
                f"Traffic classification model not found: "
                f"{self.model_path}"
            )

        bundle = joblib.load(self.model_path)

        required_keys = {
            "model",
            "feature_columns",
            "class_names",
            "model_version",
        }

        missing_keys = required_keys - set(bundle)

        if missing_keys:
            raise ValueError(
                "Invalid model bundle. Missing keys: "
                f"{sorted(missing_keys)}"
            )

        self.model = bundle["model"]
        self.feature_columns = list(bundle["feature_columns"])
        self.class_names = list(bundle["class_names"])
        self.model_version = str(bundle["model_version"])

        if self.feature_columns != FEATURE_COLUMNS:
            raise ValueError(
                "Model feature schema does not match the current "
                "traffic feature schema"
            )

    def _vectorize(
        self,
        feature_vector: dict[str, float],
    ) -> np.ndarray:
        missing = [
            column
            for column in self.feature_columns
            if column not in feature_vector
        ]

        if missing:
            raise ValueError(
                f"Feature vector is missing required fields: {missing}"
            )

        return np.asarray(
            [
                [
                    float(feature_vector[column])
                    for column in self.feature_columns
                ]
            ],
            dtype=float,
        )

    def predict(
        self,
        feature_vector: dict[str, float],
        explain: bool = True,
        top_k: int = 5,
    ) -> dict[str, Any]:
        x = self._vectorize(feature_vector)

        probabilities = self.model.predict_proba(x)[0]

        predicted_index = int(np.argmax(probabilities))
        predicted_class = self.class_names[predicted_index]
        confidence = float(probabilities[predicted_index])

        class_probabilities = {
            class_name: round(float(probability), 4)
            for class_name, probability in zip(
                self.class_names,
                probabilities,
            )
        }

        result = {
            "predicted_class": predicted_class,
            "confidence": round(confidence, 4),
            "provenance": "INFERRED",
            "model_version": self.model_version,
            "model_type": "RandomForestClassifier",
            "class_probabilities": class_probabilities,
        }

        if explain:
            explanations = explain_predictions(
                self.model,
                x,
                np.asarray([predicted_class], dtype=str),
                np.asarray([probabilities], dtype=float),
                self.class_names,
                top_k=top_k,
            )

            result["explanation"] = explanations[0]

        return result


def classify_traffic(
    feature_vector: dict[str, float],
    model_path: str | Path = DEFAULT_MODEL_PATH,
    explain: bool = True,
    top_k: int = 5,
) -> dict[str, Any]:
    classifier = TrafficClassifier(model_path)
    return classifier.predict(
        feature_vector,
        explain=explain,
        top_k=top_k,
    )
