from __future__ import annotations

from typing import Any

import numpy as np
import shap

from ml.datasets.build_dataset import FEATURE_COLUMNS


def _normalize_shap_values(
    shap_values: Any,
    class_index: int,
    sample_count: int,
    feature_count: int,
) -> np.ndarray:
    """
    Normalize SHAP output across SHAP API variants.

    Supported forms:
    - ndarray: (samples, features, classes)
    - list of ndarrays: one (samples, features) array per class
    - ndarray: (samples, features) for a single-output model
    """
    if isinstance(shap_values, list):
        if class_index >= len(shap_values):
            raise IndexError(
                f"SHAP class index {class_index} is out of range"
            )

        values = np.asarray(shap_values[class_index], dtype=float)

    else:
        values = np.asarray(shap_values, dtype=float)

        if values.ndim == 3:
            if values.shape[0] == sample_count:
                values = values[:, :, class_index]
            elif values.shape[1] == sample_count:
                values = values[class_index, :, :]
            else:
                raise ValueError(
                    f"Unsupported 3D SHAP shape: {values.shape}"
                )

    if values.shape != (sample_count, feature_count):
        raise ValueError(
            "Unexpected SHAP shape: "
            f"{values.shape}; expected "
            f"({sample_count}, {feature_count})"
        )

    return values


def explain_predictions(
    model,
    x: np.ndarray,
    predictions: np.ndarray,
    probabilities: np.ndarray,
    class_names: list[str],
    top_k: int = 5,
) -> list[dict[str, Any]]:
    """
    Explain Random Forest predictions using SHAP.

    SHAP is used only for explanation. It does not alter:
    - the predicted class,
    - prediction confidence,
    - deterministic IPsec observations,
    - security assessment,
    - security score.
    """
    x = np.asarray(x, dtype=float)
    predictions = np.asarray(predictions, dtype=str)
    probabilities = np.asarray(probabilities, dtype=float)

    if x.ndim != 2:
        raise ValueError("x must be a 2D feature matrix")

    if x.shape[1] != len(FEATURE_COLUMNS):
        raise ValueError(
            f"Expected {len(FEATURE_COLUMNS)} features, got {x.shape[1]}"
        )

    if len(predictions) != len(x):
        raise ValueError("predictions length must match x")

    if probabilities.shape[0] != len(x):
        raise ValueError("probabilities length must match x")

    explainer = shap.TreeExplainer(model)
    shap_values = explainer.shap_values(x)

    class_index_by_name = {
        name: index
        for index, name in enumerate(class_names)
    }

    explanations = []

    for sample_index, predicted_class in enumerate(predictions):
        if predicted_class not in class_index_by_name:
            raise ValueError(
                f"Unknown predicted class: {predicted_class}"
            )

        class_index = class_index_by_name[predicted_class]

        sample_values = _normalize_shap_values(
            shap_values,
            class_index,
            sample_count=len(x),
            feature_count=len(FEATURE_COLUMNS),
        )[sample_index]

        ranked = sorted(
            zip(FEATURE_COLUMNS, sample_values),
            key=lambda item: abs(float(item[1])),
            reverse=True,
        )

        contributions = [
            {
                "feature": feature_name,
                "value": float(x[sample_index, feature_index]),
                "shap_value": round(float(shap_value), 6),
                "direction": (
                    "supports"
                    if shap_value >= 0
                    else "opposes"
                ),
            }
            for feature_index, (feature_name, shap_value) in enumerate(
                zip(FEATURE_COLUMNS, sample_values)
            )
        ]

        top_contributions = sorted(
            contributions,
            key=lambda item: abs(item["shap_value"]),
            reverse=True,
        )[:top_k]

        confidence = float(
            probabilities[
                sample_index,
                class_index,
            ]
        )

        explanations.append(
            {
                "predicted_class": predicted_class,
                "confidence": round(confidence, 4),
                "provenance": "INFERRED",
                "explanation_method": "SHAP_TREE_EXPLAINER",
                "top_features": top_contributions,
            }
        )

    return explanations
