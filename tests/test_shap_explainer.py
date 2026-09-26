from __future__ import annotations

import numpy as np

from ml.datasets.build_dataset import FEATURE_COLUMNS, build_dataset
from ml.training.shap_explainer import explain_predictions
from ml.training.train_random_forest import evaluate_model


def _trained_model():
    rows, labels, metadata = build_dataset(
        "ml/datasets/manifest.csv"
    )

    x = np.asarray(
        [[row[column] for column in FEATURE_COLUMNS] for row in rows],
        dtype=float,
    )

    y = np.asarray(labels, dtype=str)

    (
        model,
        predictions,
        probabilities,
        _accuracy,
        _matrix,
        class_names,
    ) = evaluate_model(x, y)

    return (
        model,
        x,
        predictions,
        probabilities,
        class_names,
        metadata,
    )


def test_shap_explanations_match_dataset_size():
    (
        model,
        x,
        predictions,
        probabilities,
        class_names,
        _metadata,
    ) = _trained_model()

    explanations = explain_predictions(
        model,
        x,
        predictions,
        probabilities,
        class_names,
    )

    assert len(explanations) == len(x)


def test_shap_explanation_schema():
    (
        model,
        x,
        predictions,
        probabilities,
        class_names,
        _metadata,
    ) = _trained_model()

    explanations = explain_predictions(
        model,
        x,
        predictions,
        probabilities,
        class_names,
        top_k=5,
    )

    explanation = explanations[0]

    assert explanation["predicted_class"] in class_names
    assert 0.0 <= explanation["confidence"] <= 1.0
    assert explanation["provenance"] == "INFERRED"
    assert explanation["explanation_method"] == "SHAP_TREE_EXPLAINER"

    assert len(explanation["top_features"]) == 5

    for feature in explanation["top_features"]:
        assert feature["feature"] in FEATURE_COLUMNS
        assert isinstance(feature["value"], float)
        assert isinstance(feature["shap_value"], float)
        assert feature["direction"] in {
            "supports",
            "opposes",
        }


def test_shap_does_not_change_prediction():
    (
        model,
        x,
        predictions,
        probabilities,
        class_names,
        _metadata,
    ) = _trained_model()

    explanations = explain_predictions(
        model,
        x,
        predictions,
        probabilities,
        class_names,
    )

    explained_predictions = np.asarray(
        [item["predicted_class"] for item in explanations],
        dtype=str,
    )

    assert np.array_equal(
        explained_predictions,
        predictions,
    )


def test_shap_confidence_matches_model_probability():
    (
        model,
        x,
        predictions,
        probabilities,
        class_names,
        _metadata,
    ) = _trained_model()

    explanations = explain_predictions(
        model,
        x,
        predictions,
        probabilities,
        class_names,
    )

    class_index = {
        name: index
        for index, name in enumerate(class_names)
    }

    for index, explanation in enumerate(explanations):
        predicted_class = explanation["predicted_class"]

        expected_confidence = probabilities[
            index,
            class_index[predicted_class],
        ]

        assert explanation["confidence"] == round(
            float(expected_confidence),
            4,
        )
