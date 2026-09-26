from __future__ import annotations

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier

from backend.ai_engine.traffic_classifier import TrafficClassifier
from ml.datasets.build_dataset import FEATURE_COLUMNS


def make_model_bundle(tmp_path):
    rng = np.random.default_rng(42)

    feature_count = len(FEATURE_COLUMNS)

    x = np.vstack(
        [
            rng.normal(1.0, 0.05, size=(6, feature_count)),
            rng.normal(10.0, 0.05, size=(6, feature_count)),
            rng.normal(20.0, 0.05, size=(6, feature_count)),
        ]
    )

    y = np.asarray(
        ["ICMP"] * 6
        + ["VIDEO"] * 6
        + ["WEB"] * 6,
        dtype=str,
    )

    model = RandomForestClassifier(
        n_estimators=50,
        random_state=42,
    )

    model.fit(x, y)

    bundle = {
        "model": model,
        "feature_columns": FEATURE_COLUMNS,
        "class_names": ["ICMP", "VIDEO", "WEB"],
        "model_version": "test-rf-v1",
    }

    model_path = tmp_path / "traffic_random_forest.joblib"

    joblib.dump(bundle, model_path)

    return model_path


def make_feature_vector(value: float = 1.0):
    return {
        feature: float(value)
        for feature in FEATURE_COLUMNS
    }


def test_classifier_prediction_schema(tmp_path):
    model_path = make_model_bundle(tmp_path)

    classifier = TrafficClassifier(model_path)

    result = classifier.predict(
        make_feature_vector(),
        explain=False,
    )

    assert result["predicted_class"] in {
        "ICMP",
        "VIDEO",
        "WEB",
    }

    assert 0.0 <= result["confidence"] <= 1.0

    assert result["provenance"] == "INFERRED"

    assert result["model_version"] == "test-rf-v1"

    assert result["model_type"] == "RandomForestClassifier"

    assert set(result["class_probabilities"]) == {
        "ICMP",
        "VIDEO",
        "WEB",
    }


def test_classifier_returns_shap_explanation(tmp_path):
    model_path = make_model_bundle(tmp_path)

    classifier = TrafficClassifier(model_path)

    result = classifier.predict(
        make_feature_vector(),
        explain=True,
        top_k=5,
    )

    assert "explanation" in result

    explanation = result["explanation"]

    assert explanation["predicted_class"] == result["predicted_class"]

    assert explanation["confidence"] == result["confidence"]

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


def test_classifier_can_disable_explanation(tmp_path):
    model_path = make_model_bundle(tmp_path)

    classifier = TrafficClassifier(model_path)

    result = classifier.predict(
        make_feature_vector(),
        explain=False,
    )

    assert "explanation" not in result


def test_classifier_rejects_missing_features(tmp_path):
    model_path = make_model_bundle(tmp_path)

    classifier = TrafficClassifier(model_path)

    features = make_feature_vector()

    features.pop(FEATURE_COLUMNS[0])

    try:
        classifier.predict(features)
    except ValueError as exc:
        assert "missing required fields" in str(exc)
    else:
        raise AssertionError(
            "Classifier should reject incomplete feature vectors"
        )
