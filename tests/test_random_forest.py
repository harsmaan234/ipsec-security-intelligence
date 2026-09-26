import numpy as np

from ml.training.train_random_forest import (
    FEATURE_COLUMNS,
    evaluate_model,
    prediction_records,
)


def make_synthetic_dataset():
    rng = np.random.default_rng(42)

    rows_per_class = 6
    feature_count = len(FEATURE_COLUMNS)

    icmp = rng.normal(
        loc=1.0,
        scale=0.05,
        size=(rows_per_class, feature_count),
    )

    video = rng.normal(
        loc=10.0,
        scale=0.05,
        size=(rows_per_class, feature_count),
    )

    web = rng.normal(
        loc=20.0,
        scale=0.05,
        size=(rows_per_class, feature_count),
    )

    x = np.vstack([icmp, video, web])

    y = np.asarray(
        ["ICMP"] * rows_per_class
        + ["VIDEO"] * rows_per_class
        + ["WEB"] * rows_per_class,
        dtype=str,
    )

    return x, y


def test_evaluate_model_returns_fitted_model_and_expected_shapes():
    x, y = make_synthetic_dataset()

    (
        model,
        predictions,
        probabilities,
        accuracy,
        matrix,
        class_names,
    ) = evaluate_model(x, y)

    assert hasattr(model, "classes_")
    assert predictions.shape == (len(y),)
    assert probabilities.shape == (len(y), 3)
    assert matrix.shape == (3, 3)

    assert class_names == ["ICMP", "VIDEO", "WEB"]
    assert 0.0 <= accuracy <= 1.0

    assert np.allclose(
        probabilities.sum(axis=1),
        1.0,
    )


def test_prediction_records_include_inferred_provenance_and_confidence():
    x, y = make_synthetic_dataset()

    (
        model,
        predictions,
        probabilities,
        accuracy,
        matrix,
        class_names,
    ) = evaluate_model(x, y)

    metadata = [
        {
            "sample_id": f"sample_{index:03d}",
            "traffic_class": label,
            "pcap_path": f"/tmp/sample_{index:03d}.pcap",
            "label_source": "CONTROLLED_TESTBED",
            "testbed_scenario": "strong",
        }
        for index, label in enumerate(y)
    ]

    records = prediction_records(
        predictions,
        probabilities,
        class_names,
        metadata,
    )

    assert len(records) == len(y)

    for record in records:
        assert record["provenance"] == "INFERRED"
        assert record["predicted_class"] in class_names
        assert 0.0 <= record["confidence"] <= 1.0
        assert "sample_id" in record
        assert "actual_class" in record


def test_evaluate_model_requires_multiple_samples_per_class():
    x = np.ones((3, len(FEATURE_COLUMNS)))
    y = np.asarray(
        ["ICMP", "VIDEO", "WEB"],
        dtype=str,
    )

    try:
        evaluate_model(x, y)
    except ValueError as exc:
        assert "at least two samples" in str(exc)
    else:
        raise AssertionError(
            "evaluate_model should reject classes with fewer than two samples"
        )
