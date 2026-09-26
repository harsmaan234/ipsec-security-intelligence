from __future__ import annotations

from collections import Counter
from pathlib import Path
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix
from sklearn.model_selection import StratifiedKFold, cross_val_predict

from ml.datasets.build_dataset import FEATURE_COLUMNS, build_dataset


MANIFEST_PATH = Path("ml/datasets/manifest.csv")

RANDOM_STATE = 42
N_ESTIMATORS = 200
MODEL_DIR = Path("ml/models")
MODEL_PATH = MODEL_DIR / "traffic_random_forest.joblib"
MODEL_VERSION = "rf-traffic-v1"

def load_training_data(
    manifest_path: str | Path = MANIFEST_PATH,
) -> tuple[np.ndarray, np.ndarray, list[dict[str, str]]]:
    rows, labels, metadata = build_dataset(manifest_path)

    if not rows:
        raise ValueError("Dataset contains no samples")

    x = np.asarray(
        [[row[column] for column in FEATURE_COLUMNS] for row in rows],
        dtype=float,
    )

    y = np.asarray(labels, dtype=str)

    return x, y, metadata


def evaluate_model(
    x: np.ndarray,
    y: np.ndarray,
) -> tuple[
    RandomForestClassifier,
    np.ndarray,
    np.ndarray,
    float,
    np.ndarray,
    list[str],
]:
    class_counts = Counter(y)
    min_class_count = min(class_counts.values())

    if min_class_count < 2:
        raise ValueError(
            "Each class needs at least two samples for stratified cross-validation"
        )

    cv_splits = min(5, min_class_count)

    model = RandomForestClassifier(
        n_estimators=N_ESTIMATORS,
        random_state=RANDOM_STATE,
        class_weight="balanced",
    )

    probabilities = cross_val_predict(
        model,
        x,
        y,
        cv=StratifiedKFold(
            n_splits=cv_splits,
            shuffle=True,
            random_state=RANDOM_STATE,
        ),
        method="predict_proba",
    )

    class_names = sorted(np.unique(y).tolist())

    predictions = np.asarray(
        [class_names[index] for index in np.argmax(probabilities, axis=1)],
        dtype=str,
    )

    accuracy = float(accuracy_score(y, predictions))

    matrix = confusion_matrix(
        y,
        predictions,
        labels=class_names,
    )

    model.fit(x, y)

    return (
        model,
        predictions,
        probabilities,
        accuracy,
        matrix,
        class_names,
    )


def prediction_records(
    predictions: np.ndarray,
    probabilities: np.ndarray,
    class_names: list[str],
    metadata: list[dict[str, str]],
) -> list[dict]:
    records = []

    for index, sample in enumerate(metadata):
        predicted_index = int(np.argmax(probabilities[index]))
        predicted_class = class_names[predicted_index]
        confidence = float(probabilities[index, predicted_index])

        records.append(
            {
                "sample_id": sample["sample_id"],
                "actual_class": sample["traffic_class"],
                "predicted_class": predicted_class,
                "confidence": round(confidence, 4),
                "provenance": "INFERRED",
            }
        )

    return records

def save_model_bundle(
    model: RandomForestClassifier,
    class_names: list[str],
) -> Path:
    MODEL_DIR.mkdir(parents=True, exist_ok=True)

    bundle = {
        "model": model,
        "feature_columns": list(FEATURE_COLUMNS),
        "class_names": list(class_names),
        "model_version": MODEL_VERSION,
        "n_estimators": N_ESTIMATORS,
        "random_state": RANDOM_STATE,
    }

    joblib.dump(bundle, MODEL_PATH)

    return MODEL_PATH

def main() -> None:
    x, y, metadata = load_training_data()

    (
        model,
        predictions,
        probabilities,
        accuracy,
        matrix,
        class_names,
    ) = evaluate_model(x, y)

    records = prediction_records(
        predictions,
        probabilities,
        class_names,
        metadata,
    )

    print(f"samples: {len(metadata)}")
    print(f"features: {len(FEATURE_COLUMNS)}")
    print(f"classes: {class_names}")
    print()

    print("Cross-validation predictions:")

    for record in records:
        print(
            f"{record['sample_id']:10s} "
            f"actual={record['actual_class']:6s} "
            f"predicted={record['predicted_class']:6s} "
            f"confidence={record['confidence']:.4f} "
            f"provenance={record['provenance']}"
        )

    print()
    print(f"Cross-validation accuracy: {accuracy:.4f}")

    print()
    print("Confusion matrix:")
    print("classes:", class_names)
    print(matrix)

    print()
    print("Model feature importances:")

    importances = model.feature_importances_

    ranked_features = sorted(
        zip(FEATURE_COLUMNS, importances),
        key=lambda item: item[1],
        reverse=True,
    )

    for feature_name, importance in ranked_features:
        print(f"{feature_name:24s} {importance:.6f}")

    model_path = save_model_bundle(
        model,
        class_names,
    )

    print()
    print(f"Saved model bundle: {model_path}")
    print()
    print(
        "Evaluation note: this is a small controlled-testbed baseline. "
        "Cross-validation results should not be treated as production "
        "generalization performance."
    )


if __name__ == "__main__":
    main()
