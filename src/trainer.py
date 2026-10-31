import csv
from pathlib import Path

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

from src.config import DATA_PATH, MODEL_PATH


def load_dataset(path: Path) -> tuple[list[str], list[int]]:
    texts: list[str] = []
    labels: list[int] = []

    with path.open("r", encoding="utf-8-sig", newline="") as file:
        reader = csv.DictReader(file)

        if reader.fieldnames is None:
            raise ValueError("Dataset is missing a header row.")

        required = {"text", "label"}
        missing = required.difference(reader.fieldnames)

        if missing:
            raise ValueError(
                "Dataset must contain columns: text,label. "
                f"Missing: {', '.join(sorted(missing))}"
            )

        for row_number, row in enumerate(reader, start=2):
            text = (row.get("text") or "").strip()
            raw_label = (row.get("label") or "").strip()

            if not text:
                continue

            try:
                label = int(raw_label)
            except ValueError as error:
                raise ValueError(
                    f"Invalid label on row {row_number}: {raw_label!r}"
                ) from error

            if label not in {0, 1}:
                raise ValueError(
                    f"Label on row {row_number} must be 0 or 1."
                )

            texts.append(text)
            labels.append(label)

    if not texts:
        raise ValueError("Dataset contains no usable rows.")

    if len(set(labels)) != 2:
        raise ValueError("Dataset must contain both labels 0 and 1.")

    return texts, labels


def build_pipeline() -> Pipeline:
    return Pipeline(
        steps=[
            (
                "tfidf",
                TfidfVectorizer(
                    lowercase=True,
                    strip_accents="unicode",
                    ngram_range=(1, 2),
                    min_df=1,
                    max_df=0.995,
                    max_features=30000,
                    sublinear_tf=True,
                ),
            ),
            (
                "classifier",
                LogisticRegression(
                    max_iter=1500,
                    class_weight="balanced",
                    solver="liblinear",
                    random_state=42,
                ),
            ),
        ]
    )


def train() -> None:
    print(f"Loading dataset from {DATA_PATH}...", flush=True)
    texts, labels = load_dataset(DATA_PATH)
    print(f"Loaded {len(texts):,} labeled messages.", flush=True)

    X_train, X_test, y_train, y_test = train_test_split(
        texts,
        labels,
        test_size=0.25,
        random_state=42,
        stratify=labels,
    )

    print("Training TF-IDF + logistic regression model...", flush=True)
    model = build_pipeline()
    model.fit(X_train, y_train)

    print("Evaluating model...", flush=True)
    predictions = model.predict(X_test)

    print("\nClassification report:")
    print(
        classification_report(
            y_test,
            predictions,
            target_names=["legitimate", "scam"],
            digits=3,
            zero_division=0,
        )
    )

    print("Confusion matrix:")
    print(confusion_matrix(y_test, predictions))

    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    print(f"\nSaved compatible model to {MODEL_PATH}", flush=True)


if __name__ == "__main__":
    train()
