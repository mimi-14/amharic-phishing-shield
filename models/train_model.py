"""
Trains a TF-IDF + Logistic Regression classifier on the labeled dataset.

Run from the models/ folder:
    python3 train_model.py

Output:
    phishing_model.joblib   — the trained classifier
    vectorizer.joblib       — the fitted TF-IDF vectorizer
    (both saved in this models/ folder)
"""

import sys
import os
import json
import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score

# Allow importing the normalizer from ../app
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "app"))
from normalizer import normalize  # noqa: E402

DATA_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "labeled_messages.csv")
MODEL_PATH = os.path.join(os.path.dirname(__file__), "phishing_model.joblib")
VECTORIZER_PATH = os.path.join(os.path.dirname(__file__), "vectorizer.joblib")
JSON_MODEL_PATH = os.path.join(os.path.dirname(__file__), "phishing_model.json")


def export_json(model, vectorizer, path=JSON_MODEL_PATH):
    """
    Export the learned numbers to plain JSON so the app can score messages in
    pure Python, with no scikit-learn/scipy import at runtime. This is needed on
    computers where security policy blocks scikit-learn's compiled files.
    """
    classes = list(model.classes_)
    assert classes == ["legit", "phishing"], classes
    coefs = model.coef_[0]          # weights for the 'phishing' class
    idf = vectorizer.idf_
    vocab = {
        term: [float(idf[i]), float(coefs[i])]
        for term, i in vectorizer.vocabulary_.items()
    }
    data = {
        "ngram_range": list(vectorizer.ngram_range),
        "intercept": float(model.intercept_[0]),
        "vocab": vocab,   # term -> [idf, coefficient]
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False)
    print(f"Saved pure-Python model to {path}")


def load_data():
    df = pd.read_csv(DATA_PATH)
    df = df.dropna(subset=["text", "label"])
    # Normalize every message the same way the rule engine does,
    # so the ML model sees consistent, cleaned text.
    df["clean_text"] = df["text"].apply(lambda t: normalize(t)["normalized"])
    return df


def train():
    df = load_data()
    print(f"Loaded {len(df)} messages ({(df.label == 'phishing').sum()} phishing, "
          f"{(df.label == 'legit').sum()} legit)")

    X = df["clean_text"]
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # char n-grams work well for short, noisy, mixed-script messages
    vectorizer = TfidfVectorizer(
        analyzer="char_wb",
        ngram_range=(2, 4),
        min_df=1,
        max_features=5000,
    )
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)

    model = LogisticRegression(max_iter=1000, class_weight="balanced")
    model.fit(X_train_vec, y_train)

    y_pred = model.predict(X_test_vec)

    print("\n=== Evaluation on held-out test set ===")
    print(f"Accuracy: {accuracy_score(y_test, y_pred):.2f}")
    print("\nClassification report:")
    print(classification_report(y_test, y_pred))
    print("Confusion matrix (rows=actual, cols=predicted):")
    print(confusion_matrix(y_test, y_pred, labels=["legit", "phishing"]))

    joblib.dump(model, MODEL_PATH)
    joblib.dump(vectorizer, VECTORIZER_PATH)
    print(f"\nSaved model to {MODEL_PATH}")
    print(f"Saved vectorizer to {VECTORIZER_PATH}")
    export_json(model, vectorizer)


if __name__ == "__main__":
    train()
