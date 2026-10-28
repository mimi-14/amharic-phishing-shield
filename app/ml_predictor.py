"""
Pure-Python ML predictor.

Loads models/phishing_model.json (exported by models/train_model.py) and scores
a message WITHOUT importing scikit-learn, scipy, numpy or joblib. This avoids
the "Application Control policy has blocked this file" DLL errors on computers
whose security policy blocks scikit-learn's compiled files.

It reproduces scikit-learn's TF-IDF (char_wb n-grams) + Logistic Regression
exactly, so the scores match the trained model.

Fails gracefully: if the JSON is missing or broken, predict_score returns 0 and
the rule engine + link analyzer still run normally.
"""

import json
import math
import os
import re

from normalizer import normalize

_MODEL_PATH = os.path.join(
    os.path.dirname(__file__), "..", "models", "phishing_model.json"
)

_model = None
_load_attempted = False
_WHITESPACE = re.compile(r"\s\s+")


def _lazy_load():
    global _model, _load_attempted
    if _load_attempted:
        return
    _load_attempted = True
    try:
        with open(_MODEL_PATH, encoding="utf-8") as f:
            _model = json.load(f)
    except Exception as e:
        print(f"[ml_predictor] ML layer unavailable, continuing without it: {e}")
        _model = None


def _char_wb_ngrams(text, ngram_range):
    """Same n-gram logic as scikit-learn's analyzer='char_wb'."""
    text = _WHITESPACE.sub(" ", text)
    min_n, max_n = ngram_range
    ngrams = []
    for word in text.split():
        w = " " + word + " "
        w_len = len(w)
        for n in range(min_n, max_n + 1):
            offset = 0
            ngrams.append(w[offset:offset + n])
            while offset + n < w_len:
                offset += 1
                ngrams.append(w[offset:offset + n])
            if offset == 0:  # short word counted only once
                break
    return ngrams


def predict_score(raw_text: str) -> float:
    """Returns a 0-100 phishing likelihood, or 0 if the model isn't available."""
    _lazy_load()
    if _model is None:
        return 0.0

    vocab = _model["vocab"]
    clean_text = normalize(raw_text)["normalized"].lower()

    # term counts (only terms the model knows), weighted by idf
    counts = {}
    for gram in _char_wb_ngrams(clean_text, _model["ngram_range"]):
        if gram in vocab:
            counts[gram] = counts.get(gram, 0) + 1
    if not counts:
        return 0.0

    weighted = {g: c * vocab[g][0] for g, c in counts.items()}
    norm = math.sqrt(sum(v * v for v in weighted.values()))
    if norm == 0:
        return 0.0

    logit = _model["intercept"] + sum(
        (v / norm) * vocab[g][1] for g, v in weighted.items()
    )
    # numerically safe sigmoid
    if logit >= 0:
        proba = 1.0 / (1.0 + math.exp(-logit))
    else:
        e = math.exp(logit)
        proba = e / (1.0 + e)
    return round(proba * 100, 1)


if __name__ == "__main__":
    tests = [
        "ሰላም! ሂሳብዎ ይታገዳል!!! አሁኑኑ የይለፍ ቃልዎን ያስገቡ http://telebirr-verify.com",
        "Hi, are we still meeting tomorrow at 5?",
    ]
    for t in tests:
        print(f"{t[:50]!r}... -> ML score: {predict_score(t)}")
