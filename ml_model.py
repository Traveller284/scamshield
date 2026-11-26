"""Local inference for ScamShield's trained SMS message classifier.

The model is trained offline from public, labeled SMS corpora. Inference uses
only Python's standard library, so message text stays on the ScamShield server.
"""
from __future__ import annotations

import gzip
import json
import math
import re
from collections import Counter
from pathlib import Path

MODEL_PATH = Path(__file__).with_name("ml_model.json.gz")
BUCKETS = 1 << 18
TOKEN_RE = re.compile(r"\w+", re.UNICODE)
_MODEL = None


def _hash_feature(value: str) -> int:
    """Stable FNV-1a hash; identical in the offline trainer and runtime."""
    h = 2166136261
    for byte in value.encode("utf-8", "ignore"):
        h = ((h ^ byte) * 16777619) & 0xFFFFFFFF
    return h & (BUCKETS - 1)


def _features(text: str) -> Counter[int]:
    value = str(text).lower()
    tokens = TOKEN_RE.findall(value)
    counts: Counter[int] = Counter()
    for i, token in enumerate(tokens):
        if len(token) >= 2:
            counts[_hash_feature("w:" + token)] += 1
        if i and len(tokens[i - 1]) >= 2 and len(token) >= 2:
            counts[_hash_feature("b:" + tokens[i - 1] + "_" + token)] += 1
    # Character n-grams inside whitespace-delimited chunks catch misspellings,
    # obfuscated wording, URLs, and short code-mixed fragments.
    for chunk in value.split():
        padded = " " + chunk + " "
        for width in (3, 4, 5):
            for i in range(max(0, len(padded) - width + 1)):
                counts[_hash_feature("c:" + padded[i:i + width])] += 1
    return counts


def _load_model():
    global _MODEL
    if _MODEL is None:
        try:
            with gzip.open(MODEL_PATH, "rt", encoding="utf-8") as model_file:
                _MODEL = json.load(model_file)
        except (OSError, ValueError):
            _MODEL = False
    return _MODEL if _MODEL else None


def classify(text: str) -> dict | None:
    """Return the three-class local estimate, or None for weak evidence."""
    letters = [ch for ch in str(text) if ch.isalpha()]
    latin_ratio = sum(ch.isascii() for ch in letters) / max(1, len(letters))
    if len(letters) < 4 or latin_ratio < 0.55:
        return None
    model = _load_model()
    if not model:
        return None

    counts = _features(text)
    idf = model["idf"]
    vector = {}
    for index, count in counts.items():
        weight = idf.get(str(index))
        if weight is not None:
            vector[index] = (1.0 + math.log(count)) * weight
    norm = math.sqrt(sum(v * v for v in vector.values()))
    if len(vector) < 4 or norm == 0:
        return None

    scores = model["bias"][:]
    for index, value in vector.items():
        value /= norm
        for class_index, weights in enumerate(model["weights"]):
            coefficient = weights.get(str(index))
            if coefficient is not None:
                scores[class_index] += coefficient * value
    peak = max(scores)
    exp_scores = [math.exp(max(-40.0, min(40.0, score - peak))) for score in scores]
    total = sum(exp_scores)
    probabilities = [p / total for p in exp_scores]
    labels = model["classes"]
    prediction = labels[max(range(len(labels)), key=probabilities.__getitem__)]
    smishing = probabilities[labels.index("smishing")]
    return {
        "probability": round(smishing * 100),
        "category": prediction,
        "classProbabilities": {label: round(p * 100) for label, p in zip(labels, probabilities)},
        "evidence": len(vector),
        "modelVersion": model.get("version", "unknown"),
        "trainingExamples": model.get("trainingExamples", 0),
        "validationF1": model.get("validation", {}).get("smishing", {}).get("f1"),
    }
