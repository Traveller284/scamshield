"""Train and evaluate the bundled ScamShield SMS model.

Usage (from this directory):
  python train_ml_model.py --mendeley path/to/Dataset_5971.csv --uci path/to/SMSSpamCollection

Training requires NumPy. It writes only the compressed model artifact and a
metrics report; source messages are never copied into the app or repository.
"""
from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import json
import math
import random
import re
import unicodedata
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np

BUCKETS = 1 << 18
CLASSES = ("ham", "spam", "smishing")
TOKEN_RE = re.compile(r"\w+", re.UNICODE)
SEED = 20261126


def hash_feature(value: str) -> int:
    h = 2166136261
    for byte in value.encode("utf-8", "ignore"):
        h = ((h ^ byte) * 16777619) & 0xFFFFFFFF
    return h & (BUCKETS - 1)


def feature_counts(text: str) -> Counter[int]:
    value = str(text).lower()
    tokens = TOKEN_RE.findall(value)
    counts: Counter[int] = Counter()
    for i, token in enumerate(tokens):
        if len(token) >= 2:
            counts[hash_feature("w:" + token)] += 1
        if i and len(tokens[i - 1]) >= 2 and len(token) >= 2:
            counts[hash_feature("b:" + tokens[i - 1] + "_" + token)] += 1
    for chunk in value.split():
        padded = " " + chunk + " "
        for width in (3, 4, 5):
            for i in range(max(0, len(padded) - width + 1)):
                counts[hash_feature("c:" + padded[i:i + width])] += 1
    return counts


def canonical(text: str) -> str:
    text = unicodedata.normalize("NFKC", str(text)).casefold()
    return " ".join(text.split())


def load_rows(mendeley: Path, uci: Path):
    # Prefer Mendeley's more detailed label whenever corpora overlap.
    rows = {}
    with mendeley.open("r", encoding="utf-8-sig", newline="") as stream:
        for item in csv.DictReader(stream):
            label = item.get("LABEL", "").strip().lower()
            text = item.get("TEXT", "").strip()
            if label in CLASSES and text:
                rows[canonical(text)] = (2, label, text)
    with uci.open("r", encoding="latin-1") as stream:
        for line in stream:
            label, sep, text = line.rstrip("\r\n").partition("\t")
            label = {"ham": "ham", "spam": "spam"}.get(label.lower())
            if sep and label and text.strip():
                key = canonical(text)
                rows.setdefault(key, (1, label, text.strip()))
    return [(label, text) for _, label, text in rows.values()]


def split_data(rows):
    groups = defaultdict(list)
    for label, text in rows:
        groups[label].append((label, text))
    rng = random.Random(SEED)
    train, valid = [], []
    for label in CLASSES:
        entries = groups[label]
        rng.shuffle(entries)
        cut = max(1, int(len(entries) * 0.8))
        train.extend(entries[:cut])
        valid.extend(entries[cut:])
    rng.shuffle(train)
    rng.shuffle(valid)
    return train, valid


def vectorize(rows, idf=None):
    raw = [feature_counts(text) for _, text in rows]
    if idf is None:
        df = Counter(index for counts in raw for index in counts)
        idf = {index: math.log((1 + len(rows)) / (1 + freq)) + 1.0 for index, freq in df.items()}
    vectors = []
    for counts in raw:
        values = {index: (1.0 + math.log(count)) * idf[index]
                  for index, count in counts.items() if index in idf}
        norm = math.sqrt(sum(value * value for value in values.values())) or 1.0
        indices = np.fromiter(values.keys(), dtype=np.int32)
        data = np.fromiter((value / norm for value in values.values()), dtype=np.float32)
        vectors.append((indices, data))
    return vectors, idf


def softmax(scores):
    scores = scores - np.max(scores)
    values = np.exp(np.clip(scores, -40, 40))
    return values / np.sum(values)


def fit(rows, epochs=32):
    vectors, idf = vectorize(rows)
    weights = np.zeros((len(CLASSES), BUCKETS), dtype=np.float32)
    bias = np.zeros(len(CLASSES), dtype=np.float32)
    labels = np.array([CLASSES.index(label) for label, _ in rows], dtype=np.int32)
    rng = random.Random(SEED)
    learning_rate = 0.12
    regularization = 0.00008
    for epoch in range(epochs):
        order = list(range(len(rows)))
        rng.shuffle(order)
        lr = learning_rate / (1.0 + 0.035 * epoch)
        for row_index in order:
            indices, values = vectors[row_index]
            probs = softmax(bias + weights[:, indices] @ values)
            probs[labels[row_index]] -= 1.0
            weights[:, indices] *= (1.0 - lr * regularization)
            weights[:, indices] -= lr * probs[:, None] * values[None, :]
            bias -= lr * probs
    return weights, bias, idf


def predict(vector, weights, bias):
    indices, values = vector
    return softmax(bias + weights[:, indices] @ values)


def evaluate(rows, vectors, weights, bias):
    confusion = {label: {other: 0 for other in CLASSES} for label in CLASSES}
    for (actual, _), vector in zip(rows, vectors):
        scores = predict(vector, weights, bias)
        guess = CLASSES[int(np.argmax(scores))]
        confusion[actual][guess] += 1
    report = {}
    for label in CLASSES:
        tp = confusion[label][label]
        fp = sum(confusion[other][label] for other in CLASSES if other != label)
        fn = sum(confusion[label][other] for other in CLASSES if other != label)
        precision = tp / max(1, tp + fp)
        recall = tp / max(1, tp + fn)
        report[label] = {"precision": round(precision, 4), "recall": round(recall, 4),
                         "f1": round(2 * precision * recall / max(1e-12, precision + recall), 4),
                         "support": sum(confusion[label].values())}
    total = sum(sum(row.values()) for row in confusion.values())
    correct = sum(confusion[label][label] for label in CLASSES)
    report["accuracy"] = round(correct / max(1, total), 4)
    report["macro_f1"] = round(sum(report[label]["f1"] for label in CLASSES) / len(CLASSES), 4)
    report["confusion"] = confusion
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mendeley", type=Path, required=True, help="Mendeley Dataset_5971.csv")
    parser.add_argument("--uci", type=Path, required=True, help="UCI SMSSpamCollection TSV")
    parser.add_argument("--output", type=Path, default=Path("ml_model.json.gz"))
    parser.add_argument("--epochs", type=int, default=32)
    args = parser.parse_args()

    rows = load_rows(args.mendeley, args.uci)
    train, valid = split_data(rows)
    weights, bias, idf = fit(train, args.epochs)
    valid_vectors, _ = vectorize(valid, idf)
    report = evaluate(valid, valid_vectors, weights, bias)

    # Refit on all unique examples after the honest held-out evaluation.
    weights, bias, idf = fit(rows, args.epochs)
    artifact = {
        "version": "2026.11.1",
        "classes": list(CLASSES),
        "features": "hashed word 1-2 grams + character 3-5 grams; TF-IDF; multinomial logistic SGD",
        "trainingExamples": len(rows),
        "buckets": BUCKETS,
        "idf": {str(index): round(value, 7) for index, value in idf.items()},
        "bias": [round(float(value), 8) for value in bias],
        "weights": [
            {str(index): round(float(value), 8) for index, value in enumerate(row) if abs(float(value)) > 1e-7}
            for row in weights
        ],
        "validation": report,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(args.output, "wt", encoding="utf-8", compresslevel=9) as out:
        json.dump(artifact, out, separators=(",", ":"))
    metrics_path = args.output.with_suffix(".metrics.json")
    metrics_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    digest = hashlib.sha256(args.output.read_bytes()).hexdigest()
    print(json.dumps({"examples": len(rows), "train": len(train), "validation": len(valid),
                      "labels": dict(Counter(label for label, _ in rows)),
                      "metrics": report, "model_bytes": args.output.stat().st_size,
                      "sha256": digest}, indent=2))


if __name__ == "__main__":
    main()
