"""Lightweight ML classifier for secret detection with disk caching"""

import hashlib
from pathlib import Path
from typing import List, Optional

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedKFold, cross_validate
import numpy as np
import joblib

from secretguard.ml.features import extract_features
from secretguard.ml.training_data import TRAINING_DATA

CACHE_DIR = Path.home() / ".cache" / "secretguard" / "models"


def _data_hash(data: list) -> str:
    """Hash training data to create a cache key."""
    raw = str(sorted(data, key=lambda x: x[0])).encode()
    return hashlib.sha256(raw).hexdigest()[:16]


class SecretClassifier:
    """Random Forest classifier for secret vs non-secret strings"""

    def __init__(self):
        self._model: Optional[RandomForestClassifier] = None
        self._feature_names: List[str] = []

    @property
    def is_trained(self) -> bool:
        return self._model is not None

    def train(self, extra_data: Optional[List[tuple]] = None) -> None:
        """Train the classifier on built-in + optional extra data, using disk cache."""
        data = list(TRAINING_DATA)
        if extra_data:
            data.extend(extra_data)

        # Check cache
        h = _data_hash(data)
        cache_path = CACHE_DIR / f"rf_{h}.joblib"
        if cache_path.exists():
            self._model = joblib.load(cache_path)
            # Recover feature names from a sample
            feats = extract_features(data[0][0])
            self._feature_names = list(feats.keys())
            return

        X, y = [], []
        for text, label in data:
            feats = extract_features(text)
            X.append(list(feats.values()))
            y.append(label)
            if not self._feature_names:
                self._feature_names = list(feats.keys())

        self._model = RandomForestClassifier(n_estimators=50, random_state=42, max_depth=5)
        self._model.fit(np.array(X), np.array(y))

        # Save to cache
        try:
            CACHE_DIR.mkdir(parents=True, exist_ok=True)
            joblib.dump(self._model, cache_path)
        except OSError:
            pass  # Cache write failure is non-fatal

    def predict(self, candidate: str) -> Optional[float]:
        """Return probability that candidate is a secret (0.0-1.0), or None if not trained."""
        if not self.is_trained:
            return None
        feats = extract_features(candidate)
        X = np.array([list(feats.values())])
        return float(self._model.predict_proba(X)[0][1])

    def predict_batch(self, candidates: List[str]) -> List[float]:
        """Predict multiple candidates at once."""
        if not self.is_trained:
            return []
        X = np.array([list(extract_features(c).values()) for c in candidates])
        return [float(p) for p in self._model.predict_proba(X)[:, 1]]

    def evaluate(self) -> dict:
        """Run 5-fold stratified cross-validation and return metrics."""
        data = list(TRAINING_DATA)
        X, y = [], []
        for text, label in data:
            feats = extract_features(text)
            X.append(list(feats.values()))
            y.append(label)

        X_arr, y_arr = np.array(X), np.array(y)
        model = RandomForestClassifier(n_estimators=50, random_state=42, max_depth=5)
        cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
        scoring = ["precision", "recall", "f1", "accuracy"]
        results = cross_validate(model, X_arr, y_arr, cv=cv, scoring=scoring)

        return {
            "precision": float(np.mean(results["test_precision"])),
            "recall": float(np.mean(results["test_recall"])),
            "f1": float(np.mean(results["test_f1"])),
            "accuracy": float(np.mean(results["test_accuracy"])),
        }

    @classmethod
    def clear_cache(cls) -> None:
        """Remove all cached models."""
        if CACHE_DIR.exists():
            for f in CACHE_DIR.glob("rf_*.joblib"):
                f.unlink()
