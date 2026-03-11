"""Lightweight ML classifier for secret detection"""

from typing import List, Optional
from sklearn.ensemble import RandomForestClassifier
import numpy as np

from secretguard.ml.features import extract_features
from secretguard.ml.training_data import TRAINING_DATA


class SecretClassifier:
    """Random Forest classifier for secret vs non-secret strings"""

    def __init__(self):
        self._model: Optional[RandomForestClassifier] = None
        self._feature_names: List[str] = []

    @property
    def is_trained(self) -> bool:
        return self._model is not None

    def train(self, extra_data: Optional[List[tuple]] = None) -> None:
        """Train the classifier on built-in + optional extra data."""
        data = list(TRAINING_DATA)
        if extra_data:
            data.extend(extra_data)

        X, y = [], []
        for text, label in data:
            feats = extract_features(text)
            X.append(list(feats.values()))
            y.append(label)
            if not self._feature_names:
                self._feature_names = list(feats.keys())

        self._model = RandomForestClassifier(n_estimators=50, random_state=42, max_depth=5)
        self._model.fit(np.array(X), np.array(y))

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
