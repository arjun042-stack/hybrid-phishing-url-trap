"""
Machine Learning Phishing URL Classifier Engine.

Handles model loading, feature alignment, prediction, confidence scoring,
and risk level classification for the Hybrid Phishing URL Trap.
"""

import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional
from urllib.parse import urlparse

import joblib
import pandas as pd

from src.features import extract_features, FEATURE_NAMES, LEGACY_FEATURE_NAMES

logger = logging.getLogger(__name__)

# Search paths for trained model file
DEFAULT_MODEL_PATHS = [
    Path(__file__).resolve().parent.parent / 'models' / 'model.joblib',
    Path(__file__).resolve().parent.parent / 'classifier' / 'model.joblib',
    Path(__file__).resolve().parent.parent / 'model.joblib'
]

DEFAULT_METADATA_PATHS = [
    Path(__file__).resolve().parent.parent / 'models' / 'model_metadata.json',
    Path(__file__).resolve().parent.parent / 'classifier' / 'model_metadata.json',
    Path(__file__).resolve().parent.parent / 'model_metadata.json'
]

# High-reputation apex domains (top trusted anchors in cybersecurity defense)
TRUSTED_APEX_DOMAINS = {
    'google.com', 'google.co.in', 'youtube.com', 'microsoft.com', 'apple.com',
    'github.com', 'wikipedia.org', 'amazon.com', 'cloudflare.com', 'gov.in',
    'edu', 'gov', 'mil', 'ac.uk', 'edu.au', 'mit.edu', 'stanford.edu', 'harvard.edu'
}


def is_trusted_domain(hostname: str) -> bool:
    """Check if the domain is an authoritative high-reputation domain without subdomain spoofing."""
    if not hostname:
        return False
    host = hostname.lower().strip()
    # Strip leading www.
    if host.startswith('www.'):
        host = host[4:]
    if host in TRUSTED_APEX_DOMAINS:
        return True
    for trusted in TRUSTED_APEX_DOMAINS:
        if host.endswith('.' + trusted) and host.count('.') == trusted.count('.') + 1:
            return True
    return False


class URLClassifier:
    """Manages phishing classification using a trained scikit-learn model."""

    def __init__(self, model_path: Optional[Path] = None, metadata_path: Optional[Path] = None):
        self.model = None
        self.metadata = {}
        self.model_path = None
        self.feature_names = []
        self._load_model(model_path, metadata_path)

    def _load_model(self, model_path: Optional[Path] = None, metadata_path: Optional[Path] = None):
        target_model = None
        if model_path and Path(model_path).exists():
            target_model = Path(model_path)
        else:
            for p in DEFAULT_MODEL_PATHS:
                if p.exists():
                    target_model = p
                    break

        if target_model and target_model.exists():
            try:
                self.model = joblib.load(target_model)
                self.model_path = target_model
                logger.info("Successfully loaded model from %s", target_model)
            except Exception as e:
                logger.error("Failed to load model from %s: %s", target_model, e)
                self.model = None

        # Load metadata if present
        target_meta = None
        if metadata_path and Path(metadata_path).exists():
            target_meta = Path(metadata_path)
        else:
            for mp in DEFAULT_METADATA_PATHS:
                if mp.exists():
                    target_meta = mp
                    break

        if target_meta and target_meta.exists():
            try:
                with open(target_meta, 'r', encoding='utf-8') as f:
                    self.metadata = json.load(f)
            except Exception as e:
                logger.warning("Could not read model metadata from %s: %s", target_meta, e)

        # Determine expected feature names
        if hasattr(self.model, 'feature_names_in_') and self.model.feature_names_in_ is not None:
            self.feature_names = list(self.model.feature_names_in_)
        elif 'feature_names' in self.metadata:
            self.feature_names = self.metadata['feature_names']
        elif hasattr(self.model, 'n_features_in_') and self.model.n_features_in_ == 6:
            self.feature_names = LEGACY_FEATURE_NAMES
        else:
            self.feature_names = FEATURE_NAMES

    @property
    def is_loaded(self) -> bool:
        return self.model is not None

    def predict_url(self, url: str) -> Dict[str, Any]:
        """
        Classify a single URL and return structured threat intelligence.
        Guaranteed not to crash on malformed inputs or missing models.
        """
        if not isinstance(url, str) or not url.strip():
            return {
                "url": str(url or ""),
                "prediction": "INVALID",
                "confidence": 0.0,
                "risk_level": "UNKNOWN",
                "features": {},
                "model_version": self.metadata.get("version", "1.0.0"),
                "error": "URL cannot be empty."
            }

        url_clean = url.strip()
        features = extract_features(url_clean)

        # Extract hostname for domain reputation check
        parsed_url = urlparse(url_clean if '://' in url_clean else 'http://' + url_clean)
        hostname = (parsed_url.hostname or '').lower()

        # Fallback heuristic if model is not loaded
        if not self.is_loaded:
            is_suspicious = (
                features['is_ip'] == 1 or
                features['has_suspicious_keyword'] == 1 or
                features['is_shortened'] == 1 or
                features['has_at'] == 1
            )
            prediction = "SUSPICIOUS" if is_suspicious else "SAFE"
            return {
                "url": url_clean,
                "prediction": prediction,
                "confidence": 0.50,
                "risk_level": "MEDIUM" if is_suspicious else "LOW",
                "features": features,
                "model_version": "heuristic-fallback",
                "warning": "ML model file not loaded. Running in heuristic fallback mode."
            }

        try:
            # Align features with expected model input
            feature_subset = {k: features.get(k, 0) for k in self.feature_names}
            df_input = pd.DataFrame([feature_subset])

            # Predict probabilities
            if hasattr(self.model, 'predict_proba'):
                probs = self.model.predict_proba(df_input)[0]
                classes = list(self.model.classes_)
                # Robust check index for malicious class (1, '1', 'phishing', etc.)
                phishing_idx = None
                for candidate in (1, '1', True, 'phishing', 'malicious'):
                    if candidate in classes:
                        phishing_idx = classes.index(candidate)
                        break
                if phishing_idx is None:
                    str_classes = [str(c).lower() for c in classes]
                    if '1' in str_classes:
                        phishing_idx = str_classes.index('1')
                    elif 'phishing' in str_classes:
                        phishing_idx = str_classes.index('phishing')
                    else:
                        phishing_idx = min(1, len(probs) - 1)
                phishing_prob = float(probs[phishing_idx]) if phishing_idx < len(probs) else 0.5
            else:
                raw_pred = self.model.predict(df_input)[0]
                phishing_prob = 1.0 if str(raw_pred) == '1' else 0.0

            # If apex domain is known top trusted authority and has no deceptive path/IP/at
            if is_trusted_domain(hostname) and features['is_ip'] == 0 and features['has_at'] == 0:
                phishing_prob = min(phishing_prob, 0.05)

            # Determine risk category and prediction
            # Thresholds:
            # >= 0.65 -> PHISHING (HIGH)
            # 0.35 to 0.65 -> SUSPICIOUS (MEDIUM)
            # < 0.35 -> SAFE (LOW)
            if phishing_prob >= 0.65:
                prediction = "PHISHING"
                risk_level = "HIGH"
                confidence = round(phishing_prob, 4)
            elif phishing_prob >= 0.35:
                prediction = "SUSPICIOUS"
                risk_level = "MEDIUM"
                confidence = round(phishing_prob, 4)
            else:
                prediction = "SAFE"
                risk_level = "LOW"
                confidence = round(1.0 - phishing_prob, 4)

            # Extra heuristics check: IP address as hostname or @ in URL with high entropy
            if features['is_ip'] == 1 or (features['has_at'] == 1 and features['num_dots'] > 2):
                if prediction == "SAFE":
                    prediction = "SUSPICIOUS"
                    risk_level = "MEDIUM"
                    confidence = 0.60

            return {
                "url": url_clean,
                "prediction": prediction,
                "confidence": confidence,
                "risk_level": risk_level,
                "phishing_probability": round(phishing_prob, 4),
                "features": features,
                "model_version": self.metadata.get("version", "1.0.0")
            }

        except Exception as e:
            logger.error("Error during prediction for URL '%s': %s", url_clean, e)
            return {
                "url": url_clean,
                "prediction": "ERROR",
                "confidence": 0.0,
                "risk_level": "UNKNOWN",
                "features": features,
                "model_version": self.metadata.get("version", "1.0.0"),
                "error": f"Prediction error: {str(e)}"
            }


# Global singleton instance for clean re-use
_classifier_instance: Optional[URLClassifier] = None


def get_classifier(model_path: Optional[Path] = None) -> URLClassifier:
    """Get or initialize the global URLClassifier instance."""
    global _classifier_instance
    if _classifier_instance is None or model_path is not None:
        _classifier_instance = URLClassifier(model_path=model_path)
    return _classifier_instance


def predict_url(url: str, model_path: Optional[Path] = None) -> Dict[str, Any]:
    """Convenience function matching the project specification."""
    classifier = get_classifier(model_path=model_path)
    return classifier.predict_url(url)
