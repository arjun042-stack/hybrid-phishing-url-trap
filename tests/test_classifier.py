"""
Tests for ML URL Classifier engine.
"""

import pytest
from src.classifier import get_classifier, predict_url


def test_classifier_loaded():
    classifier = get_classifier()
    assert classifier.is_loaded is True
    assert len(classifier.feature_names) > 0


def test_predict_safe_url():
    res = predict_url("https://www.google.com")
    assert res['prediction'] == "SAFE"
    assert res['risk_level'] == "LOW"
    assert res['confidence'] > 0.5
    assert 'features' in res


def test_predict_phishing_url():
    # Direct IP with authentication keywords
    res = predict_url("http://192.168.1.1/login-verify-account.php")
    assert res['prediction'] in ("PHISHING", "SUSPICIOUS")
    assert res['risk_level'] in ("HIGH", "MEDIUM")
    assert 'phishing_probability' in res


def test_predict_empty_or_invalid():
    res_empty = predict_url("")
    assert res_empty['prediction'] == "INVALID"
    assert "error" in res_empty

    res_none = predict_url(None)
    assert res_none['prediction'] == "INVALID"
