"""
Tests for URL feature extraction module.
"""

import pytest
from src.features import extract_features, calculate_entropy, FEATURE_NAMES, SUSPICIOUS_KEYWORDS


def test_calculate_entropy():
    # Identical repeated characters have zero entropy
    assert calculate_entropy("aaaaaa") == 0.0
    # Diverse string has positive entropy
    assert calculate_entropy("abcdef123456!@#$") > 3.0
    # Empty string returns 0.0
    assert calculate_entropy("") == 0.0


def test_extract_features_valid_url():
    url = "https://www.example.com/login?user=admin&token=xyz"
    feats = extract_features(url)

    # Check all expected feature keys are present
    for key in FEATURE_NAMES:
        assert key in feats, f"Missing feature key: {key}"

    assert feats['has_https'] == 1
    assert feats['has_suspicious_keyword'] == 1
    assert feats['num_question_marks'] == 1
    assert feats['num_equals'] == 2
    assert feats['num_ampersands'] == 1
    assert feats['is_ip'] == 0


def test_extract_features_ip_address():
    url = "http://192.168.1.100/admin"
    feats = extract_features(url)

    assert feats['is_ip'] == 1
    assert feats['has_https'] == 0
    assert feats['path_depth'] == 1
    assert feats['num_subdomains'] == 0


def test_extract_features_url_shortener():
    url = "http://bit.ly/3xY8aQ"
    feats = extract_features(url)

    assert feats['is_shortened'] == 1


def test_extract_features_with_at_symbol():
    url = "http://legit.com@phishing-target.net/signin"
    feats = extract_features(url)

    assert feats['has_at'] == 1
    assert feats['has_suspicious_keyword'] == 1


def test_extract_features_malformed_url():
    # Must not raise an exception
    feats1 = extract_features("ht!tp://:::bad-url???")
    assert isinstance(feats1, dict)

    feats2 = extract_features("")
    assert isinstance(feats2, dict)
    assert feats2['length'] == 0

    feats3 = extract_features(None)
    assert isinstance(feats3, dict)
