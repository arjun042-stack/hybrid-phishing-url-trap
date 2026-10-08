#!/usr/bin/env python3
"""
CLI & Module Inference Engine for Hybrid Phishing URL Trap.

Loads trained model and provides structured phishing classification
and risk assessments for URLs.
"""

import json
import sys
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.classifier import predict_url, get_classifier


def classify_url(url: str) -> str:
    """
    Backwards-compatible string prediction function.
    Returns: 'MALICIOUS' or 'SAFE' (or 'SUSPICIOUS').
    """
    res = predict_url(url)
    pred = res.get('prediction', 'SAFE')
    if pred == 'PHISHING':
        return 'MALICIOUS'
    elif pred == 'SUSPICIOUS':
        return 'SUSPICIOUS'
    return 'SAFE'


def main():
    if len(sys.argv) < 2:
        print("Usage: python inference.py <URL>")
        print("Example: python inference.py https://example.com")
        sys.exit(1)

    url = sys.argv[1]
    result = predict_url(url)

    print("\n" + "=" * 55)
    print(" URL THREAT CLASSIFICATION REPORT ")
    print("=" * 55)
    print(f" Target URL     : {result.get('url')}")
    print(f" Prediction     : {result.get('prediction')}")
    print(f" Risk Level     : {result.get('risk_level')}")
    print(f" Confidence     : {result.get('confidence', 0.0) * 100:.2f}%")
    if 'phishing_probability' in result:
        print(f" Phishing Prob  : {result.get('phishing_probability', 0.0) * 100:.2f}%")
    print("-" * 55)
    print(" Extracted Features:")
    for k, v in result.get('features', {}).items():
        print(f"   - {k:<25}: {v}")
    print("=" * 55 + "\n")


if __name__ == '__main__':
    main()
