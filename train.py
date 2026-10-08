#!/usr/bin/env python3
"""
Model Training Pipeline for Hybrid Phishing URL Trap.

Loads phishing URL dataset, validates data, normalizes labels,
extracts cybersecurity lexical features, trains a Random Forest classifier,
evaluates performance metrics, and saves the serialized model and metadata.
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report
)
from sklearn.model_selection import train_test_split

from src.features import extract_features, FEATURE_NAMES

# Default paths
DEFAULT_DATASET_PATHS = [
    PROJECT_ROOT / 'data' / 'phishing_dataset.csv',
    PROJECT_ROOT / 'classifier' / 'data' / 'phishing_dataset.csv'
]
DEFAULT_MODEL_DIR = PROJECT_ROOT / 'models'
DEFAULT_METADATA_PATH = DEFAULT_MODEL_DIR / 'model_metadata.json'
DEFAULT_MODEL_PATH = DEFAULT_MODEL_DIR / 'model.joblib'


def find_dataset_path(custom_path: str = None) -> Path:
    if custom_path and Path(custom_path).exists():
        return Path(custom_path)
    for p in DEFAULT_DATASET_PATHS:
        if p.exists():
            return p
    raise FileNotFoundError(f"Could not find phishing_dataset.csv. Searched: {DEFAULT_DATASET_PATHS}")


def train_model(
    dataset_path: Path = None,
    sample_size: int = 50000,
    random_state: int = 42,
    output_model: Path = DEFAULT_MODEL_PATH,
    output_metadata: Path = DEFAULT_METADATA_PATH
):
    print("=" * 60)
    print(" Hybrid Phishing URL Trap - Model Training Pipeline ")
    print("=" * 60)

    dataset_file = find_dataset_path(dataset_path)
    print(f"[*] Ingesting dataset from: {dataset_file}")

    # 1. Load Dataset
    t0 = time.time()
    if sample_size and sample_size > 0:
        print(f"[*] Sampling {sample_size:,} rows for reproducible training...")
        df = pd.read_csv(dataset_file, nrows=sample_size, low_memory=False)
    else:
        print("[*] Loading full dataset...")
        df = pd.read_csv(dataset_file, low_memory=False)
    print(f"[+] Loaded {len(df):,} records in {time.time() - t0:.2f}s")

    # 2. Validate Required Columns
    if 'URL' not in df.columns or 'label' not in df.columns:
        raise ValueError(f"Dataset must contain 'URL' and 'label' columns. Found: {list(df.columns)}")

    # 3. Clean Data
    initial_count = len(df)
    df = df.dropna(subset=['URL', 'label'])
    df = df[df['URL'].astype(str).str.strip() != '']
    cleaned_count = len(df)
    print(f"[*] Data cleaning: {cleaned_count:,} valid rows (dropped {initial_count - cleaned_count:,} invalid rows)")

    # 4. Normalize Labels
    # In phishing_dataset.csv: 0 is Phishing, 1 is Legitimate.
    # We normalize to standard cyber convention: 1 = Phishing (positive target class), 0 = Safe/Legitimate.
    raw_labels = df['label'].astype(int)
    y = (raw_labels == 0).astype(int)
    phishing_count = int(y.sum())
    safe_count = int((y == 0).sum())
    print(f"[*] Label distribution: {phishing_count:,} Phishing (class 1) | {safe_count:,} Safe (class 0)")

    # 5. Extract Features
    print(f"[*] Extracting {len(FEATURE_NAMES)} lexical features across all URLs...")
    t_feat = time.time()
    features_list = [extract_features(u) for u in df['URL']]
    X = pd.DataFrame(features_list)[FEATURE_NAMES]
    print(f"[+] Feature extraction completed in {time.time() - t_feat:.2f}s")

    # 6. Stratified Train/Test Split
    print("[*] Splitting dataset (80% train / 20% test with stratification)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=random_state, stratify=y
    )
    print(f"[+] Train set: {len(X_train):,} samples | Test set: {len(X_test):,} samples")

    # 7. Train Classifier
    print("[*] Training RandomForestClassifier (n_estimators=100)...")
    t_train = time.time()
    clf = RandomForestClassifier(n_estimators=100, random_state=random_state, n_jobs=-1)
    clf.fit(X_train, y_train)
    print(f"[+] Model training completed in {time.time() - t_train:.2f}s")

    # 8. Evaluate Classifier
    print("[*] Evaluating model on unseen test set...")
    y_pred = clf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    cm = confusion_matrix(y_test, y_pred).tolist()
    report_dict = classification_report(y_test, y_pred, target_names=['SAFE', 'PHISHING'], output_dict=True)
    report_text = classification_report(y_test, y_pred, target_names=['SAFE', 'PHISHING'])

    print("\n" + "=" * 50)
    print(" MODEL EVALUATION METRICS ")
    print("=" * 50)
    print(f" Accuracy : {acc * 100:.2f}%")
    print(f" Precision: {prec * 100:.2f}%")
    print(f" Recall   : {rec * 100:.2f}%")
    print(f" F1-Score : {f1 * 100:.2f}%")
    print("\nConfusion Matrix [ [TN, FP], [FN, TP] ]:")
    print(np.array(cm))
    print("\nClassification Report:\n" + report_text)
    print("=" * 50 + "\n")

    # 9. Save Model and Metadata
    output_model.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(clf, output_model)
    print(f"[+] Model successfully saved to: {output_model}")

    # Also keep classifier/model.joblib synchronized
    legacy_model_path = PROJECT_ROOT / 'classifier' / 'model.joblib'
    if legacy_model_path != output_model:
        legacy_model_path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(clf, legacy_model_path)
        print(f"[+] Synced model to legacy path: {legacy_model_path}")

    # Feature importances
    importances = {name: round(float(imp), 4) for name, imp in zip(FEATURE_NAMES, clf.feature_importances_)}
    sorted_importances = sorted(importances.items(), key=lambda x: x[1], reverse=True)

    metadata = {
        "version": "1.0.0",
        "trained_at": datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%SZ'),
        "algorithm": "RandomForestClassifier(n_estimators=100)",
        "random_state": random_state,
        "sample_size": len(df),
        "train_samples": len(X_train),
        "test_samples": len(X_test),
        "feature_names": FEATURE_NAMES,
        "label_mapping": {
            "0": "SAFE",
            "1": "PHISHING"
        },
        "metrics": {
            "accuracy": round(acc, 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1_score": round(f1, 4),
            "confusion_matrix": cm,
            "classification_report": report_dict
        },
        "feature_importances": dict(sorted_importances)
    }

    output_metadata.parent.mkdir(parents=True, exist_ok=True)
    with open(output_metadata, 'w', encoding='utf-8') as f:
        json.dump(metadata, f, indent=2)
    print(f"[+] Model metadata saved to: {output_metadata}")

    # Also sync metadata to legacy path
    legacy_meta_path = PROJECT_ROOT / 'classifier' / 'model_metadata.json'
    with open(legacy_meta_path, 'w', encoding='utf-8') as f:
        json.dump(metadata, f, indent=2)

    return clf, metadata


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Train ML Phishing URL Classifier")
    parser.add_argument('--dataset', type=str, default=None, help="Path to phishing_dataset.csv")
    parser.add_argument('--sample-size', type=int, default=50000, help="Number of rows to sample (0 for full dataset)")
    parser.add_argument('--random-state', type=int, default=42, help="Random seed for reproducibility")
    args = parser.parse_args()

    train_model(
        dataset_path=args.dataset,
        sample_size=args.sample_size,
        random_state=args.random_state
    )
