#!/usr/bin/env python3
"""
Legacy entrypoint for classifier/inference.py.
Forwards to the unified inference engine.
"""
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from inference import classify_url, main
from src.classifier import predict_url

if __name__ == "__main__":
    main()
