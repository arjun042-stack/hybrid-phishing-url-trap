#!/usr/bin/env python3
"""
Legacy entrypoint for classifier/train.py.
Forwards execution to root training pipeline.
"""
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from train import train_model

if __name__ == '__main__':
    train_model()
