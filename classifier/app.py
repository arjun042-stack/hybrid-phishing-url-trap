#!/usr/bin/env python3
"""
Legacy entrypoint for classifier/app.py.
Forwards execution to the unified application in root app.py.
"""
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app import create_app

if __name__ == '__main__':
    app = create_app()
    app.run(host='127.0.0.1', port=5000, debug=True)
