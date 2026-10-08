"""
Vercel Serverless Entrypoint for Hybrid Phishing URL Trap.

Exposes the root Flask application (`app.py`) for Vercel Serverless Functions.
Ensures project root is on the Python path and configures Vercel deployment mode.
"""

import os
import sys
from pathlib import Path

# Ensure project root directory is on Python path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Default deployment mode to vercel if not explicitly specified
os.environ.setdefault('DEPLOYMENT_MODE', 'vercel')

# Import the existing Flask application instance
from app import app
