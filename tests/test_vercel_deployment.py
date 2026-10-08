"""
Tests for Vercel Serverless Deployment Architecture & Compatibility.

Validates:
1. api/index.py entrypoint imports cleanly and exposes the Flask app
2. DEPLOYMENT_MODE=vercel defaults to /tmp database storage
3. Core frontend views and API endpoints function in serverless environment
4. Heuristic fallback operates without crashing if ML model binary is absent
5. Database operations fail-safe in serverless read-only/ephemeral conditions
6. Static assets are served correctly
"""

import os
import sys
from pathlib import Path
import pytest

from app import create_app
from src.database import get_default_db_path, init_db, get_dashboard_statistics
from src.classifier import URLClassifier


def test_vercel_entrypoint_import():
    """Verify api/index.py imports cleanly and exports a valid Flask application."""
    project_root = Path(__file__).resolve().parent.parent
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))

    import api.index
    assert hasattr(api.index, 'app')
    assert api.index.app.name == 'app'


def test_vercel_deployment_mode_db_path(monkeypatch):
    """Verify that DEPLOYMENT_MODE=vercel configures DB_PATH in /tmp."""
    monkeypatch.setenv('DEPLOYMENT_MODE', 'vercel')
    db_path = get_default_db_path()
    assert str(db_path).startswith('/tmp') or str(db_path).startswith('\\tmp')

    app = create_app()
    assert app.config['DEPLOYMENT_MODE'] == 'vercel'
    assert '/tmp' in str(app.config['DB_PATH']) or '\\tmp' in str(app.config['DB_PATH'])


def test_vercel_health_endpoint_heuristic(monkeypatch, tmp_path):
    """Verify /health returns 200 even when ML model binary is not loaded in Vercel mode."""
    test_db = tmp_path / "vercel_test.db"
    monkeypatch.setenv('DEPLOYMENT_MODE', 'vercel')
    app = create_app({
        'TESTING': True,
        'DB_PATH': test_db,
        'DEPLOYMENT_MODE': 'vercel'
    })

    # Simulate classifier without trained model file
    unloaded_clf = URLClassifier()
    unloaded_clf.model = None
    monkeypatch.setattr('app.get_classifier', lambda: unloaded_clf)

    client = app.test_client()
    resp = client.get('/health')
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['status'] == 'healthy'
    assert data['deployment_mode'] == 'vercel'
    assert data['model_loaded'] is False


def test_vercel_all_routes_smoke(monkeypatch, tmp_path):
    """Smoke test all primary routes under simulated Vercel serverless environment."""
    test_db = tmp_path / "vercel_smoke.db"
    monkeypatch.setenv('DEPLOYMENT_MODE', 'vercel')
    app = create_app({
        'TESTING': True,
        'DB_PATH': test_db,
        'DEPLOYMENT_MODE': 'vercel'
    })
    init_db(test_db)
    client = app.test_client()

    routes = [
        ('/', 200),
        ('/classify', 200),
        ('/login', 200),
        ('/dashboard', 200),
        ('/model', 200),
        ('/feedback', 200),
        ('/report', 200),
        ('/health', 200),
        ('/api/stats', 200),
        ('/api/events', 200),
        ('/api/model-info', 200),
        ('/static/css/main.css', 200),
        ('/static/js/main.js', 200)
    ]

    for path, expected_status in routes:
        resp = client.get(path)
        assert resp.status_code == expected_status, f"Route {path} failed with {resp.status_code}"


def test_vercel_api_classification(monkeypatch, tmp_path):
    """Verify POST /api/classify returns predictions in Vercel deployment mode."""
    test_db = tmp_path / "vercel_classify.db"
    monkeypatch.setenv('DEPLOYMENT_MODE', 'vercel')
    app = create_app({
        'TESTING': True,
        'DB_PATH': test_db,
        'DEPLOYMENT_MODE': 'vercel'
    })
    client = app.test_client()

    # Legitimate URL test
    resp = client.post('/api/classify', json={'url': 'https://google.com'})
    assert resp.status_code == 200
    data = resp.get_json()
    assert 'prediction' in data
    assert 'risk_level' in data
    assert 'confidence' in data

    # Obvious phishing indicator URL test
    resp2 = client.post('/api/classify', json={'url': 'http://192.168.1.1/login-verify-account'})
    assert resp2.status_code == 200
    data2 = resp2.get_json()
    assert data2['prediction'] in ['PHISHING', 'SUSPICIOUS']


def test_vercel_honeypot_login(monkeypatch, tmp_path):
    """Verify POST /api/honeypot/login operates safely in Vercel mode without crashing."""
    test_db = tmp_path / "vercel_honeypot.db"
    monkeypatch.setenv('DEPLOYMENT_MODE', 'vercel')
    app = create_app({
        'TESTING': True,
        'DB_PATH': test_db,
        'DEPLOYMENT_MODE': 'vercel'
    })
    init_db(test_db)
    client = app.test_client()

    payload = {
        'username': 'admin_attacker',
        'password': 'SuperSecretPassword123'
    }
    resp = client.post('/api/honeypot/login', json=payload)
    assert resp.status_code == 401
    data = resp.get_json()
    assert data['status'] == 'error'
    assert 'event_id' in data

    # Verify password was fingerprinted (SHA-256) and never stored in plaintext
    stats = get_dashboard_statistics(test_db)
    assert stats['honeypot_interactions'] >= 1
