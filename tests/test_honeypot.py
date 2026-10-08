"""
Tests for Honeypot Security & Deception Engine.
"""

from unittest.mock import MagicMock
import pytest
from src.honeypot import assess_honeypot_risk, handle_honeypot_attempt
from src.database import init_db, get_db_connection


@pytest.fixture
def temp_honeypot_db(tmp_path):
    db_file = tmp_path / "test_honeypot_trap.db"
    init_db(db_file)
    return db_file


def test_assess_honeypot_risk_normal():
    req = MagicMock()
    req.headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
    req.path = '/other'
    risk = assess_honeypot_risk(req, username="john_doe", password="secret_password")
    assert 0.0 <= risk <= 0.6


def test_assess_honeypot_risk_scanner():
    req = MagicMock()
    req.headers = {'User-Agent': 'sqlmap/1.5.2#stable'}
    req.path = '/login'
    risk = assess_honeypot_risk(req, username="admin", password="password")
    assert risk >= 0.8


def test_assess_honeypot_risk_injection():
    req = MagicMock()
    req.headers = {'User-Agent': 'curl/7.68.0'}
    req.path = '/admin'
    risk = assess_honeypot_risk(req, username="admin' OR 1=1;--", password="pwd")
    assert risk >= 0.8


def test_handle_honeypot_attempt(temp_honeypot_db, monkeypatch):
    req = MagicMock()
    req.remote_addr = "192.168.1.50"
    req.headers = {'User-Agent': 'TestAttackerBot/1.0', 'Accept-Language': 'en-US'}
    req.path = "/login"
    req.method = "POST"
    req.content_type = "application/x-www-form-urlencoded"
    req.content_length = 42
    req.referrer = "http://phishing-lure.example.com"

    # Patch database default to temp_honeypot_db
    import src.database
    monkeypatch.setattr(src.database, 'DEFAULT_DB_PATH', temp_honeypot_db)

    result = handle_honeypot_attempt(
        request=req,
        username="corporate_admin",
        password="TopSecretAttackerPassword123!",
        route="/login"
    )

    assert result['status'] == 'captured'
    assert 'event_id' in result
    assert result['event_id'] > 0
    assert 'deceptive_message' in result

    # Check database: password MUST NOT be stored in plaintext
    conn = get_db_connection(temp_honeypot_db)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM honeypot_events WHERE id = ?", (result['event_id'],))
    row = dict(cursor.fetchone())
    conn.close()

    assert "TopSecretAttackerPassword123!" not in str(row)
    assert row['username_or_identifier'] == "corporate_admin"
    assert row['source_ip'] == "192.168.1.50"
    assert len(row['password_fingerprint']) == 16
