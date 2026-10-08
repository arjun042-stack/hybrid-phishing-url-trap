"""
Tests for Database layer and telemetry storage.
"""

import os
import tempfile
from pathlib import Path
import pytest

from src.database import (
    init_db, log_honeypot_interaction, log_classification_event,
    get_dashboard_statistics, add_feedback_sample, get_feedback_samples,
    update_feedback_sample_status, get_db_connection
)


@pytest.fixture
def temp_db(tmp_path):
    db_file = tmp_path / "test_honeypot.db"
    init_db(db_file)
    return db_file


def test_init_db(temp_db):
    assert temp_db.exists()
    conn = get_db_connection(temp_db)
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [r[0] for r in cursor.fetchall()]
    conn.close()

    assert "honeypot_events" in tables
    assert "classification_events" in tables
    assert "feedback_samples" in tables
    assert "login_attempt" in tables


def test_log_honeypot_interaction(temp_db):
    event_id = log_honeypot_interaction(
        source_ip="10.0.0.1",
        user_agent="TestScanner/1.0",
        route="/login",
        method="POST",
        username="admin",
        password="super_secret_password",
        db_path=temp_db
    )
    assert event_id > 0

    conn = get_db_connection(temp_db)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM honeypot_events WHERE id = ?", (event_id,))
    row = dict(cursor.fetchone())
    conn.close()

    # Plaintext password must NOT be in honeypot_events
    assert "super_secret_password" not in row.values()
    assert "super_secret_password" not in str(row)
    assert row['password_fingerprint'] != ""
    assert row['username_or_identifier'] == "admin"


def test_log_classification_event(temp_db):
    cid = log_classification_event(
        url="https://test-legit.com",
        prediction="SAFE",
        confidence=0.98,
        risk_level="LOW",
        features={"length": 21},
        source_ip="127.0.0.1",
        db_path=temp_db
    )
    assert cid > 0

    stats = get_dashboard_statistics(temp_db)
    assert stats['total_urls'] == 1
    assert stats['safe_count'] == 1
    assert stats['phishing_count'] == 0


def test_feedback_loop_workflow(temp_db):
    # Add candidate
    added = add_feedback_sample("http://suspicious-test.xyz", suggested_label=1, notes="test", db_path=temp_db)
    assert added is True

    # Duplicate should be rejected safely
    dup = add_feedback_sample("http://suspicious-test.xyz", suggested_label=1, db_path=temp_db)
    assert dup is False

    samples = get_feedback_samples(status="pending", db_path=temp_db)
    assert len(samples) == 1
    sample_id = samples[0]['id']

    # Approve candidate
    updated = update_feedback_sample_status(sample_id, status="approved", reviewer_label=1, db_path=temp_db)
    assert updated is True

    pending = get_feedback_samples(status="pending", db_path=temp_db)
    assert len(pending) == 0

    approved = get_feedback_samples(status="approved", db_path=temp_db)
    assert len(approved) == 1
