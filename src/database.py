"""
Database Module for Hybrid Phishing URL Trap.

Manages SQLite database initialization, schema migration, and safe
parameterized queries for honeypot events, URL classifications, and feedback samples.
"""

import json
import os
import sqlite3
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional

# Default database location relative to project root
DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent / 'instance' / 'honeypot_logs.db'


def hash_identifier(value: str) -> str:
    """Create a secure SHA-256 hash digest for sensitive telemetry such as passwords."""
    if not value:
        return ""
    return hashlib.sha256(value.encode('utf-8', errors='ignore')).hexdigest()[:16]


def get_db_connection(db_path: Optional[Path] = None) -> sqlite3.Connection:
    """Return a sqlite3 connection configured with Row factory."""
    target_path = Path(db_path) if db_path else DEFAULT_DB_PATH
    target_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(target_path))
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: Optional[Path] = None) -> None:
    """Initialize database tables safely if they do not already exist."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    # 1. Backward-compatible login_attempt table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS login_attempt (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            ip VARCHAR(50),
            user_agent VARCHAR(200),
            username VARCHAR(100),
            password VARCHAR(100)
        )
    ''')

    # 2. Comprehensive Honeypot events table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS honeypot_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            event_type VARCHAR(50) NOT NULL,
            source_ip VARCHAR(50),
            user_agent VARCHAR(255),
            route VARCHAR(255),
            request_method VARCHAR(10),
            username_or_identifier VARCHAR(100),
            password_fingerprint VARCHAR(64),
            metadata TEXT,
            risk_score REAL DEFAULT 0.0
        )
    ''')

    # 3. URL Classification events table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS classification_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            url TEXT NOT NULL,
            prediction VARCHAR(20) NOT NULL,
            confidence REAL NOT NULL,
            risk_level VARCHAR(20) NOT NULL,
            features TEXT,
            source_ip VARCHAR(50)
        )
    ''')

    # 4. Controlled Feedback loop table (pending / approved / rejected)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS feedback_samples (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            url TEXT NOT NULL UNIQUE,
            suggested_label INTEGER NOT NULL,
            reviewer_label INTEGER,
            status VARCHAR(20) DEFAULT 'pending',
            notes TEXT
        )
    ''')

    # 5. Model versioning table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS model_versions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            version_tag VARCHAR(50) NOT NULL,
            trained_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            accuracy REAL,
            precision REAL,
            recall REAL,
            f1_score REAL,
            model_path TEXT
        )
    ''')

    conn.commit()
    conn.close()


def log_honeypot_interaction(
    source_ip: str,
    user_agent: str,
    route: str,
    method: str,
    username: str,
    password: str,
    event_type: str = "credential_attempt",
    metadata: Optional[Dict[str, Any]] = None,
    risk_score: float = 0.8,
    db_path: Optional[Path] = None
) -> int:
    """
    Log an attacker honeypot interaction safely.
    NEVER stores plaintext password in honeypot_events; stores SHA-256 fingerprint.
    Also preserves redacted record in legacy login_attempt for compatibility.
    """
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    now_str = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
    pwd_fingerprint = hash_identifier(password)
    meta_json = json.dumps(metadata or {})

    # Insert into honeypot_events
    cursor.execute('''
        INSERT INTO honeypot_events (
            timestamp, event_type, source_ip, user_agent, route,
            request_method, username_or_identifier, password_fingerprint,
            metadata, risk_score
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        now_str, event_type, source_ip[:50], (user_agent or '')[:255],
        route[:255], method[:10], username[:100], pwd_fingerprint,
        meta_json, risk_score
    ))
    event_id = cursor.lastrowid

    # Backward-compatible entry in login_attempt with redacted password
    redacted_pwd = f"[HASH:{pwd_fingerprint[:8]}]"
    cursor.execute('''
        INSERT INTO login_attempt (timestamp, ip, user_agent, username, password)
        VALUES (?, ?, ?, ?, ?)
    ''', (now_str, source_ip[:50], (user_agent or '')[:200], username[:100], redacted_pwd))

    conn.commit()
    conn.close()
    return event_id


def log_classification_event(
    url: str,
    prediction: str,
    confidence: float,
    risk_level: str,
    features: Dict[str, Any],
    source_ip: str = "127.0.0.1",
    db_path: Optional[Path] = None
) -> int:
    """Log an analyzed URL and its ML prediction into classification_events."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    now_str = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
    features_json = json.dumps(features)

    cursor.execute('''
        INSERT INTO classification_events (
            timestamp, url, prediction, confidence, risk_level, features, source_ip
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (now_str, url, prediction, confidence, risk_level, features_json, source_ip[:50]))
    event_id = cursor.lastrowid

    conn.commit()
    conn.close()
    return event_id


def get_dashboard_statistics(db_path: Optional[Path] = None) -> Dict[str, Any]:
    """Retrieve aggregate statistics from the database for the threat dashboard."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    # Classification metrics
    cursor.execute("SELECT COUNT(*) FROM classification_events")
    total_urls = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM classification_events WHERE prediction = 'PHISHING'")
    phishing_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM classification_events WHERE prediction = 'SAFE'")
    safe_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM classification_events WHERE prediction = 'SUSPICIOUS'")
    suspicious_count = cursor.fetchone()[0]

    # Honeypot interactions
    cursor.execute("SELECT COUNT(*) FROM honeypot_events")
    total_honeypot_events = cursor.fetchone()[0]

    # Top attacking IPs
    cursor.execute('''
        SELECT source_ip, COUNT(*) as count
        FROM honeypot_events
        GROUP BY source_ip
        ORDER BY count DESC
        LIMIT 5
    ''')
    top_ips = [dict(row) for row in cursor.fetchall()]

    # Recent honeypot events
    cursor.execute('''
        SELECT id, timestamp, event_type, source_ip, user_agent, route, username_or_identifier, risk_score
        FROM honeypot_events
        ORDER BY id DESC
        LIMIT 10
    ''')
    recent_honeypot = [dict(row) for row in cursor.fetchall()]

    # Recent classification events
    cursor.execute('''
        SELECT id, timestamp, url, prediction, confidence, risk_level, source_ip
        FROM classification_events
        ORDER BY id DESC
        LIMIT 10
    ''')
    recent_classifications = [dict(row) for row in cursor.fetchall()]

    conn.close()

    return {
        'total_urls': total_urls,
        'phishing_count': phishing_count,
        'safe_count': safe_count,
        'suspicious_count': suspicious_count,
        'honeypot_interactions': total_honeypot_events,
        'top_ips': top_ips,
        'recent_honeypot': recent_honeypot,
        'recent_classifications': recent_classifications
    }


def add_feedback_sample(
    url: str,
    suggested_label: int,
    notes: str = "",
    db_path: Optional[Path] = None
) -> bool:
    """Add a suspicious or honeypot URL to the controlled feedback candidates table."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    now_str = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')

    try:
        cursor.execute('''
            INSERT INTO feedback_samples (timestamp, url, suggested_label, status, notes)
            VALUES (?, ?, ?, 'pending', ?)
        ''', (now_str, url, suggested_label, notes))
        conn.commit()
        success = True
    except sqlite3.IntegrityError:
        success = False
    finally:
        conn.close()

    return success


def get_feedback_samples(status: Optional[str] = None, db_path: Optional[Path] = None) -> List[Dict[str, Any]]:
    """Retrieve feedback candidate samples filtered by status."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    if status:
        cursor.execute("SELECT * FROM feedback_samples WHERE status = ? ORDER BY id DESC", (status,))
    else:
        cursor.execute("SELECT * FROM feedback_samples ORDER BY id DESC")

    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows


def update_feedback_sample_status(
    sample_id: int,
    status: str,
    reviewer_label: Optional[int] = None,
    notes: Optional[str] = None,
    db_path: Optional[Path] = None
) -> bool:
    """Approve or reject a candidate feedback sample (prevents model poisoning)."""
    if status not in ('pending', 'approved', 'rejected'):
        return False

    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    cursor.execute('''
        UPDATE feedback_samples
        SET status = ?, reviewer_label = COALESCE(?, reviewer_label), notes = COALESCE(?, notes)
        WHERE id = ?
    ''', (status, reviewer_label, notes, sample_id))

    rows_affected = cursor.rowcount
    conn.commit()
    conn.close()
    return rows_affected > 0
