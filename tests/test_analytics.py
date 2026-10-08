"""
Tests for Attacker Behavior Analytics Engine.
"""

import pytest
from src.database import init_db, log_honeypot_interaction
from src.analytics import analyze_honeypot_behavior


@pytest.fixture
def analytics_db(tmp_path):
    db_file = tmp_path / "test_analytics.db"
    init_db(db_file)
    return db_file


def test_analyze_honeypot_behavior_empty(analytics_db):
    result = analyze_honeypot_behavior(db_path=analytics_db)
    assert result['total_events'] == 0
    assert result['top_ips'] == []
    assert result['repeated_attackers'] == []
    assert result['targeted_routes'] == []
    assert result['threat_summary']['avg_risk_score'] == 0.0


def test_analyze_honeypot_behavior_populated(analytics_db):
    # Log multiple simulated events
    # Attacker 1: 3 attempts with bot UA
    for _ in range(3):
        log_honeypot_interaction(
            source_ip="203.0.113.10",
            user_agent="sqlmap/1.4",
            route="/login",
            method="POST",
            username="admin",
            password="pwd",
            risk_score=0.9,
            db_path=analytics_db
        )

    # Attacker 2: 1 attempt with browser UA
    log_honeypot_interaction(
        source_ip="198.51.100.22",
        user_agent="Mozilla/5.0 Chrome/120.0",
        route="/wp-login.php",
        method="POST",
        username="root",
        password="pwd",
        risk_score=0.6,
        db_path=analytics_db
    )

    result = analyze_honeypot_behavior(db_path=analytics_db)
    assert result['total_events'] == 4
    assert len(result['top_ips']) == 2
    assert result['top_ips'][0]['ip'] == "203.0.113.10"
    assert result['top_ips'][0]['count'] == 3

    # Check repeated attackers list
    repeated_ips = [a['ip'] for a in result['repeated_attackers']]
    assert "203.0.113.10" in repeated_ips

    # Check user agent breakdown
    assert result['user_agent_breakdown']['automated_scanners'] == 3
    assert result['user_agent_breakdown']['simulated_browsers'] == 1
    assert result['threat_summary']['scanner_detected'] is True
