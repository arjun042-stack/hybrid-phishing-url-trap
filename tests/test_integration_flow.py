"""
End-to-End Full System Integration Test for Hybrid Phishing URL Trap.

Verifies the entire lifecycle:
TEST URL
    ↓
FEATURE EXTRACTION
    ↓
ML PREDICTION
    ↓
RISK RESULT & TELEMETRY
    ↓
HONEYPOT TRAP REDIRECTION
    ↓
SAFE TEST INTERACTION
    ↓
DATABASE LOG (CREDENTIAL FINGERPRINTING)
    ↓
BEHAVIOR ANALYSIS
    ↓
DASHBOARD TELEMETRY
    ↓
CONTROLLED ANALYST FEEDBACK APPROVAL
"""

import pytest
from app import create_app
from src.features import extract_features, FEATURE_NAMES
from src.classifier import predict_url
from src.analytics import analyze_honeypot_behavior
from src.database import (
    get_db_connection,
    get_dashboard_statistics,
    get_feedback_samples,
    update_feedback_sample_status
)


def test_full_system_lifecycle_flow(tmp_path):
    test_db = tmp_path / "lifecycle_integration.db"
    app = create_app(test_config={
        'TESTING': True,
        'DB_PATH': test_db,
        'SECRET_KEY': 'integration-secret-test'
    })

    with app.test_client() as client:
        # 1. TEST URL
        test_url = "http://192.168.1.55/secure-banking-login.php?user=admin"

        # 2. FEATURE EXTRACTION
        features = extract_features(test_url)
        assert len(features) == len(FEATURE_NAMES)
        assert features['is_ip'] == 1
        assert features['has_suspicious_keyword'] == 1
        assert features['entropy'] > 0

        # 3. ML PREDICTION & 4. RISK RESULT
        ml_result = predict_url(test_url)
        assert ml_result['url'] == test_url
        assert ml_result['prediction'] in ("PHISHING", "SUSPICIOUS")
        assert ml_result['risk_level'] in ("HIGH", "MEDIUM")

        # Web inspection through Flask endpoint
        res_classify = client.post('/classify', data={'url': test_url})
        assert res_classify.status_code == 200

        # Verify classification logged in DB
        conn = get_db_connection(test_db)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM classification_events WHERE url = ?", (test_url,))
        class_event = cursor.fetchone()
        conn.close()
        assert class_event is not None
        assert class_event['risk_level'] in ("HIGH", "MEDIUM")

        # 5. HONEYPOT TRAP REDIRECTION
        res_honeypot_page = client.get(f"/login?target={test_url}")
        assert res_honeypot_page.status_code == 200
        assert b"Employee Access Gateway" in res_honeypot_page.data

        # 6. SAFE TEST INTERACTION
        honeypot_payload = {
            'username': 'target_admin',
            'password': 'RawAttackerPasswordToNeverStorePlaintext!99',
            'target': test_url
        }
        res_honeypot_post = client.post(f"/login?target={test_url}", data=honeypot_payload)
        assert res_honeypot_post.status_code == 200
        assert b"Invalid security credentials. Access denied." in res_honeypot_post.data

        # 7. DATABASE LOG & CREDENTIAL FINGERPRINTING
        conn = get_db_connection(test_db)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM honeypot_events WHERE username_or_identifier = 'target_admin'")
        hp_event = dict(cursor.fetchone())
        conn.close()

        assert hp_event is not None
        # Plaintext password MUST NOT exist anywhere in database
        assert "RawAttackerPasswordToNeverStorePlaintext!99" not in str(hp_event)
        assert len(hp_event['password_fingerprint']) == 16
        assert hp_event['route'] == "/login"

        # 8. BEHAVIOR ANALYSIS
        behavior = analyze_honeypot_behavior(db_path=test_db)
        assert behavior['total_events'] >= 1
        assert len(behavior['top_ips']) >= 1
        assert any(r['route'] == '/login' for r in behavior['targeted_routes'])
        assert any(u['username'] == 'target_admin' for u in behavior['common_usernames'])

        # 9. DASHBOARD TELEMETRY
        stats = get_dashboard_statistics(test_db)
        assert stats['total_urls'] >= 1
        assert stats['honeypot_interactions'] >= 1

        res_dashboard = client.get('/dashboard')
        assert res_dashboard.status_code == 200
        assert b"target_admin" in res_dashboard.data

        res_api_stats = client.get('/api/stats')
        assert res_api_stats.status_code == 200
        api_data = res_api_stats.get_json()
        assert api_data['honeypot_interactions'] >= 1

        # 10. CONTROLLED FEEDBACK & RETRAINING APPROVAL
        # Target URL was staged into feedback_samples as pending
        pending_samples = get_feedback_samples(status='pending', db_path=test_db)
        assert len(pending_samples) >= 1
        staged_sample = next(s for s in pending_samples if s['url'] == test_url)
        assert staged_sample['status'] == 'pending'

        # Analyst approves sample
        approved = update_feedback_sample_status(
            sample_id=staged_sample['id'],
            status='approved',
            reviewer_label=1,
            notes='Analyst verified via end-to-end integration test',
            db_path=test_db
        )
        assert approved is True

        approved_samples = get_feedback_samples(status='approved', db_path=test_db)
        assert any(s['url'] == test_url for s in approved_samples)
