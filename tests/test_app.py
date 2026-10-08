"""
Comprehensive Integration Tests for Flask Application and REST APIs.
"""

import json
import pytest
from app import create_app
from src.database import get_db_connection, get_feedback_samples


@pytest.fixture
def test_client(tmp_path):
    test_db = tmp_path / "test_app_instance.db"
    app = create_app(test_config={
        'TESTING': True,
        'DB_PATH': test_db,
        'SECRET_KEY': 'test-secret-key-1234'
    })
    with app.test_client() as client:
        yield client, test_db


def test_index_route(test_client):
    client, _ = test_client
    response = client.get('/')
    assert response.status_code == 200
    assert b"Hybrid Phishing URL Trap" in response.data


def test_classify_get_and_post(test_client):
    client, test_db = test_client
    # GET
    res_get = client.get('/classify')
    assert res_get.status_code == 200
    assert b"AI-Powered URL Phishing Classifier" in res_get.data

    # POST safe URL
    res_post = client.post('/classify', data={'url': 'https://www.google.com'})
    assert res_post.status_code == 200
    assert b"LEGITIMATE (SAFE)" in res_post.data

    # Verify event logged in DB
    conn = get_db_connection(test_db)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM classification_events WHERE url = 'https://www.google.com'")
    row = cursor.fetchone()
    conn.close()
    assert row is not None
    assert row['prediction'] == 'SAFE'


def test_login_honeypot_flow(test_client):
    client, test_db = test_client
    # GET
    res_get = client.get('/login')
    assert res_get.status_code == 200
    assert b"Employee Access Gateway" in res_get.data

    # POST honeypot attempt
    res_post = client.post('/login', data={
        'username': 'attacker_admin',
        'password': 'bad_password_to_test'
    })
    assert res_post.status_code == 200
    assert b"Invalid security credentials. Access denied." in res_post.data

    # Verify honeypot event logged with password hashed (never plaintext)
    conn = get_db_connection(test_db)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM honeypot_events WHERE username_or_identifier = 'attacker_admin'")
    row = dict(cursor.fetchone())
    conn.close()
    assert row is not None
    assert "bad_password_to_test" not in str(row)
    assert row['password_fingerprint'] != ""


def test_login_honeypot_with_target_redirection(test_client):
    client, test_db = test_client
    # POST honeypot with target URL attached
    res = client.post('/login?target=http://malicious-redirect-lure.org', data={
        'username': 'victim_user',
        'password': 'password123',
        'target': 'http://malicious-redirect-lure.org'
    })
    assert res.status_code == 200

    # Target URL should be staged into feedback_samples as pending
    samples = get_feedback_samples(status='pending', db_path=test_db)
    assert any(s['url'] == 'http://malicious-redirect-lure.org' for s in samples)


def test_dashboard_and_report_views(test_client):
    client, _ = test_client
    # Dashboard view
    res_dash = client.get('/dashboard')
    assert res_dash.status_code == 200
    assert b"Threat Intelligence & Honeypot Telemetry" in res_dash.data

    # Legacy report view
    res_rep = client.get('/report')
    assert res_rep.status_code == 200
    assert b"Honeypot Intrusion Attempts Report" in res_rep.data


def test_feedback_page_lifecycle(test_client):
    client, test_db = test_client
    # GET feedback
    res_get = client.get('/feedback')
    assert res_get.status_code == 200
    assert b"Controlled Retraining Feedback Loop" in res_get.data

    # POST action=add
    res_add = client.post('/feedback', data={
        'action': 'add',
        'url': 'http://candidate-sample-123.com',
        'suggested_label': '1',
        'notes': 'test feedback note'
    }, follow_redirects=True)
    assert res_add.status_code == 200
    assert b"http://candidate-sample-123.com" in res_add.data

    # Retrieve queued sample id
    samples = get_feedback_samples(status='pending', db_path=test_db)
    assert len(samples) >= 1
    sample_id = samples[0]['id']

    # POST action=update (approve)
    res_update = client.post('/feedback', data={
        'action': 'update',
        'sample_id': str(sample_id),
        'status': 'approved',
        'reviewer_label': '1',
        'notes': 'Analyst verified phishing'
    }, follow_redirects=True)
    assert res_update.status_code == 200
    assert b"APPROVED" in res_update.data


def test_health_endpoint(test_client):
    client, _ = test_client
    res = client.get('/health')
    assert res.status_code == 200
    data = res.get_json()
    assert data['status'] == 'healthy'
    assert data['database'] is True
    assert data['model_loaded'] is True


def test_api_stats(test_client):
    client, _ = test_client
    res = client.get('/api/stats')
    assert res.status_code == 200
    data = res.get_json()
    assert 'total_urls' in data
    assert 'phishing_count' in data
    assert 'safe_count' in data
    assert 'honeypot_interactions' in data


def test_api_classify_endpoint(test_client):
    client, _ = test_client
    # Success case
    res = client.post('/api/classify', json={'url': 'https://wikipedia.org'})
    assert res.status_code == 200
    data = res.get_json()
    assert data['url'] == 'https://wikipedia.org'
    assert data['prediction'] == 'SAFE'
    assert 'risk_level' in data
    assert 'confidence' in data
    assert 'features' in data

    # Empty URL -> 400
    res_empty = client.post('/api/classify', json={'url': ''})
    assert res_empty.status_code == 400

    # No JSON body -> 400
    res_none = client.post('/api/classify', data='')
    assert res_none.status_code == 400


def test_api_events_and_model_info(test_client):
    client, _ = test_client
    # /api/events
    res_events = client.get('/api/events')
    assert res_events.status_code == 200
    data_events = res_events.get_json()
    assert 'total' in data_events
    assert 'events' in data_events

    # /api/model-info
    res_info = client.get('/api/model-info')
    assert res_info.status_code == 200
    data_info = res_info.get_json()
    assert data_info['loaded'] is True
    assert data_info['feature_count'] > 0


def test_api_honeypot_login(test_client):
    client, _ = test_client
    # POST honeypot JSON
    res = client.post('/api/honeypot/login', json={
        'username': 'bot_scanner',
        'password': 'some_password'
    })
    assert res.status_code == 401
    data = res.get_json()
    assert data['status'] == 'error'
    assert 'message' in data

    # Missing username -> 400
    res_bad = client.post('/api/honeypot/login', json={'username': ''})
    assert res_bad.status_code == 400


def test_security_headers(test_client):
    client, _ = test_client
    res = client.get('/')
    assert res.headers.get('X-Content-Type-Options') == 'nosniff'
    assert res.headers.get('X-Frame-Options') == 'SAMEORIGIN'
    assert res.headers.get('X-XSS-Protection') == '1; mode=block'
    assert res.headers.get('Referrer-Policy') == 'strict-origin-when-cross-origin'
    assert 'default-src' in res.headers.get('Content-Security-Policy', '')


def test_not_found_404(test_client):
    client, _ = test_client
    res = client.get('/definitely-unknown-route-xyz')
    assert res.status_code == 404
    assert b"Resource Not Found" in res.data


def test_model_view(test_client):
    client, _ = test_client
    res = client.get('/model')
    assert res.status_code == 200
    assert b"Machine Learning Classifier Telemetry" in res.data
    assert b"Random Forest" in res.data


def test_api_events_invalid_and_edge_case_limits(test_client):
    client, _ = test_client
    # Non-integer limit must not raise 500 error; defaults gracefully
    res_str = client.get('/api/events?limit=invalid_string')
    assert res_str.status_code == 200
    assert 'events' in res_str.get_json()

    # Negative limit clamped to 1
    res_neg = client.get('/api/events?limit=-10')
    assert res_neg.status_code == 200

    # Overly large limit clamped to 100
    res_large = client.get('/api/events?limit=9999')
    assert res_large.status_code == 200


def test_feedback_resilient_to_invalid_inputs(test_client):
    client, _ = test_client
    # Non-integer suggested_label and sample_id must not crash the server
    res_add = client.post('/feedback', data={
        'action': 'add',
        'url': 'http://robustness-test.com',
        'suggested_label': 'not_a_number'
    }, follow_redirects=True)
    assert res_add.status_code == 200

    res_update = client.post('/feedback', data={
        'action': 'update',
        'sample_id': 'bad_id',
        'reviewer_label': 'also_bad'
    }, follow_redirects=True)
    assert res_update.status_code == 200


def test_proxy_forwarded_ip_resolution(test_client):
    client, test_db = test_client
    # Classify URL with X-Forwarded-For header
    res = client.post('/api/classify', json={'url': 'https://wikipedia.org'}, headers={
        'X-Forwarded-For': '203.0.113.195, 10.0.0.1'
    })
    assert res.status_code == 200

    # Verify origin IP is logged accurately from X-Forwarded-For
    conn = get_db_connection(test_db)
    cursor = conn.cursor()
    cursor.execute("SELECT source_ip FROM classification_events WHERE url = 'https://wikipedia.org'")
    row = cursor.fetchone()
    conn.close()
    assert row is not None
    assert row['source_ip'] == '203.0.113.195'


