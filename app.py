#!/usr/bin/env python3
"""
Hybrid Phishing URL Trap: Integrating Machine Learning and Honeypots for Cybersecurity.

Main Flask Application Server.
Exposes ML URL classification, defensive honeypot traps, threat intelligence
dashboards, and controlled human-in-the-loop feedback mechanisms.
"""

import os
import sys
from pathlib import Path
from typing import Dict, Any

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from flask import (
    Flask, request, render_template, redirect, url_for,
    jsonify, abort
)
from dotenv import load_dotenv

# Load local environment configuration if present
load_dotenv(PROJECT_ROOT / '.env')

from src.database import (
    init_db, log_classification_event, get_dashboard_statistics,
    add_feedback_sample, get_feedback_samples, update_feedback_sample_status,
    get_db_connection
)
from src.classifier import get_classifier, predict_url
from src.honeypot import handle_honeypot_attempt
from src.analytics import analyze_honeypot_behavior


def get_client_ip(req) -> str:
    """Safely extract client IP address, respecting X-Forwarded-For if behind a proxy."""
    forwarded = req.headers.get('X-Forwarded-For')
    if forwarded:
        client = forwarded.split(',')[0].strip()
        if client:
            return client[:50]
    return (req.remote_addr or '127.0.0.1')[:50]


def create_app(test_config: Dict[str, Any] = None) -> Flask:
    """Application factory for the Hybrid Phishing URL Trap."""
    template_dir = PROJECT_ROOT / 'templates'
    static_dir = PROJECT_ROOT / 'static'

    app = Flask(
        __name__,
        template_folder=str(template_dir),
        static_folder=str(static_dir)
    )

    # Configuration & Hardening
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'phish-sentinel-defensive-secret-key-2026')
    app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # 2 MB max payload size
    app.config['DB_PATH'] = PROJECT_ROOT / 'instance' / 'honeypot_logs.db'

    if test_config:
        app.config.update(test_config)

    # Initialize Database Schema
    init_db(app.config['DB_PATH'])

    # Initialize ML Classifier
    classifier = get_classifier()
    app.classifier = classifier

    # Security Headers Middleware
    @app.after_request
    def set_security_headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['Content-Security-Policy'] = (
            "default-src 'self' https: 'unsafe-inline'; "
            "img-src 'self' data: https:; "
            "font-src 'self' https: data:;"
        )
        return response

    # ---------------------------------------------------------
    # Frontend Routes
    # ---------------------------------------------------------

    @app.route('/')
    def index():
        """Home overview page."""
        stats = get_dashboard_statistics(app.config['DB_PATH'])
        clf = get_classifier()
        analytics = analyze_honeypot_behavior(app.config['DB_PATH'])
        return render_template('home.html', stats=stats, model_meta=clf.metadata, analytics=analytics)

    @app.route('/model')
    def model_monitor():
        """ML Model architecture, feature importances and performance monitoring."""
        clf = get_classifier()
        return render_template(
            'model.html',
            metadata=clf.metadata,
            feature_names=clf.feature_names,
            is_loaded=clf.is_loaded
        )

    @app.route('/classify', methods=['GET', 'POST'])
    def classify():
        """URL Phishing Classification interface."""
        url = ''
        result = None
        if request.method == 'POST':
            url = request.form.get('url', '').strip()
            if url:
                result = predict_url(url)
                # Log classification telemetry to database
                source_ip = get_client_ip(request)
                log_classification_event(
                    url=url,
                    prediction=result.get('prediction', 'UNKNOWN'),
                    confidence=result.get('confidence', 0.0),
                    risk_level=result.get('risk_level', 'LOW'),
                    features=result.get('features', {}),
                    source_ip=source_ip,
                    db_path=app.config['DB_PATH']
                )

        return render_template('classify.html', url=url, result=result)

    @app.route('/login', methods=['GET', 'POST'])
    def honeypot_login():
        """
        Isolated simulated login portal (Honeypot Trap).
        Captures attacker telemetry; never stores plaintext passwords.
        """
        message = None
        target_param = request.values.get('target', '').strip()

        if request.method == 'POST':
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '').strip()

            if username:
                attempt_res = handle_honeypot_attempt(
                    request=request,
                    username=username,
                    password=password,
                    route="/login",
                    db_path=app.config['DB_PATH']
                )
                # If target was provided from a suspicious URL redirection, stage into feedback
                if target_param:
                    add_feedback_sample(
                        url=target_param,
                        suggested_label=1,
                        notes=f"Trapped attacker probe for user: {username[:50]}",
                        db_path=app.config['DB_PATH']
                    )

                message = attempt_res.get('deceptive_message', 'Invalid security credentials. Access denied.')

        return render_template('login.html', message=message, target=target_param)

    @app.route('/dashboard')
    def dashboard():
        """Threat Intelligence & Honeypot Telemetry Dashboard."""
        stats = get_dashboard_statistics(app.config['DB_PATH'])
        analytics = analyze_honeypot_behavior(app.config['DB_PATH'])
        return render_template('dashboard.html', stats=stats, analytics=analytics)

    @app.route('/report')
    def legacy_report():
        """Backwards-compatible honeypot report view."""
        conn = get_db_connection(app.config['DB_PATH'])
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM login_attempt ORDER BY id DESC LIMIT 50")
        attempts = [dict(r) for r in cursor.fetchall()]
        conn.close()
        return render_template('report.html', attempts=attempts)

    @app.route('/feedback', methods=['GET', 'POST'])
    def feedback():
        """Controlled human-in-the-loop candidate sample review."""
        if request.method == 'POST':
            action = request.form.get('action')
            if action == 'add':
                url = request.form.get('url', '').strip()
                try:
                    suggested_label = int(request.form.get('suggested_label', 1))
                except (ValueError, TypeError):
                    suggested_label = 1
                notes = request.form.get('notes', '')
                if url:
                    add_feedback_sample(url, suggested_label, notes, app.config['DB_PATH'])
            elif action == 'update':
                try:
                    sample_id = int(request.form.get('sample_id', 0))
                except (ValueError, TypeError):
                    sample_id = 0
                status = request.form.get('status', 'pending')
                reviewer_label = request.form.get('reviewer_label')
                try:
                    rev_lbl = int(reviewer_label) if reviewer_label is not None and reviewer_label != '' else None
                except (ValueError, TypeError):
                    rev_lbl = None
                notes = request.form.get('notes')
                if sample_id:
                    update_feedback_sample_status(sample_id, status, rev_lbl, notes, app.config['DB_PATH'])
            return redirect(url_for('feedback'))

        samples = get_feedback_samples(db_path=app.config['DB_PATH'])
        return render_template('feedback.html', samples=samples)

    # ---------------------------------------------------------
    # REST API Endpoints
    # ---------------------------------------------------------

    @app.route('/api/classify', methods=['POST'])
    def api_classify():
        """JSON endpoint for automated URL threat classification."""
        data = request.get_json(silent=True) or {}
        url = data.get('url', '').strip()

        if not url:
            return jsonify({'error': 'Missing or empty "url" field.'}), 400

        res = predict_url(url)
        source_ip = get_client_ip(request)

        log_classification_event(
            url=url,
            prediction=res.get('prediction', 'UNKNOWN'),
            confidence=res.get('confidence', 0.0),
            risk_level=res.get('risk_level', 'LOW'),
            features=res.get('features', {}),
            source_ip=source_ip,
            db_path=app.config['DB_PATH']
        )

        return jsonify(res)

    @app.route('/api/honeypot/login', methods=['POST'])
    def api_honeypot_login():
        """JSON Honeypot Trap endpoint for API-driven credential stuffing bots."""
        data = request.get_json(silent=True) or request.form.to_dict()
        username = data.get('username', '').strip()
        password = data.get('password', '').strip()

        if not username:
            return jsonify({'error': 'Missing username.'}), 400

        result = handle_honeypot_attempt(
            request=request,
            username=username,
            password=password,
            route="/api/honeypot/login",
            db_path=app.config['DB_PATH']
        )
        return jsonify({
            'status': 'error',
            'message': result.get('deceptive_message', 'Authentication failed.'),
            'event_id': result.get('event_id')
        }), 401

    @app.route('/api/stats')
    def api_stats():
        """Retrieve threat intelligence dashboard metrics."""
        stats = get_dashboard_statistics(app.config['DB_PATH'])
        return jsonify(stats)

    @app.route('/api/events')
    def api_events():
        """Retrieve recent honeypot telemetry events."""
        raw_limit = request.args.get('limit', 50)
        try:
            limit = int(raw_limit)
            limit = max(1, min(limit, 100))
        except (ValueError, TypeError):
            limit = 50
        conn = get_db_connection(app.config['DB_PATH'])
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, timestamp, event_type, source_ip, user_agent, route,
                   request_method, username_or_identifier, risk_score
            FROM honeypot_events
            ORDER BY id DESC LIMIT ?
        ''', (limit,))
        events = [dict(r) for r in cursor.fetchall()]
        conn.close()
        return jsonify({'total': len(events), 'events': events})

    @app.route('/api/model-info')
    def api_model_info():
        """Retrieve current ML model version, metrics, and feature list."""
        clf = get_classifier()
        return jsonify({
            'loaded': clf.is_loaded,
            'model_path': str(clf.model_path) if clf.model_path else None,
            'feature_count': len(clf.feature_names),
            'feature_names': clf.feature_names,
            'metadata': clf.metadata
        })

    @app.route('/health')
    def health_check():
        """System health and operational status check."""
        db_ok = False
        try:
            conn = get_db_connection(app.config['DB_PATH'])
            conn.execute("SELECT 1")
            conn.close()
            db_ok = True
        except Exception:
            db_ok = False

        clf = get_classifier()
        is_healthy = db_ok and clf.is_loaded

        status_code = 200 if is_healthy else 503
        return jsonify({
            'status': 'healthy' if is_healthy else 'degraded',
            'model_loaded': clf.is_loaded,
            'database': db_ok,
            'version': clf.metadata.get('version', '1.0.0')
        }), status_code

    # ---------------------------------------------------------
    # Error Handlers
    # ---------------------------------------------------------

    @app.errorhandler(404)
    def not_found_error(error):
        return render_template(
            'error.html',
            code=404,
            title='Resource Not Found',
            description='The requested defense endpoint or page does not exist.'
        ), 404

    @app.errorhandler(413)
    def request_entity_too_large(error):
        return render_template(
            'error.html',
            code=413,
            title='Payload Too Large',
            description='Request payload exceeded the defensive 2MB security threshold.'
        ), 413

    @app.errorhandler(500)
    def internal_server_error(error):
        return render_template(
            'error.html',
            code=500,
            title='Internal Defense Server Error',
            description='An internal system error occurred. Telemetry recorded.'
        ), 500

    return app


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() in ('true', '1')
    application = create_app()
    print(f"[*] Starting Hybrid Phishing URL Trap on http://127.0.0.1:{port} (Debug: {debug_mode})")
    application.run(host='127.0.0.1', port=port, debug=debug_mode)
