"""
Honeypot Security & Deception Engine.

Provides an isolated, defensive simulation environment that captures attacker
interaction telemetry without exposing the host, executing code, or storing
plaintext credentials.
"""

import time
import logging
from typing import Dict, Any, Optional
from flask import Request

from src.database import log_honeypot_interaction

logger = logging.getLogger(__name__)

# List of typical attacker probe routes to detect in the honeypot
PROBE_ROUTES = {
    '/login', '/admin', '/wp-login.php', '/administrator',
    '/api/login', '/user/login', '/signin', '/auth'
}

# Known scanner / bot user agent signatures
SUSPICIOUS_UA_SIGNATURES = [
    'sqlmap', 'nikto', 'nmap', 'masscan', 'zgrab', 'python-requests',
    'curl/', 'wget/', 'go-http-client', 'apache-httpclient'
]


def assess_honeypot_risk(
    request: Request,
    username: str,
    password: str
) -> float:
    """
    Calculate a normalized threat risk score (0.0 to 1.0) based on request patterns.
    """
    risk = 0.5  # Base interaction risk
    user_agent = (request.headers.get('User-Agent') or '').lower()
    path = request.path.lower()

    # User-agent scan signature
    if any(sig in user_agent for sig in SUSPICIOUS_UA_SIGNATURES):
        risk += 0.3

    # Common brute-force / admin targeted route
    if path in PROBE_ROUTES:
        risk += 0.1

    # Typical credential stuffing dictionary words
    uname_lower = username.lower()
    if uname_lower in ('admin', 'root', 'administrator', 'test', 'guest', 'support'):
        risk += 0.1

    # Injection probe patterns in username (SQLi / XSS attempt)
    if any(ch in username for ch in ("'", '"', ';', '--', '/*', '<script', 'OR 1=1')):
        risk += 0.2

    return min(1.0, round(risk, 2))


def handle_honeypot_attempt(
    request: Request,
    username: str,
    password: str,
    route: Optional[str] = None,
    db_path: Optional[Any] = None
) -> Dict[str, Any]:
    """
    Process an incoming honeypot intrusion attempt:
    1. Sanitizes and validates request fields.
    2. Calculates threat risk score.
    3. Logs telemetry into SQLite with SHA-256 password fingerprinting (NO PLAINTEXT).
    4. Returns a deceptive simulation payload.
    """
    target_db = db_path
    if target_db is None:
        try:
            from flask import current_app
            if current_app and 'DB_PATH' in current_app.config:
                target_db = current_app.config['DB_PATH']
        except Exception:
            target_db = None
    forwarded = request.headers.get('X-Forwarded-For')
    if forwarded:
        source_ip = forwarded.split(',')[0].strip()[:50]
    else:
        source_ip = (request.remote_addr or '127.0.0.1')[:50]
    user_agent = request.headers.get('User-Agent', 'Unknown')
    target_route = route or request.path
    method = request.method

    risk_score = assess_honeypot_risk(request, username, password)

    metadata = {
        'content_type': request.content_type,
        'content_length': request.content_length,
        'referrer': request.referrer,
        'accept_language': request.headers.get('Accept-Language'),
        'has_injection_tokens': any(ch in username for ch in ("'", '"', ';', '--', '<')),
        'honeypot_trap': True
    }

    # Log interaction safely to database
    event_id = log_honeypot_interaction(
        source_ip=source_ip,
        user_agent=user_agent,
        route=target_route,
        method=method,
        username=username[:100],
        password=password,  # database module will hash and redact this!
        event_type="honeypot_login_trap",
        metadata=metadata,
        risk_score=risk_score,
        db_path=target_db
    )

    logger.warning(
        "[HONEYPOT ALERT] Event #%d | IP: %s | Route: %s | User: %s | Risk: %.2f",
        event_id, source_ip, target_route, username[:100], risk_score
    )

    # Deceptive behavior simulation: slight artificial delay to thwart rapid brute-force
    time.sleep(0.3)

    return {
        'event_id': event_id,
        'status': 'captured',
        'risk_score': risk_score,
        'deceptive_message': 'Invalid security credentials. Access denied.'
    }
