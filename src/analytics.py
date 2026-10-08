"""
Attacker Behavior Analysis Engine for Honeypot Telemetry.

Performs statistical, temporal, and signature-based behavioral analysis
on captured honeypot intrusion records.
"""

from collections import Counter
from datetime import datetime
from typing import Dict, Any, List
from src.database import get_db_connection


def analyze_honeypot_behavior(db_path=None) -> Dict[str, Any]:
    """
    Perform deep behavioral analysis on recorded honeypot events:
    - Attack frequency across time
    - Repeated source IP behavior & brute-force indicators
    - Targeted routes analysis
    - User Agent bot vs browser categorization
    - Credential pattern analysis (common usernames, injection markers)
    """
    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    cursor.execute('''
        SELECT id, timestamp, event_type, source_ip, user_agent, route,
               request_method, username_or_identifier, metadata, risk_score
        FROM honeypot_events
        ORDER BY id ASC
    ''')
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()

    total_events = len(rows)
    if total_events == 0:
        return {
            'total_events': 0,
            'summary': 'No honeypot intrusion events recorded yet.',
            'top_ips': [],
            'repeated_attackers': [],
            'targeted_routes': [],
            'user_agent_breakdown': {},
            'common_usernames': [],
            'hourly_distribution': {},
            'threat_summary': {
                'avg_risk_score': 0.0,
                'high_risk_events': 0,
                'scanner_detected': False
            }
        }

    # IP frequency & repeated attacker analysis
    ip_counter = Counter(r['source_ip'] for r in rows if r['source_ip'])
    top_ips = [{'ip': ip, 'count': cnt} for ip, cnt in ip_counter.most_common(5)]
    repeated_attackers = [{'ip': ip, 'attempts': cnt} for ip, cnt in ip_counter.items() if cnt > 1]

    # Targeted routes
    route_counter = Counter(r['route'] for r in rows if r['route'])
    targeted_routes = [{'route': route, 'count': cnt} for route, cnt in route_counter.most_common(5)]

    # Common usernames
    username_counter = Counter(r['username_or_identifier'] for r in rows if r['username_or_identifier'])
    common_usernames = [{'username': u, 'count': cnt} for u, cnt in username_counter.most_common(5)]

    # User Agent categorization
    bot_keywords = ('curl', 'wget', 'python', 'sqlmap', 'nikto', 'nmap', 'masscan', 'scanner', 'bot')
    bot_count = sum(1 for r in rows if any(k in (r['user_agent'] or '').lower() for k in bot_keywords))
    browser_count = total_events - bot_count

    # Risk metrics
    risk_scores = [r.get('risk_score', 0.0) or 0.0 for r in rows]
    avg_risk = round(sum(risk_scores) / total_events, 2)
    high_risk_count = sum(1 for s in risk_scores if s >= 0.75)

    # Hourly attack distribution
    hourly_counter = Counter()
    for r in rows:
        ts = r.get('timestamp')
        if ts:
            try:
                # Handle standard ISO / sqlite timestamps
                dt = datetime.fromisoformat(str(ts).replace(' ', 'T').split('.')[0])
                hour_key = f"{dt.hour:02d}:00"
                hourly_counter[hour_key] += 1
            except Exception:
                pass

    return {
        'total_events': total_events,
        'summary': f"Analyzed {total_events} interaction(s) from {len(ip_counter)} unique source IP(s).",
        'top_ips': top_ips,
        'repeated_attackers': repeated_attackers,
        'targeted_routes': targeted_routes,
        'user_agent_breakdown': {
            'automated_scanners': bot_count,
            'simulated_browsers': browser_count
        },
        'common_usernames': common_usernames,
        'hourly_distribution': dict(sorted(hourly_counter.items())),
        'threat_summary': {
            'avg_risk_score': avg_risk,
            'high_risk_events': high_risk_count,
            'scanner_detected': bot_count > 0
        }
    }
