"""
URL Feature Extraction Module for Hybrid Phishing URL Trap.

Extracts lexical, structural, and security-relevant features from URLs
for Machine Learning classification and heuristic threat analysis.
"""

import math
import re
from urllib.parse import urlparse
from typing import Dict, Any, List

# Common URL shortening domains
SHORTENING_SERVICES = {
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd',
    'buff.ly', 'adf.ly', 'bit.do', 'short.io', 'cutt.ly', 'rebrand.ly'
}

# Suspicious keywords commonly seen in phishing targets and payloads
SUSPICIOUS_KEYWORDS = [
    'login', 'signin', 'verify', 'update', 'account', 'banking',
    'secure', 'confirm', 'security', 'password', 'credential',
    'wallet', 'support', 'authenticate', 'service', 'paypal',
    'ebayisapi', 'webscr', 'appleid', 'recovery'
]

# Regex pattern for IPv4 address in hostname
IPV4_PATTERN = re.compile(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')


def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0.0
    prob_dict: Dict[str, int] = {}
    for char in text:
        prob_dict[char] = prob_dict.get(char, 0) + 1
    length = len(text)
    entropy = -sum((count / length) * math.log2(count / length) for count in prob_dict.values())
    return round(entropy, 4)


def extract_features(url: str) -> Dict[str, Any]:
    """
    Extract a comprehensive dictionary of numerical features from a given URL.
    Handles malformed URLs safely without crashing.
    """
    if not isinstance(url, str):
        url = str(url or '')

    url_clean = url.strip()
    url_lower = url_clean.lower()

    # Prepend scheme if missing for robust urlparse parsing
    parsed_candidate = url_clean
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', parsed_candidate):
        parsed_candidate = 'http://' + parsed_candidate

    try:
        parsed = urlparse(parsed_candidate)
        hostname = (parsed.hostname or '').lower()
        path = parsed.path or ''
        query = parsed.query or ''
    except Exception:
        hostname = ''
        path = ''
        query = ''

    # Basic length and counts
    length = len(url_clean)
    num_dots = url_clean.count('.')
    has_at = int('@' in url_clean)
    has_https = int(url_lower.startswith('https://') or parsed.scheme.lower() == 'https')
    num_hyphens = url_clean.count('-')
    num_digits = sum(c.isdigit() for c in url_clean)

    # Extended lexical & structural features
    domain_length = len(hostname)
    path_length = len(path)
    num_slashes = url_clean.count('/')
    num_question_marks = url_clean.count('?')
    num_equals = url_clean.count('=')
    num_ampersands = url_clean.count('&')
    num_percent = url_clean.count('%')
    
    # IP address as hostname check
    is_ip = int(bool(IPV4_PATTERN.match(hostname)))

    # Subdomains count (dots in hostname minus TLD boundary; 0 if IP address)
    host_dots = hostname.count('.')
    num_subdomains = 0 if is_ip else (max(0, host_dots - 1) if host_dots > 1 else 0)

    # URL Shortener check
    is_shortened = int(hostname in SHORTENING_SERVICES)

    # Suspicious keywords
    has_suspicious_keyword = int(any(kw in url_lower for kw in SUSPICIOUS_KEYWORDS))

    # Path depth (number of directory levels)
    path_segments = [p for p in path.split('/') if p]
    path_depth = len(path_segments)

    # Entropy
    entropy = calculate_entropy(url_clean)

    # Special characters ratio / count
    special_chars = sum(not c.isalnum() for c in url_clean)

    return {
        # Core features (compatible with baseline)
        'length': length,
        'num_dots': num_dots,
        'has_at': has_at,
        'has_https': has_https,
        'num_hyphens': num_hyphens,
        'num_digits': num_digits,
        
        # Extended cybersecurity features
        'domain_length': domain_length,
        'path_length': path_length,
        'num_slashes': num_slashes,
        'num_question_marks': num_question_marks,
        'num_equals': num_equals,
        'num_ampersands': num_ampersands,
        'num_percent': num_percent,
        'num_subdomains': num_subdomains,
        'is_ip': is_ip,
        'is_shortened': is_shortened,
        'has_suspicious_keyword': has_suspicious_keyword,
        'path_depth': path_depth,
        'entropy': entropy,
        'num_special_chars': special_chars
    }


# Standard ordered list of feature keys
FEATURE_NAMES: List[str] = [
    'length',
    'num_dots',
    'has_at',
    'has_https',
    'num_hyphens',
    'num_digits',
    'domain_length',
    'path_length',
    'num_slashes',
    'num_question_marks',
    'num_equals',
    'num_ampersands',
    'num_percent',
    'num_subdomains',
    'is_ip',
    'is_shortened',
    'has_suspicious_keyword',
    'path_depth',
    'entropy',
    'num_special_chars'
]

# Legacy 6-feature names for backwards compatibility
LEGACY_FEATURE_NAMES: List[str] = [
    'length',
    'num_dots',
    'has_at',
    'has_https',
    'num_hyphens',
    'num_digits'
]
