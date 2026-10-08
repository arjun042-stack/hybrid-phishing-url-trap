"""
Data Collection & External Threat Feed Ingestion Module.

Safely collects candidate phishing URLs from external feeds (such as PhishTank,
OpenPhish, or local seed files) ONLY when explicitly triggered.
Provides offline fallback, network error handling, deduplication,
and safe non-executing storage.
"""

import csv
import json
import logging
import os
from pathlib import Path
from typing import List, Dict, Any, Optional

import requests

logger = logging.getLogger(__name__)

DEFAULT_INGESTION_DIR = Path(__file__).resolve().parent.parent / 'data' / 'ingested'


def ingest_from_local_dataset(
    source_csv: Path,
    limit: int = 100
) -> List[Dict[str, Any]]:
    """
    Offline fallback: extracts candidate URLs from the local verified dataset.
    """
    if not Path(source_csv).exists():
        logger.warning("Local source CSV does not exist: %s", source_csv)
        return []

    collected: List[Dict[str, Any]] = []
    try:
        with open(source_csv, 'r', encoding='utf-8', errors='ignore') as f:
            reader = csv.DictReader(f)
            for row in reader:
                url = row.get('URL', '').strip()
                label = row.get('label', '')
                if url:
                    collected.append({
                        'url': url,
                        'source': 'local_phishing_dataset',
                        'raw_label': label,
                        'is_phishing': 1 if str(label) == '0' else 0
                    })
                    if len(collected) >= limit:
                        break
    except Exception as e:
        logger.error("Failed to read local dataset: %s", e)

    return collected


def fetch_external_feed(
    feed_url: Optional[str] = None,
    api_key: Optional[str] = None,
    timeout: int = 10,
    max_records: int = 50
) -> List[Dict[str, Any]]:
    """
    Fetch candidate phishing URLs from an external threat feed with timeout
    and error handling. Operates strictly as a passive collector; never executes content.
    """
    # Prefer feed URL from parameter or environment variable
    target_feed = feed_url or os.environ.get("PHISHTANK_FEED_URL")
    key = api_key or os.environ.get("PHISHTANK_API_KEY", "")

    if not target_feed:
        logger.info("No external feed configured. Utilizing safe offline ingestion.")
        return []

    headers = {
        'User-Agent': 'CyberSec-Hybrid-Trap-Collector/1.0',
        'Accept': 'application/json'
    }
    if key:
        headers['X-API-KEY'] = key

    try:
        response = requests.get(target_feed, headers=headers, timeout=timeout)
        response.raise_for_status()

        data = response.json()
        results: List[Dict[str, Any]] = []

        # PhishTank format parsing
        if isinstance(data, list):
            for entry in data[:max_records]:
                url = entry.get('url')
                if url and isinstance(url, str):
                    results.append({
                        'url': url.strip(),
                        'source': 'external_feed',
                        'phish_id': entry.get('phish_id'),
                        'verified': entry.get('verified', 'yes'),
                        'is_phishing': 1
                    })
        return results

    except requests.exceptions.Timeout:
        logger.warning("External feed request timed out after %ds", timeout)
        return []
    except requests.exceptions.RequestException as e:
        logger.warning("External feed collection skipped (network error): %s", e)
        return []
    except Exception as e:
        logger.error("Error parsing threat feed data: %s", e)
        return []


def save_ingested_urls(
    records: List[Dict[str, Any]],
    output_path: Optional[Path] = None
) -> int:
    """Save ingested URLs safely to JSON lines, deduplicating against existing entries."""
    if not records:
        return 0

    dest = Path(output_path) if output_path else (DEFAULT_INGESTION_DIR / 'feed_samples.jsonl')
    dest.parent.mkdir(parents=True, exist_ok=True)

    existing_urls = set()
    if dest.exists():
        try:
            with open(dest, 'r', encoding='utf-8') as f:
                for line in f:
                    if line.strip():
                        existing_urls.add(json.loads(line).get('url'))
        except Exception:
            pass

    written = 0
    with open(dest, 'a', encoding='utf-8') as f:
        for r in records:
            u = r.get('url')
            if u and u not in existing_urls:
                f.write(json.dumps(r) + '\n')
                existing_urls.add(u)
                written += 1

    logger.info("Saved %d new records to %s", written, dest)
    return written
