"""
Tests for Data Collector and Threat Feed Ingestion.
"""

import json
from unittest.mock import patch, MagicMock
import pytest
import requests

from src.data_collector import (
    ingest_from_local_dataset,
    fetch_external_feed,
    save_ingested_urls
)


def test_ingest_from_local_dataset(tmp_path):
    csv_file = tmp_path / "sample_dataset.csv"
    csv_file.write_text("URL,label\nhttp://example-safe.com,1\nhttp://phishing-bad.xyz,0\n", encoding="utf-8")

    records = ingest_from_local_dataset(csv_file, limit=10)
    assert len(records) == 2
    assert records[0]['url'] == "http://example-safe.com"
    assert records[0]['is_phishing'] == 0
    assert records[1]['url'] == "http://phishing-bad.xyz"
    assert records[1]['is_phishing'] == 1


def test_ingest_from_nonexistent_dataset(tmp_path):
    records = ingest_from_local_dataset(tmp_path / "nonexistent.csv")
    assert records == []


def test_fetch_external_feed_offline():
    # When no feed URL is configured
    records = fetch_external_feed(feed_url=None)
    assert records == []


@patch("src.data_collector.requests.get")
def test_fetch_external_feed_success(mock_get):
    mock_resp = MagicMock()
    mock_resp.json.return_value = [
        {"url": "http://evil-credential-steal.com", "phish_id": 1234, "verified": "yes"}
    ]
    mock_resp.raise_for_status.return_value = None
    mock_get.return_value = mock_resp

    records = fetch_external_feed(feed_url="https://fake-feed.example.com/api")
    assert len(records) == 1
    assert records[0]['url'] == "http://evil-credential-steal.com"
    assert records[0]['is_phishing'] == 1


@patch("src.data_collector.requests.get")
def test_fetch_external_feed_timeout(mock_get):
    mock_get.side_effect = requests.exceptions.Timeout("Timed out")
    records = fetch_external_feed(feed_url="https://fake-feed.example.com/api")
    assert records == []


def test_save_ingested_urls_deduplication(tmp_path):
    out_file = tmp_path / "feed_output.jsonl"
    batch1 = [
        {"url": "http://sample1.com", "is_phishing": 1},
        {"url": "http://sample2.com", "is_phishing": 1}
    ]
    saved1 = save_ingested_urls(batch1, output_path=out_file)
    assert saved1 == 2

    # Duplicate batch
    batch2 = [
        {"url": "http://sample2.com", "is_phishing": 1},
        {"url": "http://sample3.com", "is_phishing": 1}
    ]
    saved2 = save_ingested_urls(batch2, output_path=out_file)
    assert saved2 == 1  # Only sample3 is new

    # Verify lines
    with open(out_file, 'r', encoding='utf-8') as f:
        lines = [line.strip() for line in f if line.strip()]
    assert len(lines) == 3
