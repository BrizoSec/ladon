"""Tests for normalizers."""

import sys
from datetime import datetime
from pathlib import Path

import pytest

# Add src directory to path
src_path = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(src_path))

from normalizers.activity_normalizers import (
    CrowdStrikeNormalizer,
    DNSNormalizer,
    MDENormalizer,
    ProxyNormalizer,
    get_activity_normalizer,
)
from normalizers.base import NormalizationMetrics
from normalizers.ioc_normalizers import (
    AlienVaultOTXNormalizer,
    get_ioc_normalizer,
)


class TestNormalizationMetrics:
    """Tests for NormalizationMetrics."""

    def test_start_and_end(self):
        """Test starting and ending metrics collection."""
        metrics = NormalizationMetrics()
        metrics.start()

        assert metrics.start_time is not None

        metrics.end()
        assert metrics.end_time is not None
        assert metrics.end_time >= metrics.start_time

    def test_add_success(self):
        """Test adding successful events."""
        metrics = NormalizationMetrics()
        metrics.add_success(10)
        metrics.add_success(5)

        assert metrics.events_normalized == 15

    def test_add_failure(self):
        """Test adding failed events."""
        metrics = NormalizationMetrics()
        metrics.add_failure(3, "Error 1")
        metrics.add_failure(2, "Error 2")

        assert metrics.events_failed == 5
        assert len(metrics.validation_errors) == 2

    def test_to_dict(self):
        """Test converting metrics to dictionary."""
        metrics = NormalizationMetrics()
        metrics.start()
        metrics.add_success(100)
        metrics.add_failure(5, "Error")
        metrics.end()

        result = metrics.to_dict()

        assert result["events_normalized"] == 100
        assert result["events_failed"] == 5
        assert result["duration_seconds"] is not None


class TestIOCNormalizers:
    """Tests for IOC normalizers."""

    def test_alienvault_otx_normalizer(self, sample_raw_ioc):
        """Test AlienVault OTX normalizer."""
        normalizer = AlienVaultOTXNormalizer()
        normalized = normalizer.normalize(sample_raw_ioc)

        assert normalized is not None
        assert normalized.ioc_value == "evil.com"
        assert normalized.ioc_type.value == "domain"
        assert normalized.threat_type.value == "malware"
        assert normalized.confidence == 0.85
        assert normalized.source.value == "alienvault_otx"
        assert "malware" in normalized.tags

    def test_normalize_batch(self, sample_raw_ioc):
        """Test batch normalization."""
        normalizer = AlienVaultOTXNormalizer()
        raw_events = [sample_raw_ioc, sample_raw_ioc.copy()]

        normalized = normalizer.normalize_batch(raw_events)

        assert len(normalized) == 2
        assert normalizer.metrics.events_normalized == 2
        assert normalizer.metrics.events_failed == 0

    def test_normalize_invalid_ioc_skip(self):
        """Test normalization with invalid IOC (skip mode)."""
        normalizer = AlienVaultOTXNormalizer(skip_invalid=True)
        invalid_ioc = {"ioc_value": "test.com"}  # Missing required fields

        normalized = normalizer.normalize(invalid_ioc)

        assert normalized is None

    def test_normalize_invalid_ioc_strict(self):
        """Test normalization with invalid IOC (strict mode)."""
        normalizer = AlienVaultOTXNormalizer(skip_invalid=False)
        invalid_ioc = {"ioc_value": "test.com"}  # Missing required fields

        with pytest.raises(Exception):
            normalizer.normalize(invalid_ioc)

    def test_get_ioc_normalizer_factory(self):
        """Test IOC normalizer factory function."""
        normalizer = get_ioc_normalizer("alienvault_otx")
        assert isinstance(normalizer, AlienVaultOTXNormalizer)

        normalizer = get_ioc_normalizer("custom_source")
        assert normalizer.source_name == "custom_source"


class TestActivityNormalizers:
    """Tests for activity normalizers."""

    def test_dns_normalizer(self, sample_raw_dns_event):
        """Test DNS normalizer."""
        normalizer = DNSNormalizer()
        normalized = normalizer.normalize(sample_raw_dns_event)

        assert normalized is not None
        assert normalized.event_id == "dns_123"
        assert normalized.source.value == "dns"
        assert normalized.event_type.value == "dns_query"
        assert normalized.domain == "test.com"
        assert normalized.src_ip == "192.0.2.1"
        assert normalized.dst_ip == "8.8.8.8"

    def test_proxy_normalizer(self, sample_raw_proxy_event):
        """Test proxy normalizer."""
        normalizer = ProxyNormalizer()
        normalized = normalizer.normalize(sample_raw_proxy_event)

        assert normalized is not None
        assert normalized.event_id == "proxy_123"
        assert normalized.source.value == "proxy"
        assert normalized.event_type.value == "http_request"
        assert normalized.url == "https://example.com/path"
        assert normalized.domain == "example.com"
        assert normalized.user == "user@example.com"

    def test_mde_normalizer(self, sample_raw_mde_event):
        """Test MDE normalizer."""
        normalizer = MDENormalizer()
        normalized = normalizer.normalize(sample_raw_mde_event)

        assert normalized is not None
        assert normalized.event_id == "mde_123"
        assert normalized.source.value == "mde"
        assert normalized.event_type.value == "process_create"
        assert normalized.hostname == "workstation-001"
        assert normalized.user == "DOMAIN\\user"
        assert normalized.file_hash == "abc123def456"

    def test_get_activity_normalizer_factory(self):
        """Test activity normalizer factory function."""
        normalizer = get_activity_normalizer("dns")
        assert isinstance(normalizer, DNSNormalizer)

        normalizer = get_activity_normalizer("proxy")
        assert isinstance(normalizer, ProxyNormalizer)

        normalizer = get_activity_normalizer("custom_source")
        assert normalizer.source_name == "custom_source"
