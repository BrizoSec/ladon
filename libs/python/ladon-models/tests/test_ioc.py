"""Tests for IOC models."""

from datetime import datetime, timedelta

import pytest
from pydantic import ValidationError

from ladon_models import (
    IOCBatch,
    IOCMatch,
    IOCMetadata,
    IOCSource,
    IOCType,
    NormalizedIOC,
    RawIOC,
    ThreatType,
)


class TestIOCMetadata:
    """Tests for IOCMetadata model."""

    def test_create_basic_metadata(self):
        metadata = IOCMetadata(
            malware_family="Emotet", country="US", virustotal_score=50
        )
        assert metadata.malware_family == "Emotet"
        assert metadata.country == "US"
        assert metadata.virustotal_score == 50

    def test_custom_fields(self):
        metadata = IOCMetadata(custom_fields={"custom_key": "custom_value"})
        assert metadata.custom_fields["custom_key"] == "custom_value"


class TestRawIOC:
    """Tests for RawIOC model."""

    def test_create_raw_ioc(self):
        raw_ioc = RawIOC(
            source=IOCSource.ALIENVAULT_OTX,
            original_ioc_value="evil.com",
            raw_data={"indicator": "evil.com", "type": "domain"},
        )
        assert raw_ioc.source == IOCSource.ALIENVAULT_OTX
        assert raw_ioc.original_ioc_value == "evil.com"
        assert raw_ioc.received_at is not None


class TestNormalizedIOC:
    """Tests for NormalizedIOC model."""

    def test_create_domain_ioc(self):
        ioc = NormalizedIOC(
            ioc_value="evil.com",
            ioc_type=IOCType.DOMAIN,
            threat_type=ThreatType.C2,
            confidence=0.85,
            source=IOCSource.ALIENVAULT_OTX,
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
        )
        assert ioc.ioc_value == "evil.com"
        assert ioc.ioc_type == IOCType.DOMAIN
        assert ioc.threat_type == ThreatType.C2
        assert ioc.confidence == 0.85
        assert ioc.is_active

    def test_create_ip_ioc(self):
        ioc = NormalizedIOC(
            ioc_value="192.0.2.1",
            ioc_type=IOCType.IP,
            threat_type=ThreatType.MALWARE,
            confidence=0.9,
            source=IOCSource.ABUSE_CH,
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
        )
        assert ioc.ioc_value == "192.0.2.1"
        assert ioc.ioc_type == IOCType.IP

    def test_create_hash_ioc(self):
        ioc = NormalizedIOC(
            ioc_value="d41d8cd98f00b204e9800998ecf8427e",
            ioc_type=IOCType.HASH_MD5,
            threat_type=ThreatType.RANSOMWARE,
            confidence=0.95,
            source=IOCSource.MALWARE_BAZAAR,
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
        )
        assert ioc.ioc_value == "d41d8cd98f00b204e9800998ecf8427e"
        assert ioc.ioc_type == IOCType.HASH_MD5

    def test_normalize_domain_to_lowercase(self):
        ioc = NormalizedIOC(
            ioc_value="EVIL.COM",
            ioc_type=IOCType.DOMAIN,
            threat_type=ThreatType.C2,
            confidence=0.85,
            source=IOCSource.ALIENVAULT_OTX,
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
        )
        assert ioc.ioc_value == "evil.com"

    def test_normalize_hash_to_lowercase(self):
        ioc = NormalizedIOC(
            ioc_value="D41D8CD98F00B204E9800998ECF8427E",
            ioc_type=IOCType.HASH_MD5,
            threat_type=ThreatType.MALWARE,
            confidence=0.85,
            source=IOCSource.ALIENVAULT_OTX,
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
        )
        assert ioc.ioc_value == "d41d8cd98f00b204e9800998ecf8427e"

    def test_confidence_validation(self):
        # Valid confidence
        ioc = NormalizedIOC(
            ioc_value="evil.com",
            ioc_type=IOCType.DOMAIN,
            threat_type=ThreatType.C2,
            confidence=0.5,
            source=IOCSource.ALIENVAULT_OTX,
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
        )
        assert ioc.confidence == 0.5

        # Invalid confidence (too high)
        with pytest.raises(ValidationError):
            NormalizedIOC(
                ioc_value="evil.com",
                ioc_type=IOCType.DOMAIN,
                threat_type=ThreatType.C2,
                confidence=1.5,
                source=IOCSource.ALIENVAULT_OTX,
                first_seen=datetime.utcnow(),
                last_seen=datetime.utcnow(),
            )

    def test_temporal_consistency_validation(self):
        now = datetime.utcnow()
        past = now - timedelta(days=1)

        # Valid: last_seen after first_seen
        ioc = NormalizedIOC(
            ioc_value="evil.com",
            ioc_type=IOCType.DOMAIN,
            threat_type=ThreatType.C2,
            confidence=0.85,
            source=IOCSource.ALIENVAULT_OTX,
            first_seen=past,
            last_seen=now,
        )
        assert ioc.first_seen < ioc.last_seen

        # Invalid: last_seen before first_seen
        with pytest.raises(ValidationError):
            NormalizedIOC(
                ioc_value="evil.com",
                ioc_type=IOCType.DOMAIN,
                threat_type=ThreatType.C2,
                confidence=0.85,
                source=IOCSource.ALIENVAULT_OTX,
                first_seen=now,
                last_seen=past,
            )

    def test_populate_threat_types(self):
        ioc = NormalizedIOC(
            ioc_value="evil.com",
            ioc_type=IOCType.DOMAIN,
            threat_type=ThreatType.C2,
            confidence=0.85,
            source=IOCSource.ALIENVAULT_OTX,
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
        )
        assert ThreatType.C2 in ioc.threat_types

    def test_is_expired(self):
        past = datetime.utcnow() - timedelta(days=1)
        future = datetime.utcnow() + timedelta(days=1)

        # Expired IOC
        expired_ioc = NormalizedIOC(
            ioc_value="evil.com",
            ioc_type=IOCType.DOMAIN,
            threat_type=ThreatType.C2,
            confidence=0.85,
            source=IOCSource.ALIENVAULT_OTX,
            first_seen=past,
            last_seen=past,
            expires_at=past,
        )
        assert expired_ioc.is_expired()

        # Active IOC
        active_ioc = NormalizedIOC(
            ioc_value="evil.com",
            ioc_type=IOCType.DOMAIN,
            threat_type=ThreatType.C2,
            confidence=0.85,
            source=IOCSource.ALIENVAULT_OTX,
            first_seen=past,
            last_seen=datetime.utcnow(),
            expires_at=future,
        )
        assert not active_ioc.is_expired()

    def test_age_days(self):
        past = datetime.utcnow() - timedelta(days=5)
        ioc = NormalizedIOC(
            ioc_value="evil.com",
            ioc_type=IOCType.DOMAIN,
            threat_type=ThreatType.C2,
            confidence=0.85,
            source=IOCSource.ALIENVAULT_OTX,
            first_seen=past,
            last_seen=datetime.utcnow(),
        )
        assert ioc.age_days() >= 5


class TestIOCMatch:
    """Tests for IOCMatch model."""

    def test_create_ioc_match(self):
        ioc = NormalizedIOC(
            ioc_value="evil.com",
            ioc_type=IOCType.DOMAIN,
            threat_type=ThreatType.C2,
            confidence=0.85,
            source=IOCSource.ALIENVAULT_OTX,
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
        )

        match = IOCMatch(
            ioc=ioc,
            match_type="exact",
            matched_value="evil.com",
            confidence_adjusted=0.85,
        )
        assert match.ioc.ioc_value == "evil.com"
        assert match.match_type == "exact"

    def test_calculate_adjusted_confidence(self):
        ioc = NormalizedIOC(
            ioc_value="evil.com",
            ioc_type=IOCType.DOMAIN,
            threat_type=ThreatType.C2,
            confidence=0.8,
            source=IOCSource.ALIENVAULT_OTX,
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
        )

        # Exact match - full confidence
        exact_match = IOCMatch(
            ioc=ioc,
            match_type="exact",
            matched_value="evil.com",
            confidence_adjusted=0.8,
        )
        assert exact_match.calculate_adjusted_confidence() == 0.8

        # Subdomain match - reduced confidence
        subdomain_match = IOCMatch(
            ioc=ioc,
            match_type="subdomain",
            matched_value="sub.evil.com",
            confidence_adjusted=0.72,
        )
        adjusted = subdomain_match.calculate_adjusted_confidence()
        assert abs(adjusted - 0.72) < 0.001  # 0.8 * 0.9 (with floating point tolerance)


class TestIOCBatch:
    """Tests for IOCBatch model."""

    def test_create_ioc_batch(self):
        iocs = [
            NormalizedIOC(
                ioc_value=f"evil{i}.com",
                ioc_type=IOCType.DOMAIN,
                threat_type=ThreatType.C2,
                confidence=0.85,
                source=IOCSource.ALIENVAULT_OTX,
                first_seen=datetime.utcnow(),
                last_seen=datetime.utcnow(),
            )
            for i in range(3)
        ]

        batch = IOCBatch(
            batch_id="batch_123",
            source=IOCSource.ALIENVAULT_OTX,
            iocs=iocs,
            total_count=3,
        )
        assert batch.batch_id == "batch_123"
        assert len(batch.iocs) == 3
        assert batch.total_count == 3

    def test_batch_count_validation(self):
        iocs = [
            NormalizedIOC(
                ioc_value=f"evil{i}.com",
                ioc_type=IOCType.DOMAIN,
                threat_type=ThreatType.C2,
                confidence=0.85,
                source=IOCSource.ALIENVAULT_OTX,
                first_seen=datetime.utcnow(),
                last_seen=datetime.utcnow(),
            )
            for i in range(3)
        ]

        # Invalid: total_count doesn't match iocs length
        with pytest.raises(ValidationError):
            IOCBatch(
                batch_id="batch_123",
                source=IOCSource.ALIENVAULT_OTX,
                iocs=iocs,
                total_count=5,  # Wrong count
            )
