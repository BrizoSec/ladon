"""Tests for Detection models."""

from datetime import datetime, timedelta

import pytest

from ladon_models import (
    ActivitySource,
    Detection,
    DetectionStatus,
    EnrichmentData,
    EnrichmentProvider,
    IOCSource,
    IOCType,
    NormalizedIOC,
    Severity,
    SeverityScore,
    ThreatType,
)


class TestSeverityScore:
    """Tests for SeverityScore model."""

    def test_calculate_basic_severity(self):
        ioc = NormalizedIOC(
            ioc_value="evil.com",
            ioc_type=IOCType.DOMAIN,
            threat_type=ThreatType.C2,
            confidence=0.8,
            source=IOCSource.ALIENVAULT_OTX,
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
        )

        score = SeverityScore.calculate(ioc, ActivitySource.DNS)

        assert score.base_score == 80.0  # 0.8 * 100
        assert score.severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM]

    def test_calculate_severity_with_high_confidence_c2(self):
        ioc = NormalizedIOC(
            ioc_value="evil.com",
            ioc_type=IOCType.DOMAIN,
            threat_type=ThreatType.C2,
            confidence=0.9,
            source=IOCSource.ABUSE_CH,  # 1.2x multiplier
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
        )

        # C2 threat has 1.5x multiplier, abuse.ch has 1.2x
        # Base: 90, with multipliers: 90 * 1.2 * 1.5 = 162 (capped at 100)
        score = SeverityScore.calculate(ioc, ActivitySource.DNS)

        assert score.final_score == 100.0  # Capped at 100
        assert score.severity == Severity.CRITICAL

    def test_calculate_severity_ransomware_critical(self):
        ioc = NormalizedIOC(
            ioc_value="192.0.2.1",
            ioc_type=IOCType.IP,
            threat_type=ThreatType.RANSOMWARE,  # 2.0x multiplier
            confidence=0.8,
            source=IOCSource.THREAT_FOX,  # 1.2x multiplier
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
        )

        # Base: 80, with multipliers: 80 * 1.2 * 2.0 = 192 (capped)
        # Sinkhole activity source: 1.8x
        score = SeverityScore.calculate(
            ioc, ActivitySource.SINKHOLE, asset_criticality="critical"
        )

        assert score.final_score == 100.0
        assert score.severity == Severity.CRITICAL
        assert score.threat_type_multiplier == 2.0
        assert score.activity_source_multiplier == 1.8
        assert score.asset_criticality_multiplier == 1.5

    def test_calculate_severity_low_confidence(self):
        ioc = NormalizedIOC(
            ioc_value="suspicious.com",
            ioc_type=IOCType.DOMAIN,
            threat_type=ThreatType.SUSPICIOUS,
            confidence=0.3,
            source=IOCSource.CUSTOM,  # 0.8x multiplier
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
        )

        score = SeverityScore.calculate(ioc, ActivitySource.DNS)

        # Base: 30, with custom source: 30 * 0.8 = 24
        assert score.final_score < 40
        assert score.severity == Severity.LOW

    def test_severity_thresholds(self):
        # Test CRITICAL threshold (>= 80)
        ioc_critical = NormalizedIOC(
            ioc_value="evil.com",
            ioc_type=IOCType.DOMAIN,
            threat_type=ThreatType.RANSOMWARE,
            confidence=0.85,
            source=IOCSource.ABUSE_CH,
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
        )
        score_critical = SeverityScore.calculate(ioc_critical, ActivitySource.DNS)
        # 85 * 1.2 * 2.0 = 204 -> capped at 100
        assert score_critical.severity == Severity.CRITICAL

        # Test MEDIUM threshold (>= 40, < 60)
        ioc_medium = NormalizedIOC(
            ioc_value="suspicious.com",
            ioc_type=IOCType.DOMAIN,
            threat_type=ThreatType.SUSPICIOUS,
            confidence=0.5,
            source=IOCSource.ALIENVAULT_OTX,
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
        )
        score_medium = SeverityScore.calculate(ioc_medium, ActivitySource.DNS)
        # 50 * 1.1 = 55
        assert score_medium.severity == Severity.MEDIUM


class TestEnrichmentData:
    """Tests for EnrichmentData model."""

    def test_create_enrichment_data(self):
        enrichment = EnrichmentData(
            provider=EnrichmentProvider.VIRUSTOTAL,
            reputation_score=85.0,
            categories=["malware", "c2"],
            country="US",
            malware_families=["Emotet"],
        )
        assert enrichment.provider == EnrichmentProvider.VIRUSTOTAL
        assert enrichment.reputation_score == 85.0
        assert "malware" in enrichment.categories

    def test_enrichment_with_custom_data(self):
        enrichment = EnrichmentData(
            provider=EnrichmentProvider.SHODAN,
            data={"ports": [80, 443], "services": ["http", "https"]},
        )
        assert enrichment.data["ports"] == [80, 443]


class TestDetection:
    """Tests for Detection model."""

    def test_create_basic_detection(self):
        detection = Detection(
            detection_id="det_12345",
            timestamp=datetime.utcnow(),
            ioc_value="evil.com",
            ioc_type="domain",
            activity_event_id="evt_12345",
            activity_source=ActivitySource.DNS,
            severity=Severity.HIGH,
            confidence=0.85,
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
        )
        assert detection.detection_id == "det_12345"
        assert detection.severity == Severity.HIGH
        assert detection.status == DetectionStatus.NEW

    def test_create_detection_with_ioc(self):
        ioc = NormalizedIOC(
            ioc_value="evil.com",
            ioc_type=IOCType.DOMAIN,
            threat_type=ThreatType.C2,
            confidence=0.85,
            source=IOCSource.ALIENVAULT_OTX,
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
        )

        detection = Detection(
            detection_id="det_12345",
            timestamp=datetime.utcnow(),
            ioc_value="evil.com",
            ioc_type="domain",
            ioc=ioc,
            activity_event_id="evt_12345",
            activity_source=ActivitySource.DNS,
            severity=Severity.HIGH,
            confidence=0.85,
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
        )
        assert detection.ioc.ioc_value == "evil.com"

    def test_auto_calculate_severity(self):
        ioc = NormalizedIOC(
            ioc_value="evil.com",
            ioc_type=IOCType.DOMAIN,
            threat_type=ThreatType.C2,
            confidence=0.85,
            source=IOCSource.ALIENVAULT_OTX,
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
        )

        # Don't provide severity_score, it should be calculated
        detection = Detection(
            detection_id="det_12345",
            timestamp=datetime.utcnow(),
            ioc_value="evil.com",
            ioc_type="domain",
            ioc=ioc,
            activity_event_id="evt_12345",
            activity_source=ActivitySource.DNS,
            severity=Severity.HIGH,  # Will be overridden
            confidence=0.85,
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
        )

        # Severity score should be calculated
        assert detection.severity_score is not None
        assert detection.severity == detection.severity_score.severity

    def test_add_analyst_note(self):
        detection = Detection(
            detection_id="det_12345",
            timestamp=datetime.utcnow(),
            ioc_value="evil.com",
            ioc_type="domain",
            activity_event_id="evt_12345",
            activity_source=ActivitySource.DNS,
            severity=Severity.HIGH,
            confidence=0.85,
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
        )

        detection.add_analyst_note("Investigating this detection", "jdoe")
        assert len(detection.analyst_notes) == 1
        assert "jdoe" in detection.analyst_notes[0]
        assert "Investigating" in detection.analyst_notes[0]

    def test_mark_false_positive(self):
        detection = Detection(
            detection_id="det_12345",
            timestamp=datetime.utcnow(),
            ioc_value="evil.com",
            ioc_type="domain",
            activity_event_id="evt_12345",
            activity_source=ActivitySource.DNS,
            severity=Severity.HIGH,
            confidence=0.85,
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
        )

        detection.mark_false_positive("Internal testing domain", "jdoe")

        assert detection.status == DetectionStatus.FALSE_POSITIVE
        assert detection.false_positive_reason == "Internal testing domain"
        assert detection.resolved_at is not None
        assert len(detection.analyst_notes) == 1

    def test_is_critical(self):
        critical_detection = Detection(
            detection_id="det_12345",
            timestamp=datetime.utcnow(),
            ioc_value="evil.com",
            ioc_type="domain",
            activity_event_id="evt_12345",
            activity_source=ActivitySource.DNS,
            severity=Severity.CRITICAL,
            confidence=0.95,
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
        )
        assert critical_detection.is_critical()

        high_detection = Detection(
            detection_id="det_12346",
            timestamp=datetime.utcnow(),
            ioc_value="evil.com",
            ioc_type="domain",
            activity_event_id="evt_12346",
            activity_source=ActivitySource.DNS,
            severity=Severity.HIGH,
            confidence=0.85,
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
        )
        assert not high_detection.is_critical()

    def test_is_high_or_critical(self):
        critical = Detection(
            detection_id="det_1",
            timestamp=datetime.utcnow(),
            ioc_value="evil.com",
            ioc_type="domain",
            activity_event_id="evt_1",
            activity_source=ActivitySource.DNS,
            severity=Severity.CRITICAL,
            confidence=0.95,
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
        )
        assert critical.is_high_or_critical()

        high = Detection(
            detection_id="det_2",
            timestamp=datetime.utcnow(),
            ioc_value="evil.com",
            ioc_type="domain",
            activity_event_id="evt_2",
            activity_source=ActivitySource.DNS,
            severity=Severity.HIGH,
            confidence=0.85,
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
        )
        assert high.is_high_or_critical()

        medium = Detection(
            detection_id="det_3",
            timestamp=datetime.utcnow(),
            ioc_value="evil.com",
            ioc_type="domain",
            activity_event_id="evt_3",
            activity_source=ActivitySource.DNS,
            severity=Severity.MEDIUM,
            confidence=0.5,
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
        )
        assert not medium.is_high_or_critical()

    def test_age_hours(self):
        past = datetime.utcnow() - timedelta(hours=3)
        detection = Detection(
            detection_id="det_12345",
            timestamp=past,
            ioc_value="evil.com",
            ioc_type="domain",
            activity_event_id="evt_12345",
            activity_source=ActivitySource.DNS,
            severity=Severity.HIGH,
            confidence=0.85,
            first_seen=past,
            last_seen=datetime.utcnow(),
        )
        assert detection.age_hours() >= 3

    def test_update_resolved_at_on_status_change(self):
        detection = Detection(
            detection_id="det_12345",
            timestamp=datetime.utcnow(),
            ioc_value="evil.com",
            ioc_type="domain",
            activity_event_id="evt_12345",
            activity_source=ActivitySource.DNS,
            severity=Severity.HIGH,
            confidence=0.85,
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
        )

        assert detection.resolved_at is None

        # Change status to resolved
        detection.status = DetectionStatus.RESOLVED
        detection = Detection(**detection.model_dump())  # Re-validate

        assert detection.resolved_at is not None

    def test_detection_with_enrichment(self):
        enrichment = EnrichmentData(
            provider=EnrichmentProvider.VIRUSTOTAL,
            reputation_score=85.0,
            malware_families=["Emotet"],
        )

        detection = Detection(
            detection_id="det_12345",
            timestamp=datetime.utcnow(),
            ioc_value="evil.com",
            ioc_type="domain",
            activity_event_id="evt_12345",
            activity_source=ActivitySource.DNS,
            severity=Severity.HIGH,
            confidence=0.85,
            enrichment={"virustotal": enrichment},
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
        )

        assert "virustotal" in detection.enrichment
        assert detection.enrichment["virustotal"].reputation_score == 85.0
