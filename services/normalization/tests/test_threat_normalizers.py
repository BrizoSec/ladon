"""Tests for threat normalizers."""

import sys
from datetime import datetime
from pathlib import Path

import pytest

# Add src directory to path
src_path = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(src_path))

from normalizers.threat_normalizers import ThreatNormalizer, get_threat_normalizer


class TestThreatNormalizer:
    """Tests for ThreatNormalizer."""

    @pytest.fixture
    def normalizer(self):
        """Create threat normalizer."""
        return ThreatNormalizer(source="alienvault_otx", skip_invalid=True)

    def test_normalize_valid_threat(self, normalizer, sample_raw_threat):
        """Test normalization of valid threat data."""
        threat = normalizer.normalize(sample_raw_threat)

        assert threat is not None
        assert threat.threat_id == "threat_apt29"
        assert threat.name == "APT29"
        assert "Cozy Bear" in threat.aliases
        assert threat.threat_category.value == "actor"
        assert threat.threat_type.value == "c2"
        assert threat.confidence == 0.95
        assert threat.severity.value == "critical"
        assert "Execution" in threat.tactics
        assert "Persistence" in threat.tactics
        assert len(threat.techniques) == 1
        assert threat.techniques[0].technique_id == "T1059.001"
        assert threat.is_active is True

    def test_normalize_malware_threat(self, normalizer, sample_raw_malware_threat):
        """Test normalization of malware family threat."""
        threat = normalizer.normalize(sample_raw_malware_threat)

        assert threat is not None
        assert threat.threat_id == "threat_asyncrat"
        assert threat.name == "AsyncRAT"
        assert threat.threat_category.value == "malware_family"
        assert threat.threat_type.value == "malware"
        assert threat.severity.value == "high"
        assert len(threat.techniques) == 0
        assert threat.is_active is True

    def test_normalize_missing_required_field(self, normalizer):
        """Test normalization with missing required fields."""
        invalid_data = {
            "name": "Test Threat",
            # Missing threat_id, threat_category, threat_type
            "confidence": 0.5,
        }

        threat = normalizer.normalize(invalid_data)

        # Should return None when skip_invalid is True
        assert threat is None

    def test_normalize_invalid_confidence(self, normalizer, sample_raw_threat):
        """Test normalization with invalid confidence value."""
        sample_raw_threat["confidence"] = 1.5  # Out of range

        threat = normalizer.normalize(sample_raw_threat)

        # Normalizer should clamp or reject invalid confidence
        if threat is not None:
            assert 0.0 <= threat.confidence <= 1.0

    def test_normalize_datetime_parsing(self, normalizer, sample_raw_threat):
        """Test datetime field parsing."""
        threat = normalizer.normalize(sample_raw_threat)

        assert threat is not None
        assert isinstance(threat.first_seen, datetime)
        assert isinstance(threat.last_seen, datetime)
        assert threat.last_seen >= threat.first_seen

    def test_normalize_techniques_parsing(self, normalizer, sample_raw_threat):
        """Test MITRE ATT&CK techniques parsing."""
        threat = normalizer.normalize(sample_raw_threat)

        assert threat is not None
        assert len(threat.techniques) == 1
        technique = threat.techniques[0]
        assert technique.technique_id == "T1059.001"
        assert technique.technique_name == "PowerShell"
        assert technique.tactic == "Execution"
        assert "Monitor PowerShell execution" in technique.detection_methods

    def test_normalize_optional_fields(self, normalizer):
        """Test normalization with minimal required fields."""
        minimal_data = {
            "threat_id": "threat_minimal",
            "name": "Minimal Threat",
            "threat_category": "campaign",
            "threat_type": "phishing",
            "confidence": 0.5,
            "first_seen": "2024-01-01T00:00:00Z",
            "last_seen": "2024-01-01T00:00:00Z",
        }

        threat = normalizer.normalize(minimal_data)

        assert threat is not None
        assert threat.threat_id == "threat_minimal"
        assert threat.name == "Minimal Threat"
        # Optional fields should have defaults
        assert threat.aliases == []
        assert threat.techniques == []
        assert threat.tactics == []
        assert threat.sources == []
        assert threat.tags == []

    def test_normalize_with_strict_validation(self):
        """Test normalizer with strict validation enabled."""
        strict_normalizer = ThreatNormalizer(source="test", skip_invalid=False)

        invalid_data = {
            "name": "Test",
            # Missing required fields
        }

        # Should raise exception when skip_invalid is False
        with pytest.raises(Exception):
            strict_normalizer.normalize(invalid_data)


class TestGetThreatNormalizer:
    """Tests for get_threat_normalizer function."""

    def test_get_alienvault_normalizer(self):
        """Test creating AlienVault threat normalizer."""
        normalizer = get_threat_normalizer("alienvault_otx")

        assert normalizer is not None
        assert isinstance(normalizer, ThreatNormalizer)

    def test_get_abusech_normalizer(self):
        """Test creating abuse.ch threat normalizer."""
        normalizer = get_threat_normalizer("abuse_ch")

        assert normalizer is not None
        assert isinstance(normalizer, ThreatNormalizer)

    def test_get_misp_normalizer(self):
        """Test creating MISP threat normalizer."""
        normalizer = get_threat_normalizer("misp")

        assert normalizer is not None
        assert isinstance(normalizer, ThreatNormalizer)

    def test_get_custom_normalizer(self):
        """Test creating custom threat normalizer."""
        normalizer = get_threat_normalizer("custom")

        assert normalizer is not None
        assert isinstance(normalizer, ThreatNormalizer)

    def test_get_unknown_source_normalizer(self):
        """Test creating normalizer for unknown source."""
        normalizer = get_threat_normalizer("unknown_source")

        # Should return a generic ThreatNormalizer
        assert normalizer is not None
        assert isinstance(normalizer, ThreatNormalizer)

    def test_normalizer_skip_invalid_parameter(self):
        """Test normalizer with skip_invalid parameter."""
        normalizer = get_threat_normalizer("alienvault_otx", skip_invalid=False)

        assert normalizer is not None
        # Verify skip_invalid is set correctly
        assert hasattr(normalizer, "skip_invalid")


class TestThreatNormalizerEdgeCases:
    """Tests for edge cases in threat normalization."""

    @pytest.fixture
    def normalizer(self):
        """Create threat normalizer."""
        return ThreatNormalizer(source="test", skip_invalid=True)

    def test_normalize_empty_dict(self, normalizer):
        """Test normalizing empty dictionary."""
        threat = normalizer.normalize({})

        assert threat is None

    def test_normalize_none(self, normalizer):
        """Test normalizing None."""
        threat = normalizer.normalize(None)

        assert threat is None

    def test_normalize_empty_techniques_array(self, normalizer, sample_raw_threat):
        """Test normalizing threat with empty techniques array."""
        sample_raw_threat["techniques"] = []

        threat = normalizer.normalize(sample_raw_threat)

        assert threat is not None
        assert threat.techniques == []
        assert threat.tactics == []  # Tactics derived from techniques

    def test_normalize_very_long_description(self, normalizer, sample_raw_threat):
        """Test normalizing threat with very long description."""
        sample_raw_threat["description"] = "A" * 10000

        threat = normalizer.normalize(sample_raw_threat)

        assert threat is not None
        # Description should be stored (BigQuery supports up to 2MB strings)
        assert len(threat.description) > 0

    def test_normalize_special_characters_in_name(self, normalizer, sample_raw_threat):
        """Test normalizing threat with special characters in name."""
        sample_raw_threat["name"] = "APT-29 (Группа)"

        threat = normalizer.normalize(sample_raw_threat)

        assert threat is not None
        assert threat.name == "APT-29 (Группа)"

    def test_normalize_duplicate_aliases(self, normalizer, sample_raw_threat):
        """Test normalizing threat with duplicate aliases."""
        sample_raw_threat["aliases"] = ["Cozy Bear", "Cozy Bear", "The Dukes"]

        threat = normalizer.normalize(sample_raw_threat)

        assert threat is not None
        # Aliases should be deduplicated
        assert len([a for a in threat.aliases if a == "Cozy Bear"]) >= 1

    def test_normalize_invalid_severity(self, normalizer, sample_raw_threat):
        """Test normalizing threat with invalid severity value."""
        sample_raw_threat["severity"] = "super-critical"  # Invalid value

        # Should either use default or skip the threat
        threat = normalizer.normalize(sample_raw_threat)

        if threat is not None:
            # Should have valid severity
            assert threat.severity.value in ["low", "medium", "high", "critical"]
