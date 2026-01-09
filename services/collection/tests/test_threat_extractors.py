"""Tests for threat extractors."""

import sys
from datetime import datetime
from pathlib import Path

import pytest

# Add src directory to path
src_path = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(src_path))

from threat_extractors.alienvault_threat_extractor import AlienVaultThreatExtractor
from threat_extractors.abusech_threat_extractor import AbuseCHThreatExtractor


class TestAlienVaultThreatExtractor:
    """Tests for AlienVaultThreatExtractor."""

    @pytest.fixture
    def extractor(self):
        """Create AlienVault threat extractor."""
        return AlienVaultThreatExtractor()

    def test_extract_threats_from_pulse(self, extractor, sample_alienvault_pulse):
        """Test extracting threats from AlienVault pulse."""
        threats = extractor.extract_threats(sample_alienvault_pulse)

        # Should extract actor and malware families
        assert len(threats) >= 1

        # Check if actor threat was extracted
        actor_threats = [t for t in threats if t.get("threat_category") == "actor"]
        assert len(actor_threats) >= 1

        actor = actor_threats[0]
        assert actor["name"] == "APT29"
        assert actor["threat_type"] == "c2"
        assert "threat_id" in actor
        assert len(actor.get("techniques", [])) > 0

    def test_extract_threat_associations(
        self, extractor, sample_alienvault_pulse
    ):
        """Test extracting threat-IOC associations."""
        # First extract threats to get a threat_id
        threats = extractor.extract_threats(sample_alienvault_pulse)
        assert len(threats) > 0
        threat_id = threats[0]["threat_id"]

        # Now extract associations with the threat_id
        associations = extractor.extract_threat_ioc_associations(
            sample_alienvault_pulse, threat_id
        )

        # Should create associations for each IOC with each threat
        assert len(associations) > 0

        assoc = associations[0]
        assert "threat_id" in assoc
        assert assoc["threat_id"] == threat_id
        assert "ioc_value" in assoc
        assert "ioc_type" in assoc
        assert "relationship_type" in assoc
        assert assoc["relationship_type"] in ["uses", "distributes", "communicates_with"]

    def test_extract_mitre_techniques(self, extractor, sample_alienvault_pulse):
        """Test MITRE ATT&CK technique extraction."""
        threats = extractor.extract_threats(sample_alienvault_pulse)

        # Find threat with techniques
        threat_with_techniques = next(
            (t for t in threats if len(t.get("techniques", [])) > 0), None
        )

        assert threat_with_techniques is not None
        techniques = threat_with_techniques["techniques"]
        assert len(techniques) > 0

        technique = techniques[0]
        assert "technique_id" in technique
        assert "technique_name" in technique
        assert "tactic" in technique
        assert technique["technique_id"].startswith("T")

    def test_extract_malware_families(self, extractor, sample_alienvault_pulse):
        """Test malware family extraction."""
        threats = extractor.extract_threats(sample_alienvault_pulse)

        # Should extract malware families
        malware_threats = [
            t for t in threats if t.get("threat_category") == "malware_family"
        ]
        assert len(malware_threats) >= 1

        malware = malware_threats[0]
        assert malware["name"] in ["Cobalt Strike", "MiniDuke"]
        assert malware["threat_category"] == "malware_family"

    def test_extract_campaign_fallback(self, extractor):
        """Test campaign extraction when no actor/malware specified."""
        pulse_without_actor = {
            "id": "test_pulse",
            "name": "Phishing Campaign - Q1 2024",
            "description": "Phishing campaign targeting financial sector",
            "created": "2024-01-01T00:00:00",
            "modified": "2024-01-01T00:00:00",
            "tags": ["phishing", "finance"],
            "indicators": [],
        }

        threats = extractor.extract_threats(pulse_without_actor)

        # Should create campaign threat
        assert len(threats) == 1
        campaign = threats[0]
        assert campaign["threat_category"] == "campaign"
        assert campaign["name"] == "Phishing Campaign - Q1 2024"

    def test_generate_threat_id(self, extractor):
        """Test threat ID generation."""
        # Correct parameter order: (source, identifier, timestamp)
        threat_id_1 = extractor._generate_threat_id(
            "alienvault_otx", "APT29"
        )
        threat_id_2 = extractor._generate_threat_id(
            "alienvault_otx", "APT29"
        )

        # Should generate consistent IDs
        assert threat_id_1 == threat_id_2
        assert threat_id_1.startswith("threat_")

    def test_extract_empty_pulse(self, extractor):
        """Test extraction from pulse with minimal data."""
        minimal_pulse = {
            "id": "minimal",
            "name": "Minimal Pulse",
            "created": "2024-01-01T00:00:00",
            "modified": "2024-01-01T00:00:00",
        }

        threats = extractor.extract_threats(minimal_pulse)

        # Should still create a campaign
        assert len(threats) >= 1


class TestAbuseCHThreatExtractor:
    """Tests for AbuseCHThreatExtractor."""

    @pytest.fixture
    def extractor(self):
        """Create abuse.ch threat extractor."""
        return AbuseCHThreatExtractor()

    def test_extract_threats_from_entry(self, extractor, sample_abusech_entry):
        """Test extracting threats from abuse.ch entry."""
        threats = extractor.extract_threats(sample_abusech_entry)

        # Should extract malware family
        assert len(threats) == 1

        threat = threats[0]
        assert threat["name"] == "AsyncRAT"
        assert threat["threat_category"] == "malware_family"
        assert threat["threat_type"] == "malware"
        assert "threat_id" in threat

    def test_parse_malware_family_name(self, extractor):
        """Test malware family name parsing."""
        malware_type, platform = extractor._parse_malware_family_name("win.asyncrat")

        assert malware_type == "trojan"
        assert platform == "Windows"

    def test_parse_different_platforms(self, extractor):
        """Test parsing different platform malware."""
        # Linux malware
        malware_type, platform = extractor._parse_malware_family_name("linux.mirai")
        assert platform == "Linux"

        # JavaScript malware
        malware_type, platform = extractor._parse_malware_family_name(
            "js.clearfake"
        )
        assert platform == "JavaScript"

        # Android malware
        malware_type, platform = extractor._parse_malware_family_name("apk.banker")
        assert platform == "Android"

    def test_extract_threat_associations(self, extractor, sample_abusech_entry):
        """Test extracting threat-IOC associations."""
        # First extract threats to get a threat_id
        threats = extractor.extract_threats(sample_abusech_entry)
        assert len(threats) > 0
        threat_id = threats[0]["threat_id"]

        # Now extract associations with the threat_id
        associations = extractor.extract_threat_ioc_associations(
            sample_abusech_entry, threat_id
        )

        assert len(associations) >= 1

        assoc = associations[0]
        assert assoc["ioc_value"] == "evil.com"
        assert assoc["ioc_type"] == "domain"
        assert assoc["relationship_type"] == "distributes"
        assert "threat_id" in assoc
        assert assoc["threat_id"] == threat_id

    def test_extract_multiple_malware(self, extractor):
        """Test extraction when entry has multiple malware families."""
        entry = {
            "id": "123",
            "dateadded": "2024-01-01 00:00:00 UTC",
            "ioc": "evil.com",
            "malware": "win.asyncrat,win.redline",
            "malware_printable": "AsyncRAT, RedLine",
            "ioc_type": "domain",
            "confidence_level": 90,
        }

        threats = extractor.extract_threats(entry)

        # Should extract both malware families
        assert len(threats) >= 2
        malware_names = [t["name"] for t in threats]
        assert "AsyncRAT" in malware_names or "RedLine" in malware_names

    def test_extract_no_malware(self, extractor):
        """Test extraction when no malware specified."""
        entry = {
            "id": "123",
            "dateadded": "2024-01-01 00:00:00 UTC",
            "ioc": "evil.com",
            "ioc_type": "domain",
        }

        threats = extractor.extract_threats(entry)

        # Should return empty list
        assert len(threats) == 0

    def test_confidence_mapping(self, extractor, sample_abusech_entry):
        """Test confidence score mapping."""
        threats = extractor.extract_threats(sample_abusech_entry)

        threat = threats[0]
        # 90% confidence should map to 0.9
        assert threat["confidence"] == 0.9

    def test_generate_threat_id_consistency(self, extractor):
        """Test threat ID generation is consistent."""
        # Correct parameter order: (source, identifier, timestamp)
        threat_id_1 = extractor._generate_threat_id(
            "abuse_ch", "AsyncRAT"
        )
        threat_id_2 = extractor._generate_threat_id(
            "abuse_ch", "AsyncRAT"
        )

        assert threat_id_1 == threat_id_2

    def test_extract_tags_from_entry(self, extractor, sample_abusech_entry):
        """Test tag extraction from abuse.ch entry."""
        threats = extractor.extract_threats(sample_abusech_entry)

        threat = threats[0]
        assert "tags" in threat
        assert len(threat["tags"]) > 0

    def test_extract_reference_urls(self, extractor, sample_abusech_entry):
        """Test reference URL extraction."""
        threats = extractor.extract_threats(sample_abusech_entry)

        threat = threats[0]
        assert "reference_urls" in threat
        if sample_abusech_entry.get("reference"):
            assert sample_abusech_entry["reference"] in threat["reference_urls"]
        if sample_abusech_entry.get("malware_malpedia"):
            assert sample_abusech_entry["malware_malpedia"] in threat["reference_urls"]


class TestThreatExtractorEdgeCases:
    """Tests for edge cases in threat extraction."""

    def test_alienvault_extractor_with_null_fields(self):
        """Test AlienVault extractor with null/missing fields."""
        extractor = AlienVaultThreatExtractor()

        pulse = {
            "id": "test",
            "name": None,  # Null name
            "created": "2024-01-01T00:00:00",
            "modified": "2024-01-01T00:00:00",
        }

        threats = extractor.extract_threats(pulse)

        # Should handle gracefully
        assert isinstance(threats, list)

    def test_abusech_extractor_with_unknown_platform(self):
        """Test abuse.ch extractor with unknown platform."""
        extractor = AbuseCHThreatExtractor()

        entry = {
            "id": "123",
            "dateadded": "2024-01-01 00:00:00 UTC",
            "ioc": "evil.com",
            "malware": "unknown.malware",
            "malware_printable": "Unknown Malware",
            "ioc_type": "domain",
        }

        threats = extractor.extract_threats(entry)

        # Should still extract with unknown platform
        assert len(threats) >= 1

    def test_invalid_mitre_technique_ids(self):
        """Test handling of invalid MITRE technique IDs."""
        extractor = AlienVaultThreatExtractor()

        pulse = {
            "id": "test",
            "name": "Test",
            "created": "2024-01-01T00:00:00",
            "modified": "2024-01-01T00:00:00",
            "attack_ids": ["INVALID", "T9999", "not-a-technique"],
        }

        threats = extractor.extract_threats(pulse)

        # Should filter out invalid techniques
        if len(threats) > 0:
            threat = threats[0]
            for technique in threat.get("techniques", []):
                # Valid technique IDs start with T and have numbers
                assert technique["technique_id"].startswith("T")
