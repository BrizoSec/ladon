"""Threat normalizers for different threat intelligence sources."""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from ladon_models import Threat

from .base import BaseNormalizer

logger = logging.getLogger(__name__)


class ThreatNormalizer(BaseNormalizer):
    """Base class for threat normalizers."""

    def normalize(self, raw_data: Dict[str, Any]) -> Optional[Threat]:
        """Normalize raw threat data.

        Args:
            raw_data: Raw threat dictionary

        Returns:
            Threat model or None if validation fails
        """
        try:
            # Extract required fields
            threat_id = self._extract_field(raw_data, "threat_id", required=True)
            name = self._extract_field(raw_data, "name", required=True)
            threat_category = self._extract_field(raw_data, "threat_category", required=True)
            threat_type = self._extract_field(raw_data, "threat_type", required=True)

            # Extract optional fields
            aliases = self._extract_field(raw_data, "aliases", default=[])
            description = self._extract_field(raw_data, "description", default="")
            severity = self._extract_field(raw_data, "severity", default="unknown")
            confidence = float(self._extract_field(raw_data, "confidence", default=0.5))

            first_seen = self._parse_timestamp(
                self._extract_field(raw_data, "first_seen", default=datetime.utcnow())
            )
            last_seen = self._parse_timestamp(
                self._extract_field(raw_data, "last_seen", default=datetime.utcnow())
            )
            is_active = self._extract_field(raw_data, "is_active", default=True)

            # Extract MITRE ATT&CK data
            techniques = self._extract_field(raw_data, "techniques", default=[])
            tactics = self._extract_field(raw_data, "tactics", default=[])

            # Extract contextual data
            sources = self._extract_field(raw_data, "sources", default=[])
            reference_urls = self._extract_field(raw_data, "reference_urls", default=[])
            tags = self._extract_field(raw_data, "tags", default=[])
            metadata = self._extract_field(raw_data, "metadata", default={})

            # Extract associated IOC IDs (if available)
            associated_ioc_ids = self._extract_field(raw_data, "associated_ioc_ids", default=[])

            # Create Threat model
            threat = Threat(
                threat_id=threat_id,
                name=name,
                aliases=aliases,
                threat_category=threat_category,
                threat_type=threat_type,
                description=description,
                severity=severity,
                confidence=confidence,
                first_seen=first_seen,
                last_seen=last_seen,
                is_active=is_active,
                techniques=techniques,
                tactics=tactics,
                sources=sources,
                reference_urls=reference_urls,
                tags=tags,
                metadata=metadata,
                associated_ioc_ids=associated_ioc_ids,
                # Category-specific fields are handled by metadata
                actor=None,
                campaign=None,
                malware=None,
            )

            return threat

        except Exception as e:
            logger.error(f"Failed to normalize threat: {e}")
            if not self.skip_invalid:
                raise
            return None


class AlienVaultThreatNormalizer(ThreatNormalizer):
    """Normalizer for AlienVault OTX threats.

    Normalizes threats extracted from AlienVault OTX pulses including:
    - Threat actors (adversaries)
    - Malware families
    - Campaigns
    """

    def __init__(self, skip_invalid: bool = True):
        super().__init__(source_name="alienvault_otx", skip_invalid=skip_invalid)


class AbuseCHThreatNormalizer(ThreatNormalizer):
    """Normalizer for abuse.ch threats.

    Normalizes malware families extracted from abuse.ch feeds:
    - ThreatFox malware families
    - URLhaus malware tags
    """

    def __init__(self, skip_invalid: bool = True):
        super().__init__(source_name="abuse_ch", skip_invalid=skip_invalid)


class MISPThreatNormalizer(ThreatNormalizer):
    """Normalizer for MISP threats.

    Normalizes threat intelligence from MISP galaxy clusters.
    """

    def __init__(self, skip_invalid: bool = True):
        super().__init__(source_name="misp", skip_invalid=skip_invalid)


class GenericThreatNormalizer(ThreatNormalizer):
    """Generic threat normalizer for custom sources."""

    def __init__(self, source_name: str, skip_invalid: bool = True):
        super().__init__(source_name=source_name, skip_invalid=skip_invalid)


def get_threat_normalizer(source: str, skip_invalid: bool = True) -> ThreatNormalizer:
    """Factory function to get appropriate threat normalizer.

    Args:
        source: Source name
        skip_invalid: Skip invalid threats

    Returns:
        Threat normalizer instance
    """
    normalizer_map = {
        "alienvault_otx": AlienVaultThreatNormalizer,
        "abuse_ch": AbuseCHThreatNormalizer,
        "abuse_ch_threatfox": AbuseCHThreatNormalizer,
        "abuse_ch_urlhaus": AbuseCHThreatNormalizer,
        "misp": MISPThreatNormalizer,
    }

    normalizer_class = normalizer_map.get(source, GenericThreatNormalizer)

    if normalizer_class == GenericThreatNormalizer:
        return normalizer_class(source_name=source, skip_invalid=skip_invalid)
    else:
        return normalizer_class(skip_invalid=skip_invalid)
