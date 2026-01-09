"""abuse.ch threat extractor for malware families."""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .base import ThreatExtractor

logger = logging.getLogger(__name__)


class AbuseCHThreatExtractor(ThreatExtractor):
    """Extract malware family threats from abuse.ch feeds (ThreatFox, URLhaus)."""

    def __init__(self):
        """Initialize extractor with malware family cache."""
        # Cache to deduplicate malware families
        self._malware_cache = {}

    def extract_threats(self, raw_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Extract malware family threats from abuse.ch IOC data.

        abuse.ch provides excellent malware family attribution. We extract
        unique malware families and create threat entries for each.

        Args:
            raw_data: Raw IOC data from abuse.ch (ThreatFox or URLhaus)

        Returns:
            List of malware family threat dictionaries
        """
        threats = []
        malware_families_seen = set()

        # Extract from ThreatFox IOCs
        for ioc in raw_data.get("threatfox_iocs", []):
            malware_family = ioc.get("malware_family")
            if malware_family and malware_family not in malware_families_seen:
                threat = self._create_malware_threat(ioc)
                if threat:
                    threats.append(threat)
                    malware_families_seen.add(malware_family)

        # Extract from URLhaus IOCs (malware in tags)
        for ioc in raw_data.get("urlhaus_iocs", []):
            malware_names = self._extract_malware_from_tags(ioc.get("tags", []))
            for malware_name in malware_names:
                if malware_name not in malware_families_seen:
                    threat = self._create_malware_threat_from_urlhaus(ioc, malware_name)
                    if threat:
                        threats.append(threat)
                        malware_families_seen.add(malware_name)

        return threats

    def _create_malware_threat(self, ioc: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Create malware family threat from ThreatFox IOC."""
        malware_family = ioc.get("malware_family")
        if not malware_family:
            return None

        # Generate threat ID
        threat_id = self._generate_threat_id("abuse_ch", malware_family)

        # Get printable name and alias
        malware_printable = ioc.get("malware_printable", malware_family)
        malware_alias = ioc.get("malware_alias")

        aliases = [malware_printable]
        if malware_alias:
            aliases.append(malware_alias)

        # Determine malware type and platform
        malware_type, platform = self._parse_malware_family_name(malware_family)

        threat = {
            "threat_id": threat_id,
            "name": malware_printable,
            "aliases": list(set(aliases)),
            "threat_category": "malware_family",
            "threat_type": self._map_threat_type(ioc.get("threat_type", "malware")),
            "description": f"{malware_printable} malware family tracked by abuse.ch",
            "severity": self._calculate_severity(ioc),
            "confidence": self._normalize_confidence(ioc.get("confidence", 0.95)),
            "first_seen": datetime.now(timezone.utc).isoformat(),
            "last_seen": datetime.now(timezone.utc).isoformat(),
            "is_active": True,
            "techniques": [],  # abuse.ch doesn't provide TTPs
            "tactics": [],
            "sources": ["abuse_ch"],
            "reference_urls": [ioc.get("reference")] if ioc.get("reference") else [],
            "tags": [malware_family, malware_printable] + (ioc.get("tags") or []),
            "metadata": {
                "malware_family": malware_family,
                "malware_printable": malware_printable,
                "malware_alias": malware_alias,
                "malware_type": malware_type,
                "platform": platform,
                "reporter": ioc.get("reporter"),
                "feed": "threatfox",
            },
        }

        return threat

    def _create_malware_threat_from_urlhaus(
        self, ioc: Dict[str, Any], malware_name: str
    ) -> Optional[Dict[str, Any]]:
        """Create malware family threat from URLhaus IOC."""
        # Generate threat ID
        threat_id = self._generate_threat_id("abuse_ch", malware_name)

        # Determine malware type
        malware_type, platform = self._parse_malware_family_name(malware_name)

        threat = {
            "threat_id": threat_id,
            "name": malware_name,
            "aliases": [malware_name],
            "threat_category": "malware_family",
            "threat_type": "malware",
            "description": f"{malware_name} malware tracked by abuse.ch URLhaus",
            "severity": self._calculate_severity(ioc),
            "confidence": self._normalize_confidence(ioc.get("confidence", 0.8)),
            "first_seen": datetime.now(timezone.utc).isoformat(),
            "last_seen": datetime.now(timezone.utc).isoformat(),
            "is_active": ioc.get("url_status") == "online",
            "techniques": [],
            "tactics": [],
            "sources": ["abuse_ch"],
            "reference_urls": [],
            "tags": [malware_name] + (ioc.get("tags") or []),
            "metadata": {
                "malware_type": malware_type,
                "platform": platform,
                "reporter": ioc.get("reporter"),
                "feed": "urlhaus",
                "url_status": ioc.get("url_status"),
            },
        }

        return threat

    def extract_threat_ioc_associations(
        self, raw_data: Dict[str, Any], threat_id: str
    ) -> List[Dict[str, Any]]:
        """
        Extract threat-IOC associations from abuse.ch data.

        Args:
            raw_data: Raw IOC data from abuse.ch
            threat_id: ID of the malware family threat

        Returns:
            List of threat-IOC associations
        """
        associations = []

        # Associate ThreatFox IOCs
        for ioc in raw_data.get("threatfox_iocs", []):
            malware_family = ioc.get("malware_family")
            if not malware_family:
                continue

            # Check if this IOC belongs to this threat
            ioc_threat_id = self._generate_threat_id("abuse_ch", malware_family)
            if ioc_threat_id != threat_id:
                continue

            association = {
                "threat_id": threat_id,
                "ioc_value": ioc.get("ioc_value"),
                "ioc_type": ioc.get("ioc_type"),
                "relationship_type": self._map_relationship_type(ioc.get("threat_type")),
                "confidence": self._normalize_confidence(ioc.get("confidence", 0.95)),
                "first_seen": datetime.now(timezone.utc).isoformat(),
                "last_seen": datetime.now(timezone.utc).isoformat(),
                "observation_count": 1,
                "sources": ["abuse_ch"],
                "reference_urls": [ioc.get("reference")] if ioc.get("reference") else [],
                "notes": f"Reported by {ioc.get('reporter')}",
                "tags": ioc.get("tags") or [],
            }

            associations.append(association)

        # Associate URLhaus IOCs
        for ioc in raw_data.get("urlhaus_iocs", []):
            malware_names = self._extract_malware_from_tags(ioc.get("tags", []))

            for malware_name in malware_names:
                ioc_threat_id = self._generate_threat_id("abuse_ch", malware_name)
                if ioc_threat_id != threat_id:
                    continue

                association = {
                    "threat_id": threat_id,
                    "ioc_value": ioc.get("ioc_value"),
                    "ioc_type": ioc.get("ioc_type"),
                    "relationship_type": "distributes",
                    "confidence": self._normalize_confidence(ioc.get("confidence", 0.8)),
                    "first_seen": datetime.now(timezone.utc).isoformat(),
                    "last_seen": datetime.now(timezone.utc).isoformat(),
                    "observation_count": 1,
                    "sources": ["abuse_ch"],
                    "reference_urls": [],
                    "notes": f"URL status: {ioc.get('url_status')}",
                    "tags": ioc.get("tags") or [],
                }

                associations.append(association)

        return associations

    # Helper methods

    def _extract_malware_from_tags(self, tags: List[str]) -> List[str]:
        """Extract malware family names from tags."""
        malware_names = []

        # Common malware families to look for in tags
        known_malware = [
            "mozi",
            "mirai",
            "clearfake",
            "emotet",
            "trickbot",
            "qakbot",
            "cobalt strike",
            "metasploit",
            "asyncrat",
            "remcos",
            "njrat",
        ]

        for tag in tags:
            tag_lower = tag.lower()
            for malware in known_malware:
                if malware in tag_lower:
                    malware_names.append(tag)
                    break

        return malware_names

    def _parse_malware_family_name(self, malware_family: str) -> tuple:
        """
        Parse malware family name to extract type and platform.

        Format: platform.family (e.g., win.asyncrat, js.clearfake)

        Returns:
            Tuple of (malware_type, platform)
        """
        parts = malware_family.split(".")

        if len(parts) >= 2:
            platform = parts[0]
            family = ".".join(parts[1:])

            # Map platform
            platform_map = {
                "win": "Windows",
                "linux": "Linux",
                "android": "Android",
                "js": "JavaScript",
                "php": "PHP",
                "python": "Python",
                "macos": "macOS",
            }

            # Determine malware type
            malware_type = self._determine_malware_type_from_name(family)

            return malware_type, platform_map.get(platform, platform)

        return "malware", "Unknown"

    def _determine_malware_type_from_name(self, name: str) -> str:
        """Determine malware type from name."""
        name_lower = name.lower()

        if "rat" in name_lower or "remote" in name_lower:
            return "trojan"
        elif "ransom" in name_lower:
            return "ransomware"
        elif "loader" in name_lower or "dropper" in name_lower:
            return "loader"
        elif "miner" in name_lower or "crypto" in name_lower:
            return "cryptominer"
        elif "bot" in name_lower:
            return "botnet"
        else:
            return "malware"

    def _map_threat_type(self, abuse_ch_type: str) -> str:
        """Map abuse.ch threat type to standard threat type."""
        type_map = {
            "payload": "malware",
            "payload_delivery": "malware",
            "c2": "c2",
            "botnet_cc": "c2",
        }
        return type_map.get(abuse_ch_type, "malware")

    def _map_relationship_type(self, abuse_ch_type: str) -> str:
        """Map abuse.ch threat type to relationship type."""
        if abuse_ch_type == "c2" or abuse_ch_type == "botnet_cc":
            return "communicates_with"
        elif abuse_ch_type == "payload_delivery":
            return "distributes"
        else:
            return "uses"

    def _calculate_severity(self, ioc: Dict[str, Any]) -> str:
        """Calculate severity based on IOC context."""
        confidence = ioc.get("confidence", 0)

        # abuse.ch typically marks high-confidence malware
        if confidence >= 0.95:
            return "high"
        elif confidence >= 0.8:
            return "medium"
        else:
            return "low"
