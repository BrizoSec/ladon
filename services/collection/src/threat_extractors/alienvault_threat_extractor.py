"""AlienVault OTX threat extractor."""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .base import ThreatExtractor

logger = logging.getLogger(__name__)


class AlienVaultThreatExtractor(ThreatExtractor):
    """Extract threat intelligence from AlienVault OTX pulses."""

    def extract_threats(self, raw_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Extract threats from AlienVault OTX pulse data.

        AlienVault pulses contain rich threat context including:
        - Adversary names (threat actors)
        - Malware families
        - MITRE ATT&CK techniques
        - Targeted industries and countries

        Args:
            raw_data: Raw pulse data from AlienVault OTX

        Returns:
            List of threat dictionaries
        """
        threats = []

        # A pulse can represent multiple threat types
        # 1. If it has an adversary, create a threat actor
        # 2. If it has malware families, create malware threats
        # 3. The pulse itself can be treated as a campaign

        # Extract threat actor if adversary is specified
        if raw_data.get("adversary"):
            actor_threat = self._extract_threat_actor(raw_data)
            if actor_threat:
                threats.append(actor_threat)

        # Extract malware family threats
        if raw_data.get("malware_families"):
            malware_threats = self._extract_malware_families(raw_data)
            threats.extend(malware_threats)

        # If no specific actor or malware, treat pulse as a campaign
        if not threats:
            campaign_threat = self._extract_campaign(raw_data)
            if campaign_threat:
                threats.append(campaign_threat)

        return threats

    def _extract_threat_actor(self, pulse: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Extract threat actor from pulse adversary field."""
        adversary = pulse.get("adversary", "").strip()
        if not adversary:
            return None

        # Generate threat ID
        threat_id = self._generate_threat_id("alienvault_otx", pulse["id"])

        # Parse MITRE ATT&CK techniques
        techniques = []
        tactics = []
        if pulse.get("attack_ids"):
            techniques = self._parse_mitre_techniques(pulse["attack_ids"])
            tactics = self._extract_tactics_from_techniques(techniques)

        # Extract actor type from tags or default
        actor_type = self._determine_actor_type(adversary, pulse.get("tags", []))

        # Determine sophistication
        sophistication = self._determine_sophistication(techniques, pulse)

        threat = {
            "threat_id": threat_id,
            "name": adversary,
            "aliases": self._extract_aliases(adversary, pulse.get("tags", [])),
            "threat_category": "actor",
            "threat_type": self._map_threat_type(pulse),
            "description": pulse.get("description", f"Threat actor: {adversary}"),
            "severity": self._calculate_severity(pulse),
            "confidence": 0.8,  # AlienVault OTX generally high quality
            "first_seen": self._parse_date(pulse.get("created")),
            "last_seen": self._parse_date(pulse.get("modified")),
            "is_active": True,
            "techniques": techniques,
            "tactics": tactics,
            "sources": ["alienvault_otx"],
            "reference_urls": pulse.get("references", []),
            "tags": self._normalize_tags(pulse.get("tags", []), adversary),
            "metadata": {
                "pulse_id": pulse.get("id"),
                "pulse_name": pulse.get("name"),
                "author": pulse.get("author_name"),
                "tlp": pulse.get("tlp"),
                "targeted_countries": pulse.get("targeted_countries", []),
                "industries": pulse.get("industries", []),
                "actor_type": actor_type,
                "sophistication": sophistication,
            },
        }

        return threat

    def _extract_malware_families(self, pulse: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract malware family threats from pulse."""
        threats = []

        for malware_name in pulse.get("malware_families", []):
            if not malware_name:
                continue

            # Generate unique threat ID for this malware family
            threat_id = self._generate_threat_id(
                "alienvault_otx",
                f"{pulse['id']}_{malware_name}"
            )

            # Parse techniques
            techniques = []
            tactics = []
            if pulse.get("attack_ids"):
                techniques = self._parse_mitre_techniques(pulse["attack_ids"])
                tactics = self._extract_tactics_from_techniques(techniques)

            threat = {
                "threat_id": threat_id,
                "name": malware_name,
                "aliases": [malware_name],
                "threat_category": "malware_family",
                "threat_type": "malware",
                "description": pulse.get("description", f"Malware family: {malware_name}"),
                "severity": self._calculate_severity(pulse),
                "confidence": 0.85,
                "first_seen": self._parse_date(pulse.get("created")),
                "last_seen": self._parse_date(pulse.get("modified")),
                "is_active": True,
                "techniques": techniques,
                "tactics": tactics,
                "sources": ["alienvault_otx"],
                "reference_urls": pulse.get("references", []),
                "tags": self._normalize_tags(pulse.get("tags", []), malware_name),
                "metadata": {
                    "pulse_id": pulse.get("id"),
                    "pulse_name": pulse.get("name"),
                    "author": pulse.get("author_name"),
                    "malware_type": self._determine_malware_type(malware_name, pulse.get("tags", [])),
                    "targeted_industries": pulse.get("industries", []),
                },
            }

            threats.append(threat)

        return threats

    def _extract_campaign(self, pulse: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Extract campaign threat from pulse."""
        # Generate threat ID
        threat_id = self._generate_threat_id("alienvault_otx", pulse["id"])

        # Parse techniques
        techniques = []
        tactics = []
        if pulse.get("attack_ids"):
            techniques = self._parse_mitre_techniques(pulse["attack_ids"])
            tactics = self._extract_tactics_from_techniques(techniques)

        threat = {
            "threat_id": threat_id,
            "name": pulse.get("name", "Unknown Campaign"),
            "aliases": [],
            "threat_category": "campaign",
            "threat_type": self._map_threat_type(pulse),
            "description": pulse.get("description", "Threat campaign"),
            "severity": self._calculate_severity(pulse),
            "confidence": 0.75,
            "first_seen": self._parse_date(pulse.get("created")),
            "last_seen": self._parse_date(pulse.get("modified")),
            "is_active": True,
            "techniques": techniques,
            "tactics": tactics,
            "sources": ["alienvault_otx"],
            "reference_urls": pulse.get("references", []),
            "tags": pulse.get("tags", []),
            "metadata": {
                "pulse_id": pulse.get("id"),
                "author": pulse.get("author_name"),
                "tlp": pulse.get("tlp"),
                "targeted_countries": pulse.get("targeted_countries", []),
                "industries": pulse.get("industries", []),
            },
        }

        return threat

    def extract_threat_ioc_associations(
        self, raw_data: Dict[str, Any], threat_id: str
    ) -> List[Dict[str, Any]]:
        """
        Extract threat-IOC associations from pulse indicators.

        Args:
            raw_data: Raw pulse data
            threat_id: ID of the associated threat

        Returns:
            List of threat-IOC associations
        """
        associations = []

        for indicator in raw_data.get("indicators", []):
            ioc_value = indicator.get("indicator")
            ioc_type = self._map_indicator_type(indicator.get("type"))

            if not ioc_value or not ioc_type:
                continue

            association = {
                "threat_id": threat_id,
                "ioc_value": ioc_value,
                "ioc_type": ioc_type,
                "relationship_type": "uses",
                "confidence": 0.8,
                "first_seen": self._parse_date(indicator.get("created")),
                "last_seen": self._parse_date(indicator.get("created")),
                "observation_count": 1,
                "sources": ["alienvault_otx"],
                "reference_urls": raw_data.get("references", []),
                "notes": indicator.get("description"),
                "tags": raw_data.get("tags", []),
            }

            associations.append(association)

        return associations

    # Helper methods

    def _determine_actor_type(self, adversary: str, tags: List[str]) -> str:
        """Determine actor type from name and tags."""
        adversary_lower = adversary.lower()
        tags_lower = " ".join(tags).lower()

        if "apt" in adversary_lower or "apt" in tags_lower:
            return "Nation-State APT"
        elif any(term in tags_lower for term in ["state", "nation", "government"]):
            return "Nation-State"
        elif any(term in tags_lower for term in ["cybercrime", "criminal", "gang"]):
            return "Cybercrime"
        elif "hacktivist" in tags_lower:
            return "Hacktivist"
        else:
            return "Unknown"

    def _determine_sophistication(
        self, techniques: List[Dict], pulse: Dict
    ) -> str:
        """Determine sophistication level based on techniques and context."""
        technique_count = len(techniques)

        # Advanced: Many techniques, APT indicators
        if technique_count > 10:
            return "advanced"
        elif technique_count > 5:
            return "high"
        elif technique_count > 2:
            return "medium"
        else:
            return "low"

    def _determine_malware_type(self, malware_name: str, tags: List[str]) -> str:
        """Determine malware type from name and tags."""
        name_lower = malware_name.lower()
        tags_lower = " ".join(tags).lower()

        if "ransomware" in name_lower or "ransomware" in tags_lower:
            return "ransomware"
        elif "rat" in name_lower or "remote access" in tags_lower:
            return "trojan"
        elif "loader" in name_lower or "dropper" in name_lower:
            return "loader"
        elif "backdoor" in name_lower:
            return "backdoor"
        else:
            return "malware"

    def _extract_aliases(self, primary_name: str, tags: List[str]) -> List[str]:
        """Extract potential aliases from tags."""
        aliases = [primary_name]

        # Common alias patterns in tags
        for tag in tags:
            tag_clean = tag.strip()
            # If tag looks like an actor name (capitalized, not generic)
            if tag_clean and tag_clean[0].isupper() and len(tag_clean) > 3:
                if tag_clean.lower() not in ["china", "russia", "north korea"]:
                    aliases.append(tag_clean)

        return list(set(aliases))[:5]  # Limit to 5 aliases

    def _map_threat_type(self, pulse: Dict) -> str:
        """Map pulse to threat type."""
        tags_lower = " ".join(pulse.get("tags", [])).lower()

        if "c2" in tags_lower or "command" in tags_lower:
            return "c2"
        elif "phish" in tags_lower:
            return "phishing"
        elif "exploit" in tags_lower:
            return "exploit"
        elif "ransomware" in tags_lower:
            return "ransomware"
        else:
            return "malware"

    def _calculate_severity(self, pulse: Dict) -> str:
        """Calculate severity based on pulse context."""
        # Check for high-severity indicators
        tags_lower = " ".join(pulse.get("tags", [])).lower()

        if "critical" in tags_lower or "ransomware" in tags_lower:
            return "critical"
        elif "apt" in tags_lower or "state" in tags_lower:
            return "high"
        elif len(pulse.get("indicators", [])) > 20:
            return "high"
        elif len(pulse.get("indicators", [])) > 5:
            return "medium"
        else:
            return "low"

    def _normalize_tags(self, tags: List[str], entity_name: str) -> List[str]:
        """Normalize and filter tags."""
        normalized = []

        for tag in tags:
            tag_clean = tag.strip().lower()
            # Skip very generic or duplicate tags
            if (
                tag_clean
                and len(tag_clean) > 2
                and tag_clean != entity_name.lower()
            ):
                normalized.append(tag_clean)

        return list(set(normalized))[:20]  # Limit to 20 tags

    def _map_indicator_type(self, otx_type: str) -> Optional[str]:
        """Map OTX indicator type to standard IOC type."""
        type_map = {
            "IPv4": "ipv4",
            "IPv6": "ipv6",
            "domain": "domain",
            "hostname": "domain",
            "URL": "url",
            "URI": "url",
            "FileHash-MD5": "hash_md5",
            "FileHash-SHA1": "hash_sha1",
            "FileHash-SHA256": "hash_sha256",
            "FileHash-SHA512": "hash_sha512",
            "email": "email",
            "CVE": "cve",
        }
        return type_map.get(otx_type)

    def _parse_date(self, date_str: Optional[str]) -> str:
        """Parse date string to ISO format."""
        if not date_str:
            return datetime.now(timezone.utc).isoformat()

        try:
            # Try parsing common formats
            if "T" in date_str:
                dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
            else:
                dt = datetime.strptime(date_str, "%Y-%m-%d")
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.isoformat()
        except Exception:
            return datetime.now(timezone.utc).isoformat()
