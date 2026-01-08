"""Base threat extractor interface."""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Tuple


class ThreatExtractor(ABC):
    """Abstract base class for threat extractors."""

    @abstractmethod
    def extract_threats(self, raw_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Extract threat intelligence from raw feed data.

        Args:
            raw_data: Raw data from threat intelligence feed

        Returns:
            List of threat dictionaries ready for normalization
        """
        pass

    @abstractmethod
    def extract_threat_ioc_associations(
        self, raw_data: Dict[str, Any], threat_id: str
    ) -> List[Dict[str, Any]]:
        """
        Extract threat-IOC associations from raw feed data.

        Args:
            raw_data: Raw data from threat intelligence feed
            threat_id: ID of the associated threat

        Returns:
            List of threat-IOC association dictionaries
        """
        pass

    def _generate_threat_id(
        self, source: str, identifier: str, timestamp: Optional[str] = None
    ) -> str:
        """
        Generate a unique threat ID.

        Args:
            source: Source name (alienvault, abuse_ch, etc.)
            identifier: Unique identifier from the source
            timestamp: Optional timestamp for uniqueness

        Returns:
            Threat ID string
        """
        import hashlib
        from datetime import datetime

        # Create a deterministic ID based on source and identifier
        id_str = f"{source}:{identifier}"
        if timestamp:
            id_str += f":{timestamp}"

        hash_obj = hashlib.sha256(id_str.encode())
        return f"threat_{source}_{hash_obj.hexdigest()[:16]}"

    def _parse_mitre_techniques(
        self, attack_ids: List[str]
    ) -> List[Dict[str, Any]]:
        """
        Parse MITRE ATT&CK technique IDs into structured format.

        Uses comprehensive MITRE ATT&CK framework mapping from mitre_attack.py
        covering 200+ techniques across all 14 tactics.

        Args:
            attack_ids: List of MITRE technique IDs (e.g., ['T1059.001', 'T1190'])

        Returns:
            List of technique dictionaries
        """
        from .mitre_attack import get_technique_info

        techniques = []

        for attack_id in attack_ids:
            # Normalize technique ID
            attack_id = attack_id.strip().upper()

            # Get technique info from comprehensive mapping
            technique_info = get_technique_info(attack_id)

            if technique_info:
                techniques.append(technique_info)
            else:
                # Fallback for unmapped techniques
                logger.warning(f"Unknown MITRE technique: {attack_id}")
                techniques.append({
                    "technique_id": attack_id,
                    "technique_name": f"Unknown Technique {attack_id}",
                    "tactic": "Unknown",
                    "sub_technique": None,
                    "detection_methods": [],
                    "mitigations": [],
                    "reference_url": f"https://attack.mitre.org/techniques/{attack_id.replace('.', '/')}/"
                })

        return techniques

    def _extract_tactics_from_techniques(
        self, techniques: List[Dict[str, Any]]
    ) -> List[str]:
        """
        Extract unique tactics from techniques.

        Args:
            techniques: List of technique dictionaries

        Returns:
            List of unique tactic names
        """
        tactics = set()
        for technique in techniques:
            if technique.get("tactic"):
                tactics.add(technique["tactic"])
        return sorted(list(tactics))

    def _normalize_confidence(self, value: Any) -> float:
        """
        Normalize confidence value to 0.0-1.0 range.

        Args:
            value: Confidence value (could be int, float, str)

        Returns:
            Normalized confidence between 0.0 and 1.0
        """
        try:
            conf = float(value)
            # If value is > 1.0, assume it's a percentage
            if conf > 1.0:
                conf = conf / 100.0
            return max(0.0, min(1.0, conf))
        except (ValueError, TypeError):
            return 0.5  # Default confidence
