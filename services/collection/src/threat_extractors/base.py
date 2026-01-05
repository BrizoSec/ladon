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

        Args:
            attack_ids: List of MITRE technique IDs (e.g., ['T1059.001', 'T1190'])

        Returns:
            List of technique dictionaries
        """
        techniques = []

        # Simplified MITRE ATT&CK tactic mapping
        # In production, this should use the full MITRE ATT&CK matrix
        tactic_map = {
            "T1190": ("Exploit Public-Facing Application", "Initial Access"),
            "T1566": ("Phishing", "Initial Access"),
            "T1059": ("Command and Scripting Interpreter", "Execution"),
            "T1053": ("Scheduled Task/Job", "Execution"),
            "T1055": ("Process Injection", "Defense Evasion"),
            "T1548": ("Abuse Elevation Control Mechanism", "Privilege Escalation"),
            "T1082": ("System Information Discovery", "Discovery"),
            "T1083": ("File and Directory Discovery", "Discovery"),
            "T1057": ("Process Discovery", "Discovery"),
            "T1071": ("Application Layer Protocol", "Command and Control"),
            "T1041": ("Exfiltration Over C2 Channel", "Exfiltration"),
            "T1113": ("Screen Capture", "Collection"),
            "T1056": ("Input Capture", "Collection"),
            "T1115": ("Clipboard Data", "Collection"),
            "T1555": ("Credentials from Password Stores", "Credential Access"),
            "T1562": ("Impair Defenses", "Defense Evasion"),
            "T1564": ("Hide Artifacts", "Defense Evasion"),
            "T1195": ("Supply Chain Compromise", "Initial Access"),
        }

        for attack_id in attack_ids:
            # Extract base technique (without sub-technique)
            base_technique = attack_id.split(".")[0]

            # Get technique info
            technique_info = tactic_map.get(
                base_technique, (f"Unknown Technique {attack_id}", "Unknown")
            )

            technique = {
                "technique_id": attack_id,
                "technique_name": technique_info[0],
                "tactic": technique_info[1],
                "sub_technique": None,
                "detection_methods": [],
                "mitigations": [],
                "reference_url": f"https://attack.mitre.org/techniques/{attack_id.replace('.', '/')}/"
            }

            # Add sub-technique name if applicable
            if "." in attack_id:
                technique["sub_technique"] = f"Sub-technique {attack_id.split('.')[1]}"

            techniques.append(technique)

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
