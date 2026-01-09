"""
Threat Actor/Campaign data models.

This module defines models for tracking threat actors, campaigns, malware families,
and their associated TTPs (Tactics, Techniques, and Procedures) based on MITRE ATT&CK.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator

from .enums import ThreatType


class MITRETechnique(BaseModel):
    """
    MITRE ATT&CK Technique.

    Represents a specific technique from the MITRE ATT&CK framework.
    """

    technique_id: str = Field(
        ...,
        description="MITRE ATT&CK technique ID (e.g., T1059.001)",
        pattern=r"^T\d{4}(\.\d{3})?$"
    )
    technique_name: str = Field(..., description="Name of the technique")
    tactic: str = Field(..., description="Associated tactic (e.g., Execution, Persistence)")
    sub_technique: Optional[str] = Field(None, description="Sub-technique name if applicable")

    # Detection and mitigation info
    detection_methods: List[str] = Field(
        default_factory=list,
        description="Known detection methods for this technique"
    )
    mitigations: List[str] = Field(
        default_factory=list,
        description="Recommended mitigations"
    )

    # Reference
    reference_url: Optional[str] = Field(
        None,
        description="URL to MITRE ATT&CK technique page"
    )

    @field_validator("technique_id")
    @classmethod
    def format_technique_id(cls, v: str) -> str:
        """Ensure technique ID is uppercase."""
        return v.upper()

    def get_mitre_url(self) -> str:
        """Generate MITRE ATT&CK URL for this technique."""
        base_url = "https://attack.mitre.org/techniques"
        # Handle sub-techniques (e.g., T1059.001 -> T1059/001)
        if "." in self.technique_id:
            parent, sub = self.technique_id.split(".")
            return f"{base_url}/{parent}/{sub}/"
        return f"{base_url}/{self.technique_id}/"

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}


class ThreatActor(BaseModel):
    """
    Threat Actor or Group.

    Represents an individual or organized group engaged in malicious cyber activity.
    """

    # Identification
    actor_id: str = Field(..., description="Unique identifier for the threat actor")
    name: str = Field(..., description="Primary name of the threat actor")
    aliases: List[str] = Field(
        default_factory=list,
        description="Alternative names (e.g., APT28, Fancy Bear, Sofacy)"
    )

    # Classification
    actor_type: str = Field(
        ...,
        description="Type of actor (APT, Cybercrime, Hacktivist, Nation-State, etc.)"
    )
    sophistication: str = Field(
        "unknown",
        description="Sophistication level (low, medium, high, advanced)"
    )

    # Attribution
    suspected_attribution: Optional[str] = Field(
        None,
        description="Suspected country or organization (with appropriate caveats)"
    )
    confidence_level: Optional[float] = Field(
        None,
        ge=0.0,
        le=1.0,
        description="Confidence in attribution (0.0-1.0)"
    )

    # Motivations and targeting
    primary_motivation: Optional[str] = Field(
        None,
        description="Primary motivation (espionage, financial, disruption, etc.)"
    )
    target_sectors: List[str] = Field(
        default_factory=list,
        description="Targeted industry sectors"
    )
    target_regions: List[str] = Field(
        default_factory=list,
        description="Targeted geographic regions"
    )

    # Context
    description: Optional[str] = Field(None, description="Detailed description")
    first_seen: Optional[datetime] = Field(None, description="First observed activity")
    last_seen: Optional[datetime] = Field(None, description="Most recent activity")

    # References
    reference_urls: List[str] = Field(
        default_factory=list,
        description="External references and reports"
    )

    # Metadata
    is_active: bool = Field(True, description="Whether actor is currently active")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}


class ThreatCampaign(BaseModel):
    """
    Threat Campaign.

    Represents a coordinated series of attacks with a specific objective,
    typically conducted by one or more threat actors.
    """

    # Identification
    campaign_id: str = Field(..., description="Unique campaign identifier")
    name: str = Field(..., description="Campaign name")
    aliases: List[str] = Field(default_factory=list, description="Alternative names")

    # Classification
    campaign_type: str = Field(
        ...,
        description="Type of campaign (targeted attack, mass exploitation, etc.)"
    )
    objective: Optional[str] = Field(
        None,
        description="Primary objective (data theft, ransomware, disruption, etc.)"
    )

    # Attribution
    associated_actors: List[str] = Field(
        default_factory=list,
        description="IDs of associated threat actors"
    )

    # Targeting
    target_sectors: List[str] = Field(default_factory=list)
    target_regions: List[str] = Field(default_factory=list)
    target_technologies: List[str] = Field(
        default_factory=list,
        description="Targeted technologies or platforms"
    )

    # Context
    description: Optional[str] = Field(None, description="Campaign description")

    # Timeline
    first_seen: datetime = Field(..., description="Campaign start date")
    last_seen: datetime = Field(..., description="Most recent activity")
    estimated_end: Optional[datetime] = Field(None, description="Estimated end date")

    # Impact
    estimated_victims: Optional[int] = Field(None, description="Estimated victim count")
    severity: str = Field(
        "medium",
        description="Severity level (low, medium, high, critical)"
    )

    # References
    reference_urls: List[str] = Field(default_factory=list)

    # Metadata
    is_active: bool = Field(True, description="Whether campaign is ongoing")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}


class MalwareFamily(BaseModel):
    """
    Malware Family.

    Represents a distinct malware family or variant with shared characteristics.
    """

    # Identification
    family_id: str = Field(..., description="Unique malware family identifier")
    name: str = Field(..., description="Malware family name")
    aliases: List[str] = Field(
        default_factory=list,
        description="Alternative names and variants"
    )

    # Classification
    malware_type: str = Field(
        ...,
        description="Type (ransomware, trojan, worm, rootkit, etc.)"
    )
    platform: List[str] = Field(
        default_factory=list,
        description="Affected platforms (Windows, Linux, Android, etc.)"
    )

    # Capabilities
    capabilities: List[str] = Field(
        default_factory=list,
        description="Malware capabilities (encryption, exfiltration, backdoor, etc.)"
    )
    propagation_methods: List[str] = Field(
        default_factory=list,
        description="How it spreads (email, exploit, removable media, etc.)"
    )

    # Attribution
    associated_actors: List[str] = Field(
        default_factory=list,
        description="Known threat actors using this malware"
    )
    associated_campaigns: List[str] = Field(
        default_factory=list,
        description="Campaigns where this malware was observed"
    )

    # Context
    description: Optional[str] = Field(None, description="Detailed description")
    first_seen: Optional[datetime] = Field(None, description="First observation")
    last_seen: Optional[datetime] = Field(None, description="Most recent observation")

    # Detection
    yara_rules: List[str] = Field(
        default_factory=list,
        description="YARA rule names for detection"
    )
    detection_names: Dict[str, str] = Field(
        default_factory=dict,
        description="AV vendor detection names"
    )

    # References
    reference_urls: List[str] = Field(default_factory=list)

    # Metadata
    is_active: bool = Field(True, description="Whether actively circulating")
    severity: str = Field("medium", description="Severity level")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}


class Threat(BaseModel):
    """
    Unified Threat model.

    Represents a comprehensive threat that can be an actor, campaign, or malware family
    with associated TTPs, IOCs, and context. This is the primary model for threat tracking.
    """

    # Core identification
    threat_id: str = Field(..., description="Unique threat identifier")
    name: str = Field(..., description="Threat name")
    aliases: List[str] = Field(default_factory=list, description="Alternative names")

    # Classification
    threat_category: str = Field(
        ...,
        description="Category (actor, campaign, malware_family, vulnerability)"
    )
    threat_type: ThreatType = Field(..., description="Primary threat type")

    # Sub-models (one will be populated based on category)
    actor: Optional[ThreatActor] = Field(None, description="Actor details if applicable")
    campaign: Optional[ThreatCampaign] = Field(None, description="Campaign details")
    malware: Optional[MalwareFamily] = Field(None, description="Malware family details")

    # TTPs (MITRE ATT&CK)
    techniques: List[MITRETechnique] = Field(
        default_factory=list,
        description="Associated MITRE ATT&CK techniques"
    )
    tactics: List[str] = Field(
        default_factory=list,
        description="MITRE ATT&CK tactics (derived from techniques)"
    )

    # Associated entities
    associated_ioc_ids: List[str] = Field(
        default_factory=list,
        description="IDs of associated IOCs"
    )
    related_threat_ids: List[str] = Field(
        default_factory=list,
        description="IDs of related threats"
    )

    # Context
    description: str = Field(..., description="Comprehensive threat description")
    severity: str = Field(
        "medium",
        description="Overall severity (low, medium, high, critical)"
    )
    confidence: float = Field(
        0.5,
        ge=0.0,
        le=1.0,
        description="Confidence in threat intelligence (0.0-1.0)"
    )

    # Timeline
    first_seen: datetime = Field(..., description="First observation")
    last_seen: datetime = Field(..., description="Most recent activity")

    # Intelligence sources
    sources: List[str] = Field(
        default_factory=list,
        description="Intelligence sources for this threat"
    )
    reference_urls: List[str] = Field(
        default_factory=list,
        description="External references and reports"
    )

    # Tags and metadata
    tags: List[str] = Field(default_factory=list, description="Classification tags")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Custom metadata")

    # Status
    is_active: bool = Field(True, description="Whether threat is currently active")

    # Processing metadata
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def get_all_tactics(self) -> List[str]:
        """Extract all unique tactics from techniques."""
        return list(set(tech.tactic for tech in self.techniques))

    def get_technique_count(self) -> int:
        """Get count of associated techniques."""
        return len(self.techniques)

    def is_apt(self) -> bool:
        """Check if this is an APT (Advanced Persistent Threat)."""
        if self.actor:
            return "apt" in self.actor.actor_type.lower()
        return "apt" in self.threat_category.lower() or any(
            "apt" in tag.lower() for tag in self.tags
        )

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}


class ThreatIOCAssociation(BaseModel):
    """
    Association between a Threat and an IOC.

    Links threats to specific indicators with context about the relationship.
    """

    threat_id: str = Field(..., description="Associated threat ID")
    ioc_value: str = Field(..., description="Associated IOC value")
    ioc_type: str = Field(..., description="IOC type")

    # Relationship context
    relationship_type: str = Field(
        "uses",
        description="Type of relationship (uses, attributed_to, distributes, etc.)"
    )
    confidence: float = Field(
        0.5,
        ge=0.0,
        le=1.0,
        description="Confidence in this association"
    )

    # Context
    first_seen: datetime = Field(
        ...,
        description="When this association was first observed"
    )
    last_seen: datetime = Field(
        ...,
        description="Most recent observation of this association"
    )
    observation_count: int = Field(
        1,
        ge=1,
        description="Number of times this association was observed"
    )

    # Sources
    sources: List[str] = Field(
        default_factory=list,
        description="Intelligence sources reporting this association"
    )
    reference_urls: List[str] = Field(default_factory=list)

    # Metadata
    notes: Optional[str] = Field(None, description="Additional context or notes")
    tags: List[str] = Field(default_factory=list)

    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}


class ThreatStatistics(BaseModel):
    """
    Statistics about threats in the system.

    Used for monitoring, dashboards, and threat landscape analysis.
    """

    total_threats: int = 0
    active_threats: int = 0

    by_category: Dict[str, int] = Field(default_factory=dict)  # actor, campaign, malware
    by_type: Dict[str, int] = Field(default_factory=dict)  # c2, ransomware, etc.
    by_severity: Dict[str, int] = Field(default_factory=dict)  # low, medium, high, critical

    # APT tracking
    total_apts: int = 0
    active_apts: int = 0

    # TTP coverage
    total_techniques: int = 0
    techniques_by_tactic: Dict[str, int] = Field(default_factory=dict)
    most_common_techniques: List[Dict[str, Any]] = Field(default_factory=list)

    # Associations
    threats_with_iocs: int = 0
    avg_iocs_per_threat: float = 0.0

    last_updated: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}
