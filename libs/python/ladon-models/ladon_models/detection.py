"""
Detection data models.

This module defines models for security detections that result from
correlating IOCs against activity events, including severity scoring,
enrichment, and case management integration.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator, model_validator

from .activity import NormalizedActivity
from .enums import ActivitySource, DetectionStatus, EnrichmentProvider, IOCSource, Severity
from .ioc import IOCMatch, NormalizedIOC


class SeverityScore(BaseModel):
    """
    Detailed severity scoring information for a detection.

    Tracks how the final severity was calculated based on various factors.
    """

    base_score: float = Field(..., ge=0.0, le=100.0, description="Base confidence * 100")
    final_score: float = Field(..., ge=0.0, le=100.0, description="Final calculated score")
    severity: Severity = Field(..., description="Final severity level")

    # Multipliers applied
    ioc_source_multiplier: float = Field(1.0, ge=0.0, le=5.0)
    threat_type_multiplier: float = Field(1.0, ge=0.0, le=5.0)
    activity_source_multiplier: float = Field(1.0, ge=0.0, le=5.0)
    asset_criticality_multiplier: float = Field(1.0, ge=0.0, le=5.0)

    # Detailed scoring breakdown
    factors: Dict[str, Any] = Field(
        default_factory=dict, description="Detailed scoring factors"
    )

    @classmethod
    def calculate(
        cls,
        ioc: NormalizedIOC,
        activity_source: ActivitySource,
        asset_criticality: Optional[str] = None,
    ) -> "SeverityScore":
        """
        Calculate severity score based on IOC and activity context.

        Uses the scoring algorithm defined in CLAUDE.md.
        """
        base_score = ioc.confidence * 100

        # IOC source reputation multipliers
        ioc_source_multipliers = {
            IOCSource.ABUSE_CH: 1.2,
            IOCSource.MISP: 1.15,
            IOCSource.ALIENVAULT_OTX: 1.1,
            IOCSource.THREAT_FOX: 1.2,
            IOCSource.EMERGING_THREATS: 1.15,
            IOCSource.CUSTOM: 0.8,
            IOCSource.MANUAL: 0.9,
        }
        ioc_source_mult = ioc_source_multipliers.get(ioc.source, 1.0)

        # Threat type severity multipliers
        threat_type_multipliers = {
            "ransomware": 2.0,
            "c2": 1.5,
            "backdoor": 1.5,
            "malware": 1.3,
            "apt": 1.8,
            "data_exfiltration": 1.6,
            "phishing": 1.2,
        }
        threat_type_mult = threat_type_multipliers.get(ioc.threat_type.value, 1.0)

        # Activity source criticality multipliers
        activity_source_multipliers = {
            ActivitySource.MDE: 1.5,
            ActivitySource.CROWDSTRIKE: 1.5,
            ActivitySource.SINKHOLE: 1.8,
            ActivitySource.EDR: 1.4,
            ActivitySource.FIREWALL: 1.2,
        }
        activity_source_mult = activity_source_multipliers.get(activity_source, 1.0)

        # Asset criticality multipliers
        asset_criticality_multipliers = {
            "critical": 1.5,
            "high": 1.3,
            "medium": 1.0,
            "low": 0.9,
        }
        asset_crit_mult = asset_criticality_multipliers.get(
            asset_criticality or "medium", 1.0
        )

        # Calculate final score
        final_score = (
            base_score
            * ioc_source_mult
            * threat_type_mult
            * activity_source_mult
            * asset_crit_mult
        )
        final_score = min(final_score, 100.0)  # Cap at 100

        # Determine severity level
        if final_score >= 80:
            severity = Severity.CRITICAL
        elif final_score >= 60:
            severity = Severity.HIGH
        elif final_score >= 40:
            severity = Severity.MEDIUM
        else:
            severity = Severity.LOW

        return cls(
            base_score=base_score,
            final_score=final_score,
            severity=severity,
            ioc_source_multiplier=ioc_source_mult,
            threat_type_multiplier=threat_type_mult,
            activity_source_multiplier=activity_source_mult,
            asset_criticality_multiplier=asset_crit_mult,
            factors={
                "ioc_confidence": ioc.confidence,
                "ioc_source": ioc.source.value,
                "threat_type": ioc.threat_type.value,
                "activity_source": activity_source.value,
                "asset_criticality": asset_criticality,
            },
        )


class EnrichmentData(BaseModel):
    """
    Enrichment data from external APIs and internal sources.

    Stores additional context about IOCs, IPs, domains, etc.
    """

    provider: EnrichmentProvider
    enriched_at: datetime = Field(default_factory=datetime.utcnow)

    # Common enrichment fields
    reputation_score: Optional[float] = None
    categories: List[str] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)

    # Geolocation
    country: Optional[str] = None
    city: Optional[str] = None
    asn: Optional[str] = None
    organization: Optional[str] = None

    # Threat intelligence
    malware_families: List[str] = Field(default_factory=list)
    threat_actors: List[str] = Field(default_factory=list)

    # Provider-specific data
    data: Dict[str, Any] = Field(default_factory=dict)

    # Caching
    cached: bool = False
    cache_expires_at: Optional[datetime] = None

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}


class Detection(BaseModel):
    """
    Security detection resulting from IOC correlation.

    This is the primary detection model used throughout the platform,
    representing a match between an IOC and activity event that indicates
    a potential security threat.
    """

    # Core identification
    detection_id: str = Field(..., description="Unique detection identifier")
    timestamp: datetime = Field(..., description="When the detection occurred")

    # IOC information
    ioc_value: str = Field(..., description="The IOC value that matched")
    ioc_type: str = Field(..., description="Type of IOC")
    ioc: Optional[NormalizedIOC] = Field(None, description="Full IOC object")
    ioc_match: Optional[IOCMatch] = Field(None, description="Match details")

    # Activity information
    activity_event_id: str = Field(..., description="ID of the activity event")
    activity_source: ActivitySource = Field(..., description="Source of the activity")
    activity: Optional[NormalizedActivity] = Field(None, description="Full activity object")

    # Detection scoring
    severity: Severity = Field(..., description="Severity level")
    confidence: float = Field(
        ..., ge=0.0, le=1.0, description="Overall confidence in this detection"
    )
    severity_score: Optional[SeverityScore] = Field(
        None, description="Detailed severity calculation"
    )

    # Context and enrichment
    enrichment: Dict[str, EnrichmentData] = Field(
        default_factory=dict, description="External enrichment data"
    )
    context: Dict[str, Any] = Field(
        default_factory=dict, description="Additional context about this detection"
    )

    # Case management
    case_id: Optional[str] = Field(None, description="ServiceNow case number")
    case_url: Optional[str] = Field(None, description="Link to ServiceNow case")
    status: DetectionStatus = Field(DetectionStatus.NEW, description="Detection status")

    # Analyst information
    assigned_to: Optional[str] = Field(None, description="Analyst assigned to this detection")
    analyst_notes: List[str] = Field(default_factory=list, description="Analyst notes")
    false_positive_reason: Optional[str] = Field(
        None, description="Reason if marked as false positive"
    )

    # Temporal tracking
    first_seen: datetime = Field(
        ..., description="First time this IOC/activity pair was seen"
    )
    last_seen: datetime = Field(..., description="Most recent occurrence")
    occurrence_count: int = Field(1, ge=1, description="Number of times seen")

    # Processing metadata
    created_at: datetime = Field(
        default_factory=datetime.utcnow, description="When detection was created"
    )
    updated_at: datetime = Field(
        default_factory=datetime.utcnow, description="Last update timestamp"
    )
    resolved_at: Optional[datetime] = Field(None, description="When detection was resolved")

    @model_validator(mode="after")
    def calculate_severity_if_needed(self) -> "Detection":
        """Calculate severity score if not already provided."""
        if not self.severity_score and self.ioc:
            asset_criticality = self.context.get("asset_criticality")
            self.severity_score = SeverityScore.calculate(
                self.ioc, self.activity_source, asset_criticality
            )
            self.severity = self.severity_score.severity
        return self

    @model_validator(mode="after")
    def update_timestamp_on_status_change(self) -> "Detection":
        """Update resolved_at when status changes to resolved."""
        if self.status in (DetectionStatus.RESOLVED, DetectionStatus.CLOSED):
            if not self.resolved_at:
                self.resolved_at = datetime.utcnow()
        return self

    def add_analyst_note(self, note: str, analyst: Optional[str] = None) -> None:
        """Add an analyst note to this detection."""
        timestamp = datetime.utcnow().isoformat()
        annotated_note = f"[{timestamp}]"
        if analyst:
            annotated_note += f" {analyst}:"
        annotated_note += f" {note}"
        self.analyst_notes.append(annotated_note)
        self.updated_at = datetime.utcnow()

    def mark_false_positive(self, reason: str, analyst: Optional[str] = None) -> None:
        """Mark this detection as a false positive."""
        self.status = DetectionStatus.FALSE_POSITIVE
        self.false_positive_reason = reason
        self.add_analyst_note(f"Marked as false positive: {reason}", analyst)
        self.resolved_at = datetime.utcnow()

    def is_critical(self) -> bool:
        """Check if this is a critical severity detection."""
        return self.severity == Severity.CRITICAL

    def is_high_or_critical(self) -> bool:
        """Check if this is high or critical severity."""
        return self.severity in (Severity.CRITICAL, Severity.HIGH)

    def age_hours(self) -> float:
        """Calculate age of detection in hours."""
        return (datetime.utcnow() - self.timestamp).total_seconds() / 3600

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}


class DetectionBatch(BaseModel):
    """
    Batch of detections for bulk processing.

    Used during batch detection runs or when processing large volumes.
    """

    batch_id: str
    detections: List[Detection]
    created_at: datetime = Field(default_factory=datetime.utcnow)
    total_count: int = Field(..., ge=0)
    critical_count: int = Field(0, ge=0)
    high_count: int = Field(0, ge=0)
    medium_count: int = Field(0, ge=0)
    low_count: int = Field(0, ge=0)

    @model_validator(mode="after")
    def calculate_severity_counts(self) -> "DetectionBatch":
        """Calculate counts by severity level."""
        self.critical_count = sum(1 for d in self.detections if d.severity == Severity.CRITICAL)
        self.high_count = sum(1 for d in self.detections if d.severity == Severity.HIGH)
        self.medium_count = sum(1 for d in self.detections if d.severity == Severity.MEDIUM)
        self.low_count = sum(1 for d in self.detections if d.severity == Severity.LOW)
        return self

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}


class DetectionStatistics(BaseModel):
    """
    Statistics about detections in the system.

    Used for monitoring, dashboards, and reporting.
    """

    total_detections: int = 0
    new_detections: int = 0
    investigating: int = 0
    confirmed: int = 0
    false_positives: int = 0
    resolved: int = 0

    by_severity: Dict[str, int] = Field(default_factory=dict)
    by_status: Dict[str, int] = Field(default_factory=dict)
    by_ioc_type: Dict[str, int] = Field(default_factory=dict)
    by_activity_source: Dict[str, int] = Field(default_factory=dict)

    avg_confidence: float = 0.0
    avg_time_to_resolution_hours: Optional[float] = None

    oldest_unresolved: Optional[datetime] = None
    newest_detection: Optional[datetime] = None

    last_updated: datetime = Field(default_factory=datetime.utcnow)

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}
