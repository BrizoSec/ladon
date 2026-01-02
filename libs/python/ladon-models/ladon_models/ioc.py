"""
IOC (Indicator of Compromise) data models.

This module defines the core data models for representing IOCs from various
threat intelligence sources, with support for multiple IOC types and
flexible metadata storage.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator, model_validator

from .enums import IOCSource, IOCType, ThreatType


class IOCMetadata(BaseModel):
    """
    Flexible metadata container for IOC-specific information.

    Different IOC sources provide different metadata fields. This model
    allows for flexible storage while providing type-safe access to
    common fields.
    """

    # Malware/threat family
    malware_family: Optional[str] = None
    campaign: Optional[str] = None

    # Geolocation
    country: Optional[str] = None
    city: Optional[str] = None
    asn: Optional[str] = None
    organization: Optional[str] = None

    # Reputation scores from various sources
    virustotal_score: Optional[int] = None
    community_score: Optional[float] = None

    # Reference URLs
    reference_urls: List[str] = Field(default_factory=list)

    # Custom key-value pairs for source-specific data
    custom_fields: Dict[str, Any] = Field(default_factory=dict)

    class Config:
        extra = "allow"  # Allow additional fields from different sources


class RawIOC(BaseModel):
    """
    Raw IOC data as received from threat intelligence sources.

    This represents the original, unnormalized data before processing.
    Used for audit trails and debugging.
    """

    source: IOCSource
    received_at: datetime = Field(default_factory=datetime.utcnow)
    raw_data: Dict[str, Any]

    # Original values before normalization
    original_ioc_value: str
    original_ioc_type: Optional[str] = None

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}


class NormalizedIOC(BaseModel):
    """
    Normalized IOC after processing and validation.

    This is the primary IOC model used throughout the platform for
    detection, correlation, and analysis. All IOCs are normalized
    to this format regardless of source.
    """

    # Core identification
    ioc_value: str = Field(
        ..., description="The actual indicator value (IP, domain, hash, etc.)"
    )
    ioc_type: IOCType = Field(..., description="Type of indicator")

    # Classification
    threat_type: ThreatType = Field(..., description="Category of threat")
    threat_types: List[ThreatType] = Field(
        default_factory=list, description="Multiple threat categories if applicable"
    )

    # Confidence and quality
    confidence: float = Field(
        ..., ge=0.0, le=1.0, description="Confidence score from 0.0 to 1.0"
    )
    false_positive_risk: Optional[float] = Field(
        None, ge=0.0, le=1.0, description="Estimated false positive probability"
    )

    # Source information
    source: IOCSource = Field(..., description="Threat intelligence source")
    source_id: Optional[str] = Field(None, description="Original ID from source")

    # Temporal information
    first_seen: datetime = Field(..., description="First observation of this IOC")
    last_seen: datetime = Field(..., description="Most recent observation")
    expires_at: Optional[datetime] = Field(None, description="When this IOC expires")

    # Enrichment and context
    tags: List[str] = Field(default_factory=list, description="Classification tags")
    metadata: IOCMetadata = Field(
        default_factory=IOCMetadata, description="Additional metadata"
    )

    # Processing information
    normalized_at: datetime = Field(
        default_factory=datetime.utcnow, description="When normalization occurred"
    )
    is_active: bool = Field(True, description="Whether this IOC is currently active")
    is_whitelisted: bool = Field(False, description="Whether this IOC is whitelisted")

    @model_validator(mode="before")
    @classmethod
    def normalize_ioc_value(cls, data: dict) -> dict:
        """Normalize IOC value based on type."""
        if "ioc_value" not in data:
            return data

        v = data["ioc_value"].strip()
        ioc_type = data.get("ioc_type")

        if ioc_type in (IOCType.DOMAIN, IOCType.EMAIL, "domain", "email"):
            v = v.lower()
        elif ioc_type in (
            IOCType.HASH_MD5,
            IOCType.HASH_SHA1,
            IOCType.HASH_SHA256,
            IOCType.HASH_SHA512,
            "hash_md5",
            "hash_sha1",
            "hash_sha256",
            "hash_sha512",
        ):
            v = v.lower()
        elif ioc_type in (IOCType.IP, IOCType.IPV4, "ip", "ipv4"):
            # Remove leading zeros from IP octets
            parts = v.split(".")
            if len(parts) == 4 and all(p.isdigit() for p in parts):
                v = ".".join(str(int(p)) for p in parts)

        data["ioc_value"] = v
        return data

    @model_validator(mode="after")
    def populate_threat_types(self) -> "NormalizedIOC":
        """Ensure threat_types list includes the primary threat_type."""
        if self.threat_type and self.threat_type not in self.threat_types:
            self.threat_types.insert(0, self.threat_type)
        return self

    @model_validator(mode="after")
    def validate_temporal_consistency(self) -> "NormalizedIOC":
        """Ensure temporal fields are logically consistent."""
        if self.last_seen < self.first_seen:
            raise ValueError("last_seen cannot be earlier than first_seen")

        if self.expires_at and self.expires_at < self.first_seen:
            raise ValueError("expires_at cannot be earlier than first_seen")

        return self

    def is_expired(self) -> bool:
        """Check if this IOC has expired."""
        if not self.expires_at:
            return False
        return datetime.utcnow() > self.expires_at

    def age_days(self) -> int:
        """Calculate the age of this IOC in days."""
        return (datetime.utcnow() - self.first_seen).days

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}
        use_enum_values = False


class IOCMatch(BaseModel):
    """
    Represents a match between an IOC and an activity event.

    Used during the detection process to track which IOCs matched
    which activity patterns.
    """

    ioc: NormalizedIOC
    match_type: str = Field(
        ...,
        description="Type of match (exact, subdomain, cidr, regex, etc.)",
    )
    matched_value: str = Field(
        ..., description="The actual value from activity that matched"
    )
    confidence_adjusted: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="IOC confidence adjusted for match type",
    )
    matched_at: datetime = Field(default_factory=datetime.utcnow)

    def calculate_adjusted_confidence(self) -> float:
        """
        Calculate confidence score adjusted for match type.

        Exact matches retain full confidence, while fuzzy matches
        (subdomain, CIDR) receive reduced confidence.
        """
        adjustments = {
            "exact": 1.0,
            "subdomain": 0.9,
            "parent_domain": 0.85,
            "cidr": 0.95,
            "regex": 0.8,
            "fuzzy": 0.7,
        }
        adjustment = adjustments.get(self.match_type, 0.8)
        return self.ioc.confidence * adjustment

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}


class IOCBatch(BaseModel):
    """
    Batch of IOCs for bulk processing.

    Used when ingesting large numbers of IOCs from threat feeds
    or during batch enrichment operations.
    """

    batch_id: str
    source: IOCSource
    iocs: List[NormalizedIOC]
    received_at: datetime = Field(default_factory=datetime.utcnow)
    total_count: int = Field(..., ge=0)
    processed_count: int = Field(0, ge=0)
    failed_count: int = Field(0, ge=0)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_counts(self) -> "IOCBatch":
        """Ensure counts are consistent."""
        if self.total_count != len(self.iocs):
            raise ValueError("total_count must match length of iocs list")
        if self.processed_count + self.failed_count > self.total_count:
            raise ValueError("processed + failed cannot exceed total")
        return self

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}


class IOCStatistics(BaseModel):
    """
    Statistics about IOCs in the system.

    Used for monitoring, dashboards, and capacity planning.
    """

    total_iocs: int = 0
    active_iocs: int = 0
    expired_iocs: int = 0
    whitelisted_iocs: int = 0

    by_type: Dict[str, int] = Field(default_factory=dict)
    by_source: Dict[str, int] = Field(default_factory=dict)
    by_threat_type: Dict[str, int] = Field(default_factory=dict)

    avg_confidence: float = 0.0
    oldest_ioc: Optional[datetime] = None
    newest_ioc: Optional[datetime] = None

    last_updated: datetime = Field(default_factory=datetime.utcnow)

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}
