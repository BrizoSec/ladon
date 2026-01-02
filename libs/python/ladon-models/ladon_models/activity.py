"""
Activity Event data models.

This module defines models for activity log events from various sources
(proxy, DNS, EDR, etc.) that are correlated against IOCs for threat detection.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator, model_validator

from .enums import ActivityEventType, ActivitySource


class NetworkFields(BaseModel):
    """Network-related fields for activity events."""

    src_ip: Optional[str] = None
    src_port: Optional[int] = Field(None, ge=0, le=65535)
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = Field(None, ge=0, le=65535)

    domain: Optional[str] = None
    url: Optional[str] = None
    protocol: Optional[str] = None

    bytes_sent: Optional[int] = Field(None, ge=0)
    bytes_received: Optional[int] = Field(None, ge=0)

    @field_validator("domain", "url")
    @classmethod
    def normalize_domain_url(cls, v: Optional[str]) -> Optional[str]:
        """Normalize domain and URL to lowercase."""
        return v.lower() if v else v


class HostFields(BaseModel):
    """Host/endpoint-related fields for activity events."""

    hostname: Optional[str] = None
    fqdn: Optional[str] = None
    ip_address: Optional[str] = None
    mac_address: Optional[str] = None
    os: Optional[str] = None
    os_version: Optional[str] = None


class UserFields(BaseModel):
    """User-related fields for activity events."""

    user: Optional[str] = None
    username: Optional[str] = None
    domain: Optional[str] = None  # Domain for domain\username
    email: Optional[str] = None
    sid: Optional[str] = None  # Security Identifier (Windows)
    uid: Optional[int] = None  # User ID (Unix/Linux)


class ProcessFields(BaseModel):
    """Process-related fields for activity events."""

    process_name: Optional[str] = None
    process_path: Optional[str] = None
    process_id: Optional[int] = None
    parent_process_name: Optional[str] = None
    parent_process_id: Optional[int] = None
    command_line: Optional[str] = None


class FileFields(BaseModel):
    """File-related fields for activity events."""

    file_name: Optional[str] = None
    file_path: Optional[str] = None
    file_hash: Optional[str] = None
    file_hash_md5: Optional[str] = None
    file_hash_sha1: Optional[str] = None
    file_hash_sha256: Optional[str] = None
    file_size: Optional[int] = Field(None, ge=0)
    file_type: Optional[str] = None


class EmailFields(BaseModel):
    """Email-related fields for activity events."""

    sender: Optional[str] = None
    recipient: Optional[str] = None
    recipients: List[str] = Field(default_factory=list)
    subject: Optional[str] = None
    message_id: Optional[str] = None
    attachment_names: List[str] = Field(default_factory=list)
    attachment_hashes: List[str] = Field(default_factory=list)


class DNSFields(BaseModel):
    """DNS-specific fields for activity events."""

    query: Optional[str] = None
    query_type: Optional[str] = None  # A, AAAA, CNAME, MX, etc.
    response: Optional[str] = None
    response_code: Optional[int] = None
    answers: List[str] = Field(default_factory=list)

    @field_validator("query")
    @classmethod
    def normalize_query(cls, v: Optional[str]) -> Optional[str]:
        """Normalize DNS query to lowercase."""
        return v.lower() if v else v


class HTTPFields(BaseModel):
    """HTTP/HTTPS-specific fields for activity events."""

    method: Optional[str] = None  # GET, POST, etc.
    status_code: Optional[int] = None
    user_agent: Optional[str] = None
    referer: Optional[str] = None
    content_type: Optional[str] = None
    request_headers: Dict[str, str] = Field(default_factory=dict)
    response_headers: Dict[str, str] = Field(default_factory=dict)


class RawActivity(BaseModel):
    """
    Raw activity event as received from data sources.

    This represents the original, unnormalized event before processing.
    Used for audit trails and debugging.
    """

    source: ActivitySource
    received_at: datetime = Field(default_factory=datetime.utcnow)
    raw_event: Dict[str, Any]

    # Minimal required fields for routing
    event_id: Optional[str] = None
    timestamp: Optional[datetime] = None

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}


class NormalizedActivity(BaseModel):
    """
    Normalized activity event after processing and validation.

    This is the primary activity model used throughout the platform for
    detection, correlation, and analysis. All activity events are normalized
    to this format regardless of source.
    """

    # Core identification
    event_id: str = Field(..., description="Unique event identifier")
    timestamp: datetime = Field(..., description="When the event occurred")

    # Source information
    source: ActivitySource = Field(..., description="Source system that generated the event")
    event_type: ActivityEventType = Field(..., description="Type of activity event")

    # Categorized fields (optional based on event type)
    network: Optional[NetworkFields] = None
    host: Optional[HostFields] = None
    user: Optional[UserFields] = None
    process: Optional[ProcessFields] = None
    file: Optional[FileFields] = None
    email: Optional[EmailFields] = None
    dns: Optional[DNSFields] = None
    http: Optional[HTTPFields] = None

    # Quick-access fields (denormalized for performance)
    # These are extracted from the categorized fields above
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    domain: Optional[str] = None
    url: Optional[str] = None
    hostname: Optional[str] = None
    user_name: Optional[str] = None
    process_name: Optional[str] = None
    file_hash: Optional[str] = None

    # Enrichment and metadata
    enrichment: Dict[str, Any] = Field(
        default_factory=dict, description="External enrichment data"
    )
    tags: List[str] = Field(default_factory=list, description="Classification tags")

    # Processing information
    normalized_at: datetime = Field(
        default_factory=datetime.utcnow, description="When normalization occurred"
    )
    raw_event: Dict[str, Any] = Field(
        default_factory=dict, description="Original raw event for reference"
    )

    @model_validator(mode="after")
    def populate_quick_access_fields(self) -> "NormalizedActivity":
        """Extract quick-access fields from categorized field groups."""
        if self.network:
            self.src_ip = self.src_ip or self.network.src_ip
            self.dst_ip = self.dst_ip or self.network.dst_ip
            self.domain = self.domain or self.network.domain
            self.url = self.url or self.network.url

        if self.host:
            self.hostname = self.hostname or self.host.hostname

        if self.user:
            self.user_name = self.user_name or self.user.user or self.user.username

        if self.process:
            self.process_name = self.process_name or self.process.process_name

        if self.file:
            self.file_hash = (
                self.file_hash
                or self.file.file_hash_sha256
                or self.file.file_hash_sha1
                or self.file.file_hash_md5
                or self.file.file_hash
            )

        if self.dns:
            self.domain = self.domain or self.dns.query

        return self

    def extract_ioc_values(self) -> Dict[str, List[str]]:
        """
        Extract all potential IOC values from this activity event.

        Uses quick-access fields that are pre-populated by populate_quick_access_fields()
        for optimal performance. This avoids redundant attribute lookups and duplicate
        creation when processing high volumes of events.

        Returns a dictionary mapping IOC types to lists of values that
        can be checked against the IOC database.
        """
        ioc_values: Dict[str, List[str]] = {
            "ip": [],
            "domain": [],
            "url": [],
            "hash": [],
            "email": [],
            "process": [],
        }

        # IPs - Use quick-access fields only
        if self.src_ip:
            ioc_values["ip"].append(self.src_ip)
        if self.dst_ip:
            ioc_values["ip"].append(self.dst_ip)

        # Domains - Use quick-access field + DNS answers (which aren't in quick-access)
        if self.domain:
            ioc_values["domain"].append(self.domain)
        if self.dns and self.dns.answers:
            ioc_values["domain"].extend(self.dns.answers)

        # URLs - Use quick-access field only
        if self.url:
            ioc_values["url"].append(self.url)

        # Hashes - Need to check ALL hash fields from file object, not just quick-access
        # (file_hash quick-access only stores highest priority hash, but we need all for IOC matching)
        if self.file_hash:
            ioc_values["hash"].append(self.file_hash)
        if self.file:
            # Extract all available hash values (MD5, SHA1, SHA256, etc.)
            for hash_val in [
                self.file.file_hash,
                self.file.file_hash_md5,
                self.file.file_hash_sha1,
                self.file.file_hash_sha256,
            ]:
                if hash_val and hash_val not in ioc_values["hash"]:
                    ioc_values["hash"].append(hash_val)

        # Emails - No quick-access field, so check nested email fields
        if self.email:
            if self.email.sender:
                ioc_values["email"].append(self.email.sender)
            if self.email.recipient:
                ioc_values["email"].append(self.email.recipient)
            if self.email.recipients:
                ioc_values["email"].extend(self.email.recipients)

        # Process names - Use quick-access field only
        if self.process_name:
            ioc_values["process"].append(self.process_name)

        # Filter out None/empty values (no deduplication needed - each value checked once)
        return {k: [x for x in v if x] for k, v in ioc_values.items()}

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}


class ActivityBatch(BaseModel):
    """
    Batch of activity events for bulk processing.

    Used when ingesting large numbers of events from data sources.
    """

    batch_id: str
    source: ActivitySource
    events: List[NormalizedActivity]
    received_at: datetime = Field(default_factory=datetime.utcnow)
    total_count: int = Field(..., ge=0)
    processed_count: int = Field(0, ge=0)
    failed_count: int = Field(0, ge=0)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_counts(self) -> "ActivityBatch":
        """Ensure counts are consistent."""
        if self.total_count != len(self.events):
            raise ValueError("total_count must match length of events list")
        if self.processed_count + self.failed_count > self.total_count:
            raise ValueError("processed + failed cannot exceed total")
        return self

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}


class ActivityStatistics(BaseModel):
    """
    Statistics about activity events in the system.

    Used for monitoring, dashboards, and capacity planning.
    """

    total_events: int = 0
    events_per_second: float = 0.0

    by_source: Dict[str, int] = Field(default_factory=dict)
    by_event_type: Dict[str, int] = Field(default_factory=dict)

    oldest_event: Optional[datetime] = None
    newest_event: Optional[datetime] = None

    last_updated: datetime = Field(default_factory=datetime.utcnow)

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}
