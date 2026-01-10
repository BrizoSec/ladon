"""
LADON Data Models Package

This package provides all data models used across the LADON platform,
including IOCs, activity events, detections, and supporting utilities.
"""

# Version
__version__ = "0.1.0"

# Enums
from .enums import (
    ActivityEventType,
    ActivitySource,
    DetectionStatus,
    EnrichmentProvider,
    IOCSource,
    IOCType,
    Severity,
    ThreatType,
)

# IOC Models
from .ioc import (
    IOCBatch,
    IOCMatch,
    IOCMetadata,
    IOCStatistics,
    NormalizedIOC,
    RawIOC,
)

# Activity Models
from .activity import (
    ActivityBatch,
    ActivityStatistics,
    DNSFields,
    EmailFields,
    FileFields,
    HostFields,
    HTTPFields,
    NetworkFields,
    NormalizedActivity,
    ProcessFields,
    RawActivity,
    UserFields,
)

# Detection Models
from .detection import (
    Detection,
    DetectionBatch,
    DetectionStatistics,
    EnrichmentData,
    SeverityScore,
)

# Threat Models
from .threat import (
    MalwareFamily,
    MITRETechnique,
    Threat,
    ThreatActor,
    ThreatCampaign,
    ThreatIOCAssociation,
    ThreatStatistics,
)

# Validators and Utilities
from .validators import (
    DomainMatcher,
    HashCalculator,
    IOCValidator,
    IPMatcher,
)

__all__ = [
    # Version
    "__version__",
    # Enums
    "IOCType",
    "ThreatType",
    "Severity",
    "DetectionStatus",
    "ActivitySource",
    "ActivityEventType",
    "IOCSource",
    "EnrichmentProvider",
    # IOC Models
    "NormalizedIOC",
    "RawIOC",
    "IOCMetadata",
    "IOCMatch",
    "IOCBatch",
    "IOCStatistics",
    # Activity Models
    "NormalizedActivity",
    "RawActivity",
    "NetworkFields",
    "HostFields",
    "UserFields",
    "ProcessFields",
    "FileFields",
    "EmailFields",
    "DNSFields",
    "HTTPFields",
    "ActivityBatch",
    "ActivityStatistics",
    # Detection Models
    "Detection",
    "SeverityScore",
    "EnrichmentData",
    "DetectionBatch",
    "DetectionStatistics",
    # Threat Models
    "Threat",
    "ThreatActor",
    "ThreatCampaign",
    "MalwareFamily",
    "MITRETechnique",
    "ThreatIOCAssociation",
    "ThreatStatistics",
    # Validators
    "IOCValidator",
    "DomainMatcher",
    "IPMatcher",
    "HashCalculator",
]
