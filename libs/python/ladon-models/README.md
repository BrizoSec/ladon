# ladon-models

Core data models for the LADON platform. This package provides Pydantic-based models for IOCs (Indicators of Compromise), activity events, detections, and supporting utilities.

## Overview

The `ladon-models` package provides:

- **Flexible IOC models** supporting 25+ IOC types (IP, domain, URL, hash, email, etc.)
- **Normalized activity event models** for proxy, DNS, EDR, and other log sources
- **Detection models** with severity scoring and case management integration
- **Validation utilities** for IOC validation and matching
- **Type-safe enums** for consistent categorization

## Installation

```bash
cd libs/python/ladon-models
poetry install
```

## Quick Start

### Working with IOCs

```python
from datetime import datetime
from ladon_models import NormalizedIOC, IOCType, ThreatType, IOCSource

# Create a malicious domain IOC
ioc = NormalizedIOC(
    ioc_value="evil.com",
    ioc_type=IOCType.DOMAIN,
    threat_type=ThreatType.C2,
    confidence=0.85,
    source=IOCSource.ALIENVAULT_OTX,
    first_seen=datetime.utcnow(),
    last_seen=datetime.utcnow(),
    tags=["apt", "cobalt-strike"]
)

print(f"IOC: {ioc.ioc_value} ({ioc.threat_type})")
print(f"Age: {ioc.age_days()} days")
print(f"Active: {not ioc.is_expired()}")
```

### Working with Activity Events

```python
from ladon_models import (
    NormalizedActivity,
    ActivitySource,
    ActivityEventType,
    NetworkFields,
    DNSFields
)

# Create a DNS query activity event
activity = NormalizedActivity(
    event_id="evt_12345",
    timestamp=datetime.utcnow(),
    source=ActivitySource.DNS,
    event_type=ActivityEventType.DNS_QUERY,
    network=NetworkFields(
        src_ip="10.0.1.100",
        domain="evil.com"
    ),
    dns=DNSFields(
        query="evil.com",
        query_type="A",
        answers=["192.0.2.100"]
    )
)

# Extract all potential IOC values
ioc_values = activity.extract_ioc_values()
print(f"Domains to check: {ioc_values['domain']}")
print(f"IPs to check: {ioc_values['ip']}")
```

### Creating Detections

```python
from ladon_models import Detection, Severity, SeverityScore

# Calculate severity based on IOC and activity context
severity_score = SeverityScore.calculate(
    ioc=ioc,
    activity_source=ActivitySource.DNS,
    asset_criticality="high"
)

# Create detection
detection = Detection(
    detection_id="det_12345",
    timestamp=datetime.utcnow(),
    ioc_value="evil.com",
    ioc_type="domain",
    ioc=ioc,
    activity_event_id="evt_12345",
    activity_source=ActivitySource.DNS,
    activity=activity,
    severity=severity_score.severity,
    confidence=0.85,
    severity_score=severity_score,
    first_seen=datetime.utcnow(),
    last_seen=datetime.utcnow()
)

print(f"Detection: {detection.detection_id}")
print(f"Severity: {detection.severity} (score: {detection.severity_score.final_score:.1f})")
print(f"Critical: {detection.is_critical()}")
```

## Supported IOC Types

The platform supports 25+ IOC types:

### Network Indicators
- `ip`, `ipv4`, `ipv6` - IP addresses
- `domain` - Domain names
- `url` - URLs
- `email` - Email addresses
- `cidr` - CIDR notation
- `asn` - Autonomous System Numbers

### File Indicators
- `hash_md5`, `hash_sha1`, `hash_sha256`, `hash_sha512` - File hashes
- `file_path`, `file_name` - File system paths
- `imphash`, `ssdeep` - Specialized hash types

### User/Account Indicators
- `username`, `account_number`, `user_agent`

### Other Indicators
- `ssl_cert_fingerprint`, `ja3_fingerprint` - TLS fingerprints
- `registry_key` - Windows registry keys
- `process_name`, `mutex` - Process indicators
- `cve` - CVE identifiers
- `mac_address` - MAC addresses

## Validation Utilities

### IOC Validation

```python
from ladon_models import IOCValidator

# Validate various IOC types
IOCValidator.is_valid_ipv4("192.0.2.1")  # True
IOCValidator.is_valid_domain("example.com")  # True
IOCValidator.is_valid_email("user@example.com")  # True
IOCValidator.is_valid_sha256("a" * 64)  # True

# Auto-detect hash type
hash_type = IOCValidator.detect_hash_type("d41d8cd98f00b204e9800998ecf8427e")
print(hash_type)  # "hash_md5"
```

### Domain Matching

```python
from ladon_models import DomainMatcher

# Check subdomain relationships
DomainMatcher.is_subdomain("sub.evil.com", "evil.com")  # True
DomainMatcher.is_subdomain("evil.com", "evil.com")  # True

# Extract base domain
base = DomainMatcher.extract_base_domain("www.sub.example.com")
print(base)  # "example.com"

# Extract domain from URL
domain = DomainMatcher.extract_domain_from_url("https://evil.com/path")
print(domain)  # "evil.com"
```

### IP Matching

```python
from ladon_models import IPMatcher

# Check CIDR membership
IPMatcher.ip_in_cidr("192.0.2.50", "192.0.2.0/24")  # True

# Check for private IPs
IPMatcher.is_private_ip("10.0.1.1")  # True
IPMatcher.is_private_ip("8.8.8.8")  # False

# Check for reserved IPs
IPMatcher.is_reserved_ip("127.0.0.1")  # True
```

## Data Model Details

### NormalizedIOC

Core IOC model with:
- **Flexible typing**: Support for 25+ IOC types
- **Confidence scoring**: 0.0-1.0 confidence range
- **Source tracking**: Track which threat feed provided the IOC
- **Temporal tracking**: first_seen, last_seen, expires_at
- **Rich metadata**: Tags, malware families, campaigns, geolocation
- **Auto-normalization**: Automatic value normalization (lowercase domains, normalized IPs)

### NormalizedActivity

Unified activity event model with:
- **Multi-source support**: DNS, proxy, EDR, firewall, email gateway, etc.
- **Structured fields**: Network, host, user, process, file, email, DNS, HTTP
- **Quick-access fields**: Denormalized fields for fast detection
- **IOC extraction**: Built-in method to extract checkable IOC values
- **Flexible enrichment**: Store external enrichment data

### Detection

Detection model with:
- **Severity scoring**: Automatic calculation based on IOC confidence, threat type, and context
- **Case management**: ServiceNow integration fields
- **Analyst workflow**: Status tracking, notes, assignment
- **Temporal tracking**: Occurrence counting and time-to-resolution
- **Rich context**: Full IOC and activity objects embedded

## Severity Scoring Algorithm

Detections are scored using a multi-factor algorithm:

```
base_score = ioc.confidence * 100

final_score = base_score
    * ioc_source_multiplier      # abuse.ch: 1.2x, custom: 0.8x
    * threat_type_multiplier      # ransomware: 2.0x, c2: 1.5x
    * activity_source_multiplier  # EDR: 1.5x, sinkhole: 1.8x
    * asset_criticality_multiplier # critical: 1.5x, low: 0.9x

Severity levels:
- CRITICAL: score >= 80
- HIGH: score >= 60
- MEDIUM: score >= 40
- LOW: score < 40
```

## Enums

All categorical values use type-safe enums:

```python
from ladon_models import (
    IOCType,
    ThreatType,
    Severity,
    DetectionStatus,
    ActivitySource,
    ActivityEventType,
    IOCSource,
    EnrichmentProvider
)
```

## Field Groups

Activity events use structured field groups for organization:

- `NetworkFields` - IPs, ports, domains, URLs, protocols
- `HostFields` - Hostname, FQDN, OS information
- `UserFields` - Username, email, SID, UID
- `ProcessFields` - Process name, PID, command line
- `FileFields` - File name, path, hashes
- `EmailFields` - Sender, recipients, subject, attachments
- `DNSFields` - Query, type, response, answers
- `HTTPFields` - Method, status, user agent, headers

## Batch Processing

All models support batch processing:

```python
from ladon_models import IOCBatch, ActivityBatch, DetectionBatch

# Batch IOC ingestion
ioc_batch = IOCBatch(
    batch_id="batch_123",
    source=IOCSource.ALIENVAULT_OTX,
    iocs=[ioc1, ioc2, ioc3],
    total_count=3
)

# Track processing
ioc_batch.processed_count = 3
ioc_batch.failed_count = 0
```

## Statistics Models

Track system metrics with statistics models:

```python
from ladon_models import IOCStatistics, ActivityStatistics, DetectionStatistics

stats = DetectionStatistics(
    total_detections=1000,
    by_severity={"CRITICAL": 50, "HIGH": 200, "MEDIUM": 500, "LOW": 250},
    avg_time_to_resolution_hours=2.5
)
```

## Testing

Run tests with:

```bash
poetry run pytest
```

## Type Checking

Run type checking with:

```bash
poetry run mypy ladon_models
```

## Usage in Services

Import models in your services:

```python
from ladon_models import (
    NormalizedIOC,
    NormalizedActivity,
    Detection,
    IOCType,
    Severity,
    IOCValidator
)

# Use in FastAPI endpoints
from fastapi import FastAPI

app = FastAPI()

@app.post("/v1/iocs")
async def create_ioc(ioc: NormalizedIOC):
    # Pydantic automatically validates
    return {"status": "created", "ioc_id": ioc.ioc_value}
```

## Contributing

When adding new IOC types or fields:

1. Add enum to `enums.py`
2. Add validation to `validators.py`
3. Update model field definitions
4. Add tests
5. Update this README

## License

Internal use only - LADON Platform
