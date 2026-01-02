# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

LADON is an enterprise Threat XDR (Extended Detection and Response) platform that correlates Indicators of Compromise (IOCs) from multiple threat intelligence feeds against organizational activity logs to identify security threats in real-time. Named after the hundred-headed serpent that guarded the golden apples in the Garden of the Hesperides.

**Key Capabilities:**
- Real-time threat detection with <5 minute SLA
- Correlate IOCs against 5 data sources: Proxy, DNS, Sinkhole, MDE, CrowdStrike logs
- Integrate 3+ threat intelligence feeds: AlienVault OTX, abuse.ch, MISP
- Automated case creation in ServiceNow
- Deep behavioral analytics (beaconing detection, DGA detection, lateral movement)
- Advanced threat hunting capabilities

## Architecture

### Lambda Architecture Pattern
The platform uses a **Lambda architecture** with two processing paths:

1. **Fast Path (Real-time Detection):**
   - Collection Service → Normalization → Detection Service (with Redis IOC cache) → Scoring → Notification → ServiceNow
   - Target: <5 minute detection latency
   - Processes millions of events/day

2. **Slow Path (Deep Analytics):**
   - BigQuery analytics jobs running daily/weekly
   - Behavioral detection (beaconing, DGA, lateral movement)
   - Threat hunting queries

### Monorepo Structure
```
ladon/
├── services/              # Microservices (Cloud Run)
│   ├── gateway/          # API Gateway
│   ├── auth/             # Authentication & Authorization
│   ├── collection/       # IOC and activity log collection
│   ├── normalization/    # Data normalization
│   ├── storage/          # BigQuery/Redis abstraction
│   ├── detection/        # Fast-path IOC correlation
│   ├── enrichment/       # External API enrichment (VT, PassiveTotal, etc.)
│   ├── scoring/          # Threat severity calculation
│   ├── notification/     # ServiceNow, Slack, Email
│   └── [15+ more services across 4 phases]
├── libs/
│   └── python/
│       ├── ladon-common/    # Shared utilities (logging, metrics, config)
│       ├── ladon-models/    # Pydantic data models
│       └── ladon-clients/   # Client libraries
├── infra/
│   └── terraform/           # Infrastructure as Code
└── docs/
```

## Technology Stack

### Primary Platform: Google Cloud Platform
- **Compute:** Cloud Run (serverless containers), GKE for stateful services
- **Storage:** BigQuery (analytics), Firestore (metadata), Cloud Storage
- **Cache:** Cloud Memorystore (Redis)
- **Messaging:** Cloud Pub/Sub
- **Orchestration:** Cloud Composer (Apache Airflow)

### Languages
- **Python 3.11+:** Primary language for most services
- **Go 1.21+:** Performance-critical services (Detection, Collection)
- **SQL:** BigQuery analytics
- **TypeScript/React:** Web UI

### Frameworks
- **FastAPI:** REST API services
- **Pydantic:** Data validation and models
- **gRPC:** Service-to-service communication
- **pytest:** Testing framework

## Core Data Models

### IOC (Indicator of Compromise)
```python
@dataclass
class NormalizedIOC:
    ioc_value: str          # IP, domain, hash, etc.
    ioc_type: str           # ip, domain, url, hash_md5, hash_sha256
    threat_type: str        # malware, c2, phishing, exploit, ransomware
    confidence: float       # 0.0-1.0
    source: str             # Feed name (alienvault, abuse.ch, misp)
    first_seen: datetime
    last_seen: datetime
    tags: List[str]
    metadata: Dict
```

### Activity Event
```python
@dataclass
class NormalizedActivity:
    event_id: str
    timestamp: datetime
    source: str             # proxy, dns, mde, crowdstrike, sinkhole
    event_type: str         # dns_query, http_request, process_create

    # Network fields
    src_ip: Optional[str]
    dst_ip: Optional[str]
    domain: Optional[str]
    url: Optional[str]

    # Host fields
    hostname: Optional[str]
    user: Optional[str]
    process_name: Optional[str]
    file_hash: Optional[str]

    raw_event: Dict         # Original event for reference
```

### Detection
```python
@dataclass
class Detection:
    detection_id: str
    timestamp: datetime
    ioc_value: str
    ioc_type: str
    activity_event_id: str
    activity_source: str
    severity: str           # CRITICAL, HIGH, MEDIUM, LOW
    confidence: float
    enrichment: Dict
    case_id: Optional[str]  # ServiceNow case number
    status: str             # New, Investigating, False Positive, Confirmed, Resolved
```

## Data Flow

### IOC Pipeline
```
AlienVault/abuse.ch/MISP
  → Collection Service
  → [raw-ioc-events] Pub/Sub
  → Normalization Service
  → [normalized-ioc-events] Pub/Sub
  → Enrichment Service (VirusTotal, PassiveTotal)
  → Storage Service → BigQuery + Redis cache
```

### Activity Pipeline
```
Trino/BigQuery (Proxy/DNS/MDE/CrowdStrike)
  → Collection Service (watermark-based incremental)
  → [raw-activity-events] Pub/Sub
  → Normalization Service
  → [normalized-activity-events] Pub/Sub
  → Detection Service (correlate against Redis IOC cache)
  → Scoring Service (calculate severity)
  → Notification Service → ServiceNow/Slack/Email
```

## Detection Logic

### Correlation Algorithm
The Detection Service matches activity events against cached IOCs using:

1. **Domain Matching:**
   - Exact match: `evil.com` = `evil.com`
   - Subdomain match: IOC `evil.com` matches activity `sub.evil.com`

2. **IP Matching:**
   - Exact match: `192.0.2.1` = `192.0.2.1`
   - CIDR match: IOC `192.0.2.0/24` matches any IP in range

3. **Hash Matching:**
   - Exact match only (MD5, SHA256)

4. **URL Matching:**
   - Exact match or domain extraction + domain matching

### Severity Scoring
```python
base_score = ioc.confidence * 100

# Factors:
# - IOC source reputation (abuse.ch: 1.2x, custom: 0.8x)
# - Threat type severity (ransomware: 2.0x, c2: 1.5x, malware: 1.3x)
# - Activity source criticality (mde: 1.5x, sinkhole: 1.8x)
# - Asset criticality from enrichment (high: 1.3x)

# Thresholds:
# - CRITICAL: ≥80
# - HIGH: ≥60
# - MEDIUM: ≥40
# - LOW: <40
```

## BigQuery Schema

### IOCs Table
```sql
threat_xdr.iocs
  - ioc_value STRING
  - ioc_type STRING
  - threat_type STRING
  - confidence FLOAT64
  - source STRING
  - first_seen TIMESTAMP
  - last_seen TIMESTAMP
  - tags ARRAY<STRING>
  - enrichment JSON
  PARTITION BY DATE(first_seen)
  CLUSTER BY ioc_type, source
```

### Activity Logs Table
```sql
threat_xdr.activity_logs
  - event_id STRING
  - timestamp TIMESTAMP
  - source STRING
  - event_type STRING
  - src_ip, dst_ip, domain, url, hostname, user, process_name, file_hash
  - enrichment JSON
  - raw_event JSON
  PARTITION BY DATE(timestamp)
  CLUSTER BY source, event_type
```

### Detections Table
```sql
threat_xdr.detections
  - detection_id STRING
  - timestamp TIMESTAMP
  - ioc_value STRING
  - activity_event_id STRING
  - severity STRING
  - confidence FLOAT64
  - case_id STRING
  - status STRING
  PARTITION BY DATE(timestamp)
  CLUSTER BY severity, status
```

## Development Workflow

### Setting Up a New Service

When creating a new service (e.g., Detection Service), follow this pattern:

1. **Service Structure:**
   ```
   services/detection/
   ├── src/
   │   ├── main.py              # FastAPI app
   │   ├── detection_engine.py  # Core business logic
   │   ├── config.py            # Configuration
   │   └── models.py            # Pydantic models
   ├── tests/
   │   ├── test_engine.py
   │   └── test_api.py
   ├── Dockerfile
   ├── requirements.txt
   └── README.md
   ```

2. **Standard Components:**
   - Health check endpoint: `GET /health`
   - Structured logging using `ladon-common`
   - Prometheus metrics: `detections_total`, `detection_latency_seconds`
   - Error handling with standard error response format
   - RBAC enforcement on protected endpoints

3. **FastAPI Application Template:**
   ```python
   from fastapi import FastAPI, Depends
   from ladon_common.logging import setup_logging
   from ladon_common.metrics import setup_metrics
   from ladon_common.auth import verify_token

   app = FastAPI(title="Detection Service", version="1.0")
   setup_logging()
   setup_metrics(app)

   @app.get("/health")
   async def health():
       return {"status": "healthy"}

   @app.post("/v1/detect", dependencies=[Depends(verify_token)])
   async def detect(events: List[ActivityEvent]):
       # Implementation
   ```

### Watermark-Based Collection Pattern

All collection services must use watermarks for incremental collection:

```python
from ladon_common.watermark import WatermarkManager

watermark_mgr = WatermarkManager()

def collect(source_config):
    # Get last successful timestamp
    watermark = watermark_mgr.get_watermark(source_config.id)

    # Query for new data since watermark
    query = f"""
        SELECT * FROM {source_config.table}
        WHERE timestamp > '{watermark.last_successful}'
        ORDER BY timestamp
        LIMIT 100000
    """

    events = execute_query(query)

    if events:
        # Publish to Pub/Sub
        publish_to_pubsub(topic='raw-events', data=events)

        # Update watermark atomically
        watermark_mgr.update_watermark(
            source_config.id,
            max(e.timestamp for e in events),
            status='success'
        )
```

### Service Communication Patterns

1. **Async Messaging (Primary):**
   - Use Pub/Sub for event streaming between services
   - Dead letter queues for failed messages
   - Idempotent message handlers

2. **Sync API Calls (Secondary):**
   - Use gRPC for low-latency service-to-service calls
   - Implement circuit breakers for external APIs
   - Retry with exponential backoff

3. **Cache Strategy:**
   - Redis for hot IOCs (last 48 hours + confidence >0.7)
   - 24-hour TTL
   - Cache key format: `ioc:{ioc_type}:{ioc_value}`

## External API Integration

### Rate Limiting Strategy
```python
from ladon_common.rate_limiter import RateLimiter

# VirusTotal: 4 requests/min (free tier)
vt_limiter = RateLimiter(rate=4, per=60)

# Cache enrichment for 7 days
@cache(ttl=604800)
def get_virustotal_domain(domain):
    vt_limiter.acquire()
    return vt_api.get_domain(domain)
```

### Circuit Breaker Pattern
```python
from ladon_common.circuit_breaker import CircuitBreaker

vt_breaker = CircuitBreaker(
    failure_threshold=5,
    timeout=60,
    expected_exceptions=[APIRateLimitError, APITimeoutError]
)

result = vt_breaker.call(get_virustotal_domain, domain)
```

## Analytics Jobs (Slow Path)

### Beaconing Detection
Runs daily to detect C2 beaconing patterns:
- Regular connection intervals (low stddev)
- High connection count
- Intervals between 1 minute and 1 hour

### DGA Detection
Runs daily to detect Domain Generation Algorithm patterns:
- Long domain names (>15 chars)
- High entropy (>3.5)
- Low query count (rare domains)

### Lateral Movement Detection
Runs daily to detect unusual authentication patterns:
- Users accessing >20 unique hosts
- >50 authentication events

## Testing Strategy

### Unit Tests
- Target: >80% code coverage
- Use pytest with fixtures for test data
- Mock external dependencies (BigQuery, Redis, external APIs)

### Integration Tests
- Test full pipeline with sample data
- Use BigQuery emulator or test project
- Use Redis mock or local instance

### Performance Tests
- Load test at 2x expected volume
- Target: Process 10K events/min
- Detection latency <100ms per batch (1000 events)

## Security Considerations

### Authentication & Authorization
- Service-to-service: JWT tokens (15 min TTL)
- User auth: SSO via Okta/Auth0 (SAML 2.0)
- API keys: Generated via Auth Service with rotation
- Secrets: Google Secret Manager (never commit secrets)

### RBAC Roles
- **Analyst:** Read detections, run hunts, view dashboards
- **SOC Lead:** All analyst + approve whitelists, manage cases
- **Admin:** All + service configuration, user management
- **API User:** Programmatic access with scoped permissions

### Data Privacy
- PII handling: Tokenize usernames, IP addresses in logs
- Audit logging: 7-year retention for compliance
- Encryption: At-rest (Cloud KMS), in-transit (TLS 1.3)

## Cost Optimization

### BigQuery Best Practices
- **Always** use partition filters in WHERE clauses
- Use clustering for common filter columns
- Estimate query costs before running large queries
- Set daily/monthly quotas to prevent runaway costs
- Use streaming inserts (not individual inserts) for high throughput

### Redis Optimization
- Cache only hot IOCs (last 48 hours, confidence >0.7)
- Use TTL to auto-expire old entries
- Monitor cache hit rate (target >95%)

## Monitoring & Observability

### Key Metrics
```python
# Collection
collection_events_per_second
collection_errors_total
collection_latency_seconds

# Detection
detections_created_total
detection_latency_seconds
false_positive_rate

# Enrichment
enrichment_api_calls_total
enrichment_cache_hit_rate
enrichment_latency_seconds
```

### Structured Logging Format
```python
{
    "timestamp": "2026-01-01T12:00:00Z",
    "severity": "INFO",
    "service": "detection",
    "trace_id": "abc123",
    "message": "Detection created",
    "detection_id": "det_123",
    "severity": "CRITICAL",
    "ioc_value": "malicious.com"
}
```

## Deployment

### Cloud Run Deployment
Each service follows this pattern:
1. Build: `docker build -t gcr.io/project/service:tag .`
2. Push: `docker push gcr.io/project/service:tag`
3. Deploy: `gcloud run deploy service --image gcr.io/project/service:tag --region us-central1`

### Terraform Infrastructure
- Modules: `infra/terraform/modules/` (cloud-run, pubsub, bigquery)
- Environments: `infra/terraform/environments/{dev,staging,prod}/`
- State: GCS backend with locking

### CI/CD Pipeline
1. Pre-commit: Lint, type check, unit tests
2. PR: Integration tests, security scan (SonarQube)
3. Merge to main: Build, deploy to dev
4. Tag: Deploy to staging → manual approval → prod

## Common Patterns

### Error Handling
```python
from ladon_common.errors import LadonError, APIError

try:
    result = external_api_call()
except APIRateLimitError as e:
    # Circuit breaker will handle retry
    raise
except APIError as e:
    # Log and publish to DLQ
    logger.error(f"API error: {e}")
    publish_to_dlq(event)
    raise LadonError("Enrichment failed") from e
```

### Standard Error Response
```json
{
    "error": {
        "code": "DETECTION_FAILED",
        "message": "Failed to correlate events",
        "details": {...},
        "trace_id": "abc123"
    }
}
```

## Project Phases

The platform is built across 4 phases over 18 months:

1. **Phase 1 (Months 1-6): MVP**
   - Core detection pipeline (8 services)
   - Real-time IOC detection
   - ServiceNow integration

2. **Phase 2 (Months 7-10): Intelligence & Analytics**
   - Enrichment, deep analytics, threat intel services (7 services)
   - Behavioral detection jobs

3. **Phase 3 (Months 11-14): Operations & Scale**
   - Observability, validation, backfill services (6 services)
   - Production hardening

4. **Phase 4 (Months 15-18): Advanced Features**
   - Threat hunting, playbooks, ML services (7 services)
   - Automated response

## Key Performance Targets

- **Detection Latency:** <5 minutes (p95)
- **Throughput:** 10M+ events/day
- **False Positive Rate:** <5% for high-severity alerts
- **Uptime:** 99.9%
- **MTTD (Mean Time to Detect):** <5 minutes for known IOCs
- **MTTR (Mean Time to Resolve):** <30 minutes

## References

- **Quick Start Guide:** `ladon_quick_start_guide.md` - How to use this spec with Claude for code generation
- **Project Plan:** `threat_xdr_project_plan.md` - Detailed 18-month roadmap with all service specifications

## Working with This Codebase

When implementing services:
1. Always reference the service specifications in `threat_xdr_project_plan.md`
2. Use the data models defined above (IOC, ActivityEvent, Detection)
3. Follow the Lambda architecture pattern (fast path + slow path)
4. Implement watermark-based collection for all data sources
5. Use Pub/Sub for async messaging, gRPC for sync calls
6. Apply rate limiting and circuit breakers for external APIs
7. Write comprehensive tests (unit + integration)
8. Include structured logging and metrics in all services
9. Follow security best practices (RBAC, secret management, audit logging)
