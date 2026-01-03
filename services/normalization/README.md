## Normalization Service

The Normalization Service transforms raw events from various sources (threat intelligence feeds, activity logs) into standardized formats using the `ladon-models` data models. It consumes events from Pub/Sub, validates and normalizes them, and publishes to downstream services.

## Features

- **Multi-Source Support**: Normalizes IOCs from AlienVault OTX, abuse.ch, MISP and activity logs from DNS, Proxy, MDE, CrowdStrike, Sinkhole
- **Automatic Validation**: Validates events using Pydantic models with configurable strictness
- **Dead Letter Queue**: Failed events are routed to DLQ topics for analysis and reprocessing
- **Batch Processing**: Efficiently processes messages in batches from Pub/Sub
- **Error Handling**: Graceful handling of invalid data with skip or fail modes
- **Real-time Processing**: Continuous processing loops for IOC and activity events

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│              Collection Service                          │
│  - AlienVault OTX, abuse.ch, MISP                       │
│  - Trino, BigQuery                                      │
└────────────────┬───────────────────────────────────────┘
                 │ publishes raw events
                 ↓
┌─────────────────────────────────────────────────────────┐
│            Pub/Sub Topics                                │
│  - raw-ioc-events                                       │
│  - raw-activity-events                                  │
└────────────────┬───────────────────────────────────────┘
                 │
                 v
┌─────────────────────────────────────────────────────────┐
│          Normalization Service                           │
│  ┌─────────────────────────────────────────────┐        │
│  │ IOC Normalizers                             │        │
│  │  - AlienVault OTX                           │        │
│  │  - abuse.ch                                 │        │
│  │  - MISP                                     │        │
│  └─────────────────────────────────────────────┘        │
│  ┌─────────────────────────────────────────────┐        │
│  │ Activity Normalizers                        │        │
│  │  - DNS, Proxy, MDE                          │        │
│  │  - CrowdStrike, Sinkhole                    │        │
│  └─────────────────────────────────────────────┘        │
└────────────────┬───────────────────────────────────────┘
                 │
    ┌────────────┴──────────────┐
    ↓                           ↓
┌─────────────────┐    ┌─────────────────┐
│  Normalized     │    │  Dead Letter    │
│  Events Topics  │    │  Queue Topics   │
│  - normalized-  │    │  - dlq-ioc-     │
│    ioc-events   │    │    events       │
│  - normalized-  │    │  - dlq-activity-│
│    activity-    │    │    events       │
│    events       │    │                 │
└─────────────────┘    └─────────────────┘
         │
         ↓
┌─────────────────────────────────────────────────────────┐
│          Detection Service                               │
│  (Correlates IOCs against activity)                     │
└─────────────────────────────────────────────────────────┘
```

## Data Flow

### IOC Normalization Flow

```python
# Input: Raw IOC from Collection Service
{
    "ioc_value": "evil.com",
    "ioc_type": "domain",
    "threat_type": "malware",
    "confidence": 0.85,
    "source": "alienvault_otx",
    "first_seen": "2024-01-01T00:00:00Z",
    "last_seen": "2024-01-02T00:00:00Z",
    "tags": ["malware", "c2"],
    "metadata": {"pulse_id": "123"}
}

# ↓ Normalization

# Output: NormalizedIOC (ladon-models)
NormalizedIOC(
    ioc_value="evil.com",
    ioc_type=IOCType.DOMAIN,
    threat_type=ThreatType.MALWARE,
    confidence=0.85,
    source=IOCSource.ALIENVAULT_OTX,
    first_seen=datetime(...),
    last_seen=datetime(...),
    tags=["malware", "c2"],
    metadata={"pulse_id": "123"}
)
```

### Activity Normalization Flow

```python
# Input: Raw DNS event from Trino
{
    "event_id": "dns_123",
    "timestamp": "2024-01-01T12:00:00Z",
    "query_name": "test.com",
    "client_ip": "192.0.2.1",
    "server_ip": "8.8.8.8"
}

# ↓ Normalization (DNS-specific mapping)

# Output: NormalizedActivity (ladon-models)
NormalizedActivity(
    event_id="dns_123",
    timestamp=datetime(...),
    source=ActivitySource.DNS,
    event_type=ActivityEventType.DNS_QUERY,
    domain="test.com",
    src_ip="192.0.2.1",
    dst_ip="8.8.8.8",
    raw_event={...}  # Original event preserved
)
```

## Normalizers

### IOC Normalizers

- **AlienVaultOTXNormalizer**: AlienVault OTX pulses and indicators
- **AbuseCHNormalizer**: abuse.ch feeds (ThreatFox, URLhaus, MalwareBazaar)
- **MISPNormalizer**: MISP events and attributes
- **GenericIOCNormalizer**: Custom IOC sources

### Activity Normalizers

- **DNSNormalizer**: DNS query logs
  - Maps `query_name` → `domain`, `client_ip` → `src_ip`
- **ProxyNormalizer**: HTTP proxy logs
  - Extracts domain from URL, maps `username` → `user`
- **MDENormalizer**: Microsoft Defender for Endpoint
  - Maps `device_name` → `hostname`, `sha256` → `file_hash`
- **CrowdStrikeNormalizer**: CrowdStrike Falcon logs
  - Maps `computer_name` → `hostname`, `image_file_name` → `process_name`
- **SinkholeNormalizer**: Sinkhole connection logs
  - Maps `sinkhole_ip` → `dst_ip`, `queried_domain` → `domain`
- **GenericActivityNormalizer**: Custom activity sources

## Configuration

Environment variables:

```bash
# Environment
ENVIRONMENT=development|staging|production
LOG_LEVEL=DEBUG|INFO|WARNING|ERROR

# Pub/Sub
PUBSUB_PROJECT_ID=your-gcp-project
PUBSUB_RAW_IOC_EVENTS_TOPIC=raw-ioc-events
PUBSUB_RAW_ACTIVITY_EVENTS_TOPIC=raw-activity-events
PUBSUB_NORMALIZED_IOC_EVENTS_TOPIC=normalized-ioc-events
PUBSUB_NORMALIZED_ACTIVITY_EVENTS_TOPIC=normalized-activity-events
PUBSUB_IOC_SUBSCRIPTION=normalization-ioc-sub
PUBSUB_ACTIVITY_SUBSCRIPTION=normalization-activity-sub

# Validation
STRICT_VALIDATION=true|false  # Fail on validation errors vs skip
SKIP_INVALID_IOCS=true|false  # Skip invalid IOCs vs fail entire batch
```

## API Endpoints

### Health Check
```bash
GET /health
```

Returns health status.

**Response:**
```json
{
  "status": "healthy",
  "running": true
}
```

### Service Status
```bash
GET /status
```

Returns detailed status.

**Response:**
```json
{
  "service": "normalization",
  "running": true,
  "processing_tasks": 2,
  "config": {
    "environment": "production",
    "strict_validation": true,
    "skip_invalid_iocs": true
  }
}
```

### Process IOC Batch
```bash
POST /process/ioc
```

Triggers one-time processing of IOC messages.

**Response:**
```json
{
  "total": 100,
  "success": 98,
  "failed": 2
}
```

### Process Activity Batch
```bash
POST /process/activity
```

Triggers one-time processing of activity messages.

## Development

### Installation

```bash
cd services/normalization
pip install -r requirements.txt
```

### Running Locally

```bash
cd services/normalization
python -m src.main
```

The service will start on `http://localhost:8001`.

### Running Tests

```bash
pytest tests/ -v --cov=src
```

## Error Handling

### Validation Modes

**Strict Mode** (`strict_validation=true`):
- Fails entire batch if any event is invalid
- Use for critical pipelines where data quality is paramount

**Lenient Mode** (`strict_validation=false`):
- Skips invalid events and continues processing
- Sends failed events to DLQ for manual review
- Use for high-volume pipelines where some data loss is acceptable

### Dead Letter Queue

Failed events are published to DLQ topics with error information:

```json
{
  "raw_event": { /* original event */ },
  "error": "ValidationError: Field 'ioc_type' is required",
  "timestamp": "2024-01-01T12:00:00Z"
}
```

### Monitoring DLQ

```bash
# Pull messages from DLQ
gcloud pubsub subscriptions pull dlq-ioc-events-sub --limit=10

# Count messages in DLQ
gcloud pubsub topics describe dlq-ioc-events
```

## Performance

### Throughput

- **IOC Events**: ~10K events/minute
- **Activity Events**: ~50K events/minute (depends on source)

### Latency

- **Normalization**: <10ms per event
- **End-to-End**: <100ms from Pub/Sub pull to publish

### Optimization Tips

1. **Batch Size**: Increase `max_messages_per_pull` for higher throughput
2. **Workers**: Increase `max_workers` for concurrent processing
3. **Skip Invalid**: Enable `skip_invalid_iocs` to avoid blocking on bad data

## Monitoring

Key metrics to monitor:

- `normalization_events_per_second`: Throughput
- `normalization_validation_errors_total`: Validation failure rate
- `normalization_latency_seconds`: Processing duration
- `dlq_messages_total`: Dead letter queue depth

## Deployment

The Normalization Service is deployed as a Cloud Run service:

```bash
# Build and push image
gcloud builds submit --tag gcr.io/PROJECT_ID/normalization-service

# Deploy to Cloud Run
gcloud run deploy normalization-service \
  --image gcr.io/PROJECT_ID/normalization-service \
  --region us-central1 \
  --set-env-vars ENVIRONMENT=production
```

## Troubleshooting

### High DLQ volume

1. Check validation errors: `GET /status`
2. Review DLQ messages for patterns
3. Adjust source mapping or add custom normalizer

### Processing stalls

1. Check Pub/Sub subscription backlog
2. Increase `max_workers` or `max_messages_per_pull`
3. Review logs for errors

### Memory usage

1. Reduce `max_messages_per_pull`
2. Enable `skip_invalid_iocs` to avoid holding invalid data
3. Monitor batch size

## License

Copyright (c) 2024 LADON Team
