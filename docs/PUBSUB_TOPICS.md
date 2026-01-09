# LADON Pub/Sub Topics Architecture

This document describes all Pub/Sub topics in the LADON Threat XDR platform and how data flows through them.

## Overview

The LADON platform uses Google Cloud Pub/Sub as the primary messaging backbone for asynchronous data processing. The architecture follows a **Lambda pattern** with distinct raw and normalized event streams.

## Topic Categories

### 1. Raw Event Topics
Raw events are published directly from collectors without normalization or validation.

### 2. Normalized Event Topics
Normalized events are published after validation, standardization, and enrichment.

### 3. Dead Letter Queue (DLQ) Topics
Failed messages are routed to DLQ topics for investigation and replay.

---

## Complete Topic List

| Topic Name | Type | Publisher | Subscriber | Description |
|------------|------|-----------|------------|-------------|
| `raw-ioc-events` | Raw | Collection Service | Normalization Service | Raw IOC data from threat feeds |
| `raw-activity-events` | Raw | Collection Service | Normalization Service | Raw activity logs from data sources |
| `raw-threat-events` | Raw | Collection Service | Normalization Service | Raw threat intelligence (actors, campaigns, malware) |
| `normalized-ioc-events` | Normalized | Normalization Service | Storage, Detection | Validated and standardized IOCs |
| `normalized-activity-events` | Normalized | Normalization Service | Detection Service | Validated and standardized activity logs |
| `normalized-threat-events` | Normalized | Normalization Service | Storage Service | Validated threat intelligence data |
| `dlq-ioc-events` | DLQ | Normalization Service | Manual Review | Failed IOC normalization |
| `dlq-activity-events` | DLQ | Normalization Service | Manual Review | Failed activity normalization |
| `dlq-threat-events` | DLQ | Normalization Service | Manual Review | Failed threat normalization |

---

## Data Flow Diagrams

### IOC Data Flow

```
AlienVault/abuse.ch/MISP (External APIs)
    ↓
Collection Service
    ↓ [publishes]
raw-ioc-events
    ↓ [subscribes]
Normalization Service
    ├─ [validates/normalizes] → normalized-ioc-events
    │                              ↓
    │                          Detection Service (correlates with activity)
    │                              ↓
    │                          Storage Service (BigQuery + Redis)
    │
    └─ [validation fails] → dlq-ioc-events
                              ↓
                          Manual Review/Replay
```

### Activity Log Data Flow

```
Trino/BigQuery (Proxy, DNS, MDE, CrowdStrike)
    ↓
Collection Service
    ↓ [publishes]
raw-activity-events
    ↓ [subscribes]
Normalization Service
    ├─ [validates/normalizes] → normalized-activity-events
    │                              ↓
    │                          Detection Service (correlates with IOCs)
    │                              ↓
    │                          Storage Service (BigQuery)
    │
    └─ [validation fails] → dlq-activity-events
```

### Threat Intelligence Data Flow

```
AlienVault (Threat Actors/Campaigns)
abuse.ch (Malware Families)
MISP (Threat Intelligence)
    ↓
Collection Service (Threat Extractors)
    ↓ [publishes]
raw-threat-events
    ↓ [subscribes]
Normalization Service
    ├─ [validates/normalizes] → normalized-threat-events
    │                              ↓
    │                          Storage Service (BigQuery threats table)
    │                              ↓
    │                          Enrichment Service (contextualize detections)
    │
    └─ [validation fails] → dlq-threat-events
```

---

## Topic Details

### raw-ioc-events

**Description:** Raw IOC data collected from threat intelligence feeds

**Message Format:**
```json
{
  "source": "alienvault_otx",
  "collection_timestamp": "2026-01-09T12:34:56Z",
  "ioc_data": {
    "ioc_value": "malicious.com",
    "ioc_type": "domain",
    "threat_type": "c2",
    "confidence": 0.95,
    "first_seen": "2026-01-08T10:00:00Z",
    "tags": ["apt29", "cozy-bear"],
    "metadata": { ... }
  }
}
```

**Volume:** ~10K-100K events/day
**Retention:** 7 days
**Partitioning:** By source

---

### raw-activity-events

**Description:** Raw activity logs from organizational data sources

**Message Format:**
```json
{
  "source": "proxy_logs",
  "collection_timestamp": "2026-01-09T12:34:56Z",
  "event_data": {
    "timestamp": "2026-01-09T12:30:00Z",
    "src_ip": "10.0.1.100",
    "dst_ip": "93.184.216.34",
    "domain": "suspicious.com",
    "url": "http://suspicious.com/malware.exe",
    "user": "john.doe@company.com",
    "bytes_transferred": 1024
  }
}
```

**Volume:** ~10M-50M events/day (high volume!)
**Retention:** 1 day (fast processing)
**Partitioning:** By source and timestamp

---

### raw-threat-events

**Description:** Raw threat intelligence data (actors, campaigns, malware families)

**Message Format:**
```json
{
  "source": "alienvault_otx",
  "collection_timestamp": "2026-01-09T12:34:56Z",
  "threat_data": {
    "threat_category": "actor",
    "name": "APT29",
    "aliases": ["Cozy Bear", "The Dukes"],
    "threat_type": "c2",
    "first_seen": "2015-01-01T00:00:00Z",
    "last_seen": "2026-01-08T00:00:00Z",
    "techniques": [
      {
        "technique_id": "T1566.001",
        "technique_name": "Spearphishing Attachment",
        "tactic": "Initial Access"
      }
    ],
    "associated_iocs": ["evil.com", "192.0.2.1"],
    "description": "Advanced persistent threat group..."
  }
}
```

**Volume:** ~1K-10K events/day
**Retention:** 7 days
**Partitioning:** By threat category

---

### normalized-ioc-events

**Description:** Validated, standardized IOCs ready for detection

**Message Format:**
```json
{
  "ioc_value": "malicious.com",
  "ioc_type": "domain",
  "threat_type": "c2",
  "confidence": 0.95,
  "source": "alienvault_otx",
  "first_seen": "2026-01-08T10:00:00Z",
  "last_seen": "2026-01-09T12:34:56Z",
  "tags": ["apt29", "cozy-bear"],
  "metadata": {
    "original_source": "alienvault_otx",
    "normalization_timestamp": "2026-01-09T12:35:00Z",
    "validation_passed": true
  },
  "is_active": true,
  "is_whitelisted": false
}
```

**Volume:** ~8K-90K events/day (some filtered)
**Retention:** 7 days
**Partitioning:** By IOC type

---

### normalized-activity-events

**Description:** Validated, standardized activity logs ready for correlation

**Message Format:**
```json
{
  "event_id": "evt_abc123",
  "timestamp": "2026-01-09T12:30:00Z",
  "source": "proxy",
  "event_type": "http_request",
  "src_ip": "10.0.1.100",
  "dst_ip": "93.184.216.34",
  "domain": "suspicious.com",
  "url": "http://suspicious.com/malware.exe",
  "user": "john.doe@company.com",
  "normalized_at": "2026-01-09T12:35:00Z"
}
```

**Volume:** ~8M-45M events/day
**Retention:** 1 day
**Partitioning:** By source and hour

---

### normalized-threat-events

**Description:** Validated threat intelligence data ready for storage and enrichment

**Message Format:**
```json
{
  "threat_id": "threat_apt29_alienvault_123",
  "name": "APT29",
  "aliases": ["Cozy Bear", "The Dukes"],
  "threat_category": "actor",
  "threat_type": "c2",
  "description": "Advanced persistent threat group...",
  "first_seen": "2015-01-01T00:00:00Z",
  "last_seen": "2026-01-08T00:00:00Z",
  "techniques": [...],
  "tactics": ["Initial Access", "Execution"],
  "associated_ioc_ids": ["ioc_123", "ioc_456"],
  "sources": ["alienvault_otx"],
  "confidence": 0.85,
  "is_active": true
}
```

**Volume:** ~500-5K events/day
**Retention:** 7 days
**Partitioning:** By threat category

---

### Dead Letter Queue (DLQ) Topics

**Purpose:** Capture failed messages for debugging and replay

**Common Failure Reasons:**
- Validation errors (invalid IOC format, missing required fields)
- Data quality issues (malformed JSON, encoding errors)
- Business logic violations (duplicate IOCs, invalid threat types)
- Downstream service unavailability

**Message Format:**
```json
{
  "original_message": { ... },
  "error": {
    "type": "ValidationError",
    "message": "IOC value failed regex validation",
    "timestamp": "2026-01-09T12:35:00Z",
    "service": "normalization-service",
    "retry_count": 3
  },
  "metadata": {
    "original_topic": "raw-ioc-events",
    "original_message_id": "msg_123",
    "subscription": "normalization-ioc-sub"
  }
}
```

**Retention:** 14 days (for investigation)

---

## Subscription Configuration

### Collection Service
- **Publishes to:**
  - `raw-ioc-events`
  - `raw-activity-events`
  - `raw-threat-events`

### Normalization Service
- **Subscribes to:**
  - `raw-ioc-events` → `normalization-ioc-sub`
  - `raw-activity-events` → `normalization-activity-sub`
  - `raw-threat-events` → `normalization-threat-sub`

- **Publishes to:**
  - `normalized-ioc-events`
  - `normalized-activity-events`
  - `normalized-threat-events`
  - `dlq-ioc-events`
  - `dlq-activity-events`
  - `dlq-threat-events`

### Detection Service
- **Subscribes to:**
  - `normalized-ioc-events` → `detection-ioc-sub`
  - `normalized-activity-events` → `detection-activity-sub`

### Storage Service
- **Subscribes to:**
  - `normalized-ioc-events` → `storage-ioc-sub`
  - `normalized-activity-events` → `storage-activity-sub`
  - `normalized-threat-events` → `storage-threat-sub`

---

## Performance Configuration

### Message Attributes

All messages include standard attributes for routing and monitoring:

```json
{
  "attributes": {
    "source": "alienvault_otx",
    "event_type": "ioc",
    "priority": "normal",
    "schema_version": "1.0",
    "trace_id": "trace_abc123"
  }
}
```

### Subscription Settings

| Subscription | Ack Deadline | Max Messages | Max Workers |
|--------------|--------------|--------------|-------------|
| normalization-ioc-sub | 60s | 100 | 10 |
| normalization-activity-sub | 30s | 500 | 20 |
| normalization-threat-sub | 60s | 50 | 5 |
| detection-ioc-sub | 120s | 100 | 10 |
| detection-activity-sub | 120s | 1000 | 30 |
| storage-ioc-sub | 60s | 500 | 10 |
| storage-activity-sub | 30s | 1000 | 20 |
| storage-threat-sub | 60s | 100 | 5 |

### Batching Configuration

```python
# Collection Service (Publisher)
max_messages_per_batch = 1000
max_batch_size_bytes = 10_000_000  # 10 MB
timeout_seconds = 10.0

# Normalization Service (Subscriber)
max_messages_per_pull = 100  # IOCs
max_messages_per_pull = 500  # Activities (high volume)
max_messages_per_pull = 50   # Threats
```

---

## Monitoring & Alerting

### Key Metrics

**Publisher Metrics:**
- `pubsub_publish_latency_seconds` - Time to publish
- `pubsub_publish_errors_total` - Failed publishes
- `pubsub_messages_published_total` - Messages sent

**Subscriber Metrics:**
- `pubsub_pull_latency_seconds` - Time to pull messages
- `pubsub_processing_latency_seconds` - Time to process
- `pubsub_ack_latency_seconds` - Time to acknowledge
- `pubsub_messages_received_total` - Messages received
- `pubsub_messages_dlq_total` - Messages sent to DLQ

**Topic Metrics (from GCP Console):**
- Message backlog (unacknowledged messages)
- Oldest unacknowledged message age
- Publish throughput (messages/sec)
- Subscription throughput (messages/sec)

### Alerts

```yaml
# High backlog
- alert: PubSubHighBacklog
  expr: pubsub_subscription_num_undelivered_messages > 10000
  for: 5m
  severity: warning

# Old messages
- alert: PubSubOldestMessageAge
  expr: pubsub_subscription_oldest_unacked_message_age > 300
  for: 5m
  severity: warning

# High DLQ rate
- alert: PubSubHighDLQRate
  expr: rate(pubsub_messages_dlq_total[5m]) > 100
  for: 2m
  severity: critical
```

---

## Topic Creation

### Using gcloud CLI

```bash
# Create all raw event topics
gcloud pubsub topics create raw-ioc-events --project=ladon-production
gcloud pubsub topics create raw-activity-events --project=ladon-production
gcloud pubsub topics create raw-threat-events --project=ladon-production

# Create all normalized event topics
gcloud pubsub topics create normalized-ioc-events --project=ladon-production
gcloud pubsub topics create normalized-activity-events --project=ladon-production
gcloud pubsub topics create normalized-threat-events --project=ladon-production

# Create DLQ topics
gcloud pubsub topics create dlq-ioc-events --project=ladon-production
gcloud pubsub topics create dlq-activity-events --project=ladon-production
gcloud pubsub topics create dlq-threat-events --project=ladon-production
```

### Using Terraform

See `infra/terraform/modules/pubsub/` for complete infrastructure-as-code.

---

## Best Practices

### 1. Message Size
- Keep messages < 1 MB (Pub/Sub limit: 10 MB)
- Use Cloud Storage for large payloads (>100 KB)
- Reference data by ID, not full payload

### 2. Idempotency
- All message processors must be idempotent
- Use `message_id` or `event_id` for deduplication
- Store processed message IDs (Redis/Firestore)

### 3. Ordering
- Pub/Sub does not guarantee order
- Use ordering keys if order matters (rare)
- Design for out-of-order processing

### 4. Error Handling
- Retry transient errors (network, timeouts)
- Send to DLQ after max retries
- Log all errors with trace_id

### 5. Schema Evolution
- Include `schema_version` in attributes
- Support multiple schema versions
- Use Pub/Sub Schema for validation (optional)

---

## Troubleshooting

### High Backlog

**Symptom:** Messages accumulating in subscription

**Causes:**
- Subscriber down or slow
- Processing errors
- Insufficient workers

**Fix:**
```bash
# Check subscription backlog
gcloud pubsub subscriptions describe normalization-ioc-sub

# Scale up workers
kubectl scale deployment normalization-service --replicas=5

# Purge old messages (if safe)
gcloud pubsub subscriptions seek normalization-ioc-sub --time=2026-01-09T12:00:00Z
```

### Messages Going to DLQ

**Symptom:** High rate of DLQ messages

**Causes:**
- Data quality issues
- Schema changes
- Validation bugs

**Fix:**
```bash
# Pull DLQ messages for inspection
gcloud pubsub subscriptions pull dlq-ioc-events-sub --limit=10

# Fix root cause
# Replay messages from DLQ
python scripts/replay_dlq.py --topic=dlq-ioc-events --target=raw-ioc-events
```

### Slow Processing

**Symptom:** High processing latency

**Causes:**
- Heavy normalization logic
- External API calls
- Database writes

**Fix:**
- Batch database writes
- Cache external API calls
- Profile code for bottlenecks
- Increase workers

---

## Configuration Files

All Pub/Sub topic configurations are defined in:

- Collection Service: `services/collection/src/config.py`
- Normalization Service: `services/normalization/src/config.py`
- Environment variables: `.env` files
- Infrastructure: `infra/terraform/modules/pubsub/`

For examples, see:
- `services/collection/config/config.example.yaml`
- `services/collection/.env.example`
