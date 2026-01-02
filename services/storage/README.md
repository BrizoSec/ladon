## Storage Service

Unified storage layer for the LADON Threat XDR platform. Provides a single interface to BigQuery (analytics), Redis (caching), and Firestore (metadata) following the Lambda architecture pattern.

### Architecture

```
┌─────────────────────────────────────────────┐
│          Storage Service (Facade)           │
├─────────────────────────────────────────────┤
│  Fast Path (Redis)    │   Slow Path (BQ)    │
│  - Hot IOC Cache      │   - IOCs           │
│  - <5ms lookups       │   - Activities     │
│  - 24hr TTL           │   - Detections     │
│                       │   - Analytics      │
├───────────────────────┴─────────────────────┤
│          Metadata (Firestore)               │
│          - Watermarks                       │
│          - Configuration                    │
└─────────────────────────────────────────────┘
```

### Features

- ✅ **Unified API** - Single interface for all storage operations
- ✅ **Lambda Architecture** - Fast path (Redis) + Slow path (BigQuery)
- ✅ **Automatic Caching** - Hot IOCs cached automatically based on confidence & recency
- ✅ **Batch Operations** - Efficient bulk insert for high-volume data
- ✅ **Watermark Management** - Track incremental collection state
- ✅ **Health Checks** - Monitor all backend connections
- ✅ **Retry Logic** - Built-in resilience for transient failures

### Installation

```bash
cd services/storage
pip install -e .
```

### Quick Start

```python
import asyncio
from datetime import datetime
from ladon_models import NormalizedIOC, IOCType, ThreatType, IOCSource
from storage_service import StorageService, StorageConfig

async def main():
    # Initialize service
    config = StorageConfig.from_env()
    storage = StorageService(config)
    await storage.initialize()

    # Store an IOC (automatically cached if hot)
    ioc = NormalizedIOC(
        ioc_value="evil.com",
        ioc_type=IOCType.DOMAIN,
        threat_type=ThreatType.C2,
        confidence=0.95,
        source=IOCSource.ALIENVAULT_OTX,
        first_seen=datetime.utcnow(),
        last_seen=datetime.utcnow()
    )

    await storage.store_ioc(ioc, cache=True)

    # Fast lookup (checks cache first)
    cached_ioc = await storage.get_ioc("evil.com", "domain")
    print(f"Found IOC: {cached_ioc.ioc_value} (confidence: {cached_ioc.confidence})")

    # Clean up
    await storage.cleanup()

asyncio.run(main())
```

### Configuration

Set environment variables:

```bash
# BigQuery
export BIGQUERY_PROJECT_ID="your-project"
export BIGQUERY_DATASET="threat_xdr"

# Redis
export REDIS_HOST="localhost"
export REDIS_PORT="6379"
export REDIS_PASSWORD="your-password"  # Optional

# Firestore
export FIRESTORE_PROJECT_ID="your-project"
```

Or use configuration objects:

```python
from storage_service import StorageConfig, BigQueryConfig, RedisConfig

config = StorageConfig(
    bigquery=BigQueryConfig(
        project_id="my-project",
        dataset="threat_xdr"
    ),
    redis=RedisConfig(
        host="redis.example.com",
        port=6379
    ),
    firestore=FirestoreConfig(
        project_id="my-project"
    )
)

storage = StorageService(config)
```

### Usage Examples

#### IOC Operations

```python
# Store single IOC
await storage.store_ioc(ioc, cache=True)

# Batch store IOCs (auto-caches hot ones)
iocs = [ioc1, ioc2, ioc3]
result = await storage.store_iocs_batch(iocs)
print(f"Stored {result['success']}/{len(iocs)} IOCs")

# Get IOC (cache-first)
ioc = await storage.get_ioc("evil.com", "domain", use_cache=True)

# Search IOCs
iocs = await storage.search_iocs(
    threat_type="c2",
    min_confidence=0.8,
    limit=100
)

# Invalidate cached IOC
await storage.invalidate_ioc_cache("evil.com", "domain")
```

#### Activity Logging

```python
from ladon_models import NormalizedActivity, ActivitySource, ActivityEventType

activity = NormalizedActivity(
    event_id="evt_123",
    timestamp=datetime.utcnow(),
    source=ActivitySource.DNS,
    event_type=ActivityEventType.DNS_QUERY,
    domain="evil.com"
)

# Store single activity
await storage.store_activity(activity)

# Batch store activities
activities = [activity1, activity2, activity3]
result = await storage.store_activities_batch(activities)

# Search activities
activities = await storage.search_activities(
    source="dns",
    start_time=datetime.utcnow() - timedelta(hours=1),
    limit=1000
)
```

#### Detection Management

```python
from ladon_models import Detection, Severity

detection = Detection(
    detection_id="det_123",
    timestamp=datetime.utcnow(),
    ioc_value="evil.com",
    ioc_type="domain",
    activity_event_id="evt_123",
    activity_source=ActivitySource.DNS,
    severity=Severity.HIGH,
    confidence=0.95,
    first_seen=datetime.utcnow(),
    last_seen=datetime.utcnow()
)

# Store detection
await storage.store_detection(detection)

# Search high-severity detections
detections = await storage.search_detections(
    severity="HIGH",
    status="New",
    limit=50
)

# Update detection status
await storage.update_detection_status(
    detection_id="det_123",
    status="Investigating",
    case_id="INC0012345"  # ServiceNow case
)
```

#### Watermark Management

```python
# Get last collection watermark
watermark = await storage.get_watermark("mde_logs")
if watermark:
    last_timestamp = watermark["last_successful_timestamp"]
    print(f"Last collection: {last_timestamp}")

# Update watermark after successful collection
await storage.update_watermark(
    source_id="mde_logs",
    timestamp=datetime.utcnow(),
    status="success"
)

# Record failed collection
await storage.update_watermark(
    source_id="mde_logs",
    timestamp=datetime.utcnow(),
    status="failed",
    error_message="Connection timeout"
)
```

#### Configuration Management

```python
# Store configuration
await storage.set_config("notification_rules", {
    "critical": {"slack": True, "email": True},
    "high": {"slack": False, "email": True},
    "medium": {"email": False}
})

# Retrieve configuration
config = await storage.get_config("notification_rules")
```

#### Cache Operations

```python
# Get cache statistics
stats = await storage.get_cache_stats()
print(f"Cache hit rate: {stats['hit_rate']}%")
print(f"Total IOCs cached: {stats['ioc_keys']}")

# Warm cache with hot IOCs
cached_count = await storage.warm_ioc_cache(
    min_confidence=0.7,
    hours=48
)
print(f"Warmed cache with {cached_count} IOCs")
```

#### Health Checks

```python
# Check all backends
health = await storage.health_check()
print(f"BigQuery: {health['bigquery']}")
print(f"Redis: {health['redis']}")
print(f"Firestore: {health['firestore']}")
```

### Caching Strategy

IOCs are automatically cached when they meet these criteria:

- **Recency**: `last_seen` within 48 hours (configurable)
- **Confidence**: `confidence` >= 0.7 (configurable)

Cache configuration:

```python
config = StorageConfig(
    redis=RedisConfig(
        ioc_cache_ttl=86400,  # 24 hours
        hot_ioc_threshold_hours=48,
        hot_ioc_min_confidence=0.7
    )
)
```

### Performance

#### Batch Operations

Always use batch operations for bulk data:

```python
# ❌ Bad: Individual inserts
for ioc in iocs:
    await storage.store_ioc(ioc)

# ✅ Good: Batch insert
await storage.store_iocs_batch(iocs)
```

#### Cache Usage

For detection workloads, always use cache-first lookups:

```python
# Fast path - check cache first
ioc = await storage.get_ioc("evil.com", "domain", use_cache=True)
```

### Testing

Run tests with mocked backends:

```bash
cd services/storage
pytest tests/ -v
```

### Monitoring

Key metrics to monitor:

- **Redis**:
  - Cache hit rate (target: >95%)
  - IOC key count
  - Memory usage

- **BigQuery**:
  - Query costs
  - Slot usage
  - Streaming insert errors

- **Firestore**:
  - Read/write operations
  - Latency

### Error Handling

The service includes built-in error handling and logging:

```python
try:
    await storage.store_ioc(ioc)
except Exception as e:
    logger.error(f"Failed to store IOC: {e}")
    # Service logs detailed errors automatically
```

### Development

File structure:

```
services/storage/
├── src/
│   ├── __init__.py
│   ├── config.py                    # Configuration models
│   ├── storage_service.py           # Main facade
│   └── repositories/
│       ├── base.py                  # Abstract interfaces
│       ├── bigquery_repository.py   # BigQuery implementation
│       ├── redis_repository.py      # Redis implementation
│       └── firestore_repository.py  # Firestore implementation
├── tests/
│   ├── test_bigquery_repository.py
│   ├── test_redis_repository.py
│   ├── test_firestore_repository.py
│   └── test_storage_service.py
├── README.md
└── requirements.txt
```

### Dependencies

- `google-cloud-bigquery` - BigQuery client
- `google-cloud-firestore` - Firestore client
- `redis[asyncio]` - Redis client with async support
- `pydantic-settings` - Configuration management
- `ladon-models` - Shared data models

### License

Internal use only - LADON Threat XDR Platform
