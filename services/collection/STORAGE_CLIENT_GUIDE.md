# Storage Client Integration Guide

## Overview

The Collection Service now integrates with the Storage Service to persist watermarks (the last successfully collected timestamp for each data source). This enables incremental collection and prevents duplicate data ingestion.

## What Was Implemented

### 1. Storage Service HTTP Client (`src/clients/storage_client.py`)

Two implementations:

**StorageServiceClient** (Production):
- HTTP client for connecting to Storage Service REST API
- Methods:
  - `get_watermark(source_id)` - Retrieve watermark for a data source
  - `update_watermark(source_id, timestamp, status, error_message)` - Update watermark after collection
  - `health_check()` - Verify Storage Service is healthy

**MockStorageClient** (Development/Testing):
- In-memory implementation for testing
- Same interface as production client
- No external dependencies

### 2. Integration in main.py

The storage client is now automatically initialized on startup:

```python
# If STORAGE_SERVICE_URL is set
storage_client = StorageServiceClient(
    base_url=config.storage_service_url,
    timeout=30
)

# If STORAGE_SERVICE_URL is not set (development)
storage_client = MockStorageClient()
```

## How to Use

### Setting Up

**Option 1: With Storage Service (Production)**

Set the environment variable:
```bash
export STORAGE_SERVICE_URL=http://storage-service:8000
```

Or in Docker Compose:
```yaml
services:
  collection:
    environment:
      - STORAGE_SERVICE_URL=http://storage:8000

  storage:
    # Storage Service container
```

**Option 2: Without Storage Service (Development)**

Simply don't set `STORAGE_SERVICE_URL`:
```bash
# No STORAGE_SERVICE_URL set
python -m src.main
```

The service will use `MockStorageClient` and log:
```
No storage service URL provided - using mock storage client
```

### How Watermarks Work

#### 1. First Collection (No Watermark)

```python
# Collector checks for watermark
watermark = await watermark_manager.get_watermark("alienvault_otx")
# Returns: None

# Collector uses default lookback (e.g., 7 days)
start_time = datetime.utcnow() - timedelta(days=7)

# Collect data from start_time to now
events = await collector.fetch_events(start_time)

# Update watermark after successful collection
await watermark_manager.update_watermark(
    source_id="alienvault_otx",
    timestamp=latest_event_timestamp,
    status="success",
    records_collected=len(events)
)
```

#### 2. Subsequent Collections (With Watermark)

```python
# Collector checks for watermark
watermark = await watermark_manager.get_watermark("alienvault_otx")
# Returns: {
#   "source_id": "alienvault_otx",
#   "last_successful_timestamp": "2024-01-01T12:00:00Z",
#   "status": "success"
# }

# Collector uses watermark as starting point
start_time = watermark["last_successful_timestamp"]

# Collect only NEW data since last run
events = await collector.fetch_events(start_time)

# Update watermark with latest timestamp
await watermark_manager.update_watermark(
    source_id="alienvault_otx",
    timestamp=latest_event_timestamp,
    status="success",
    records_collected=len(events)
)
```

## Storage Service API Endpoints

The storage client calls these endpoints:

### Get Watermark
```bash
GET /api/v1/watermarks/{source_id}

Response 200:
{
  "source_id": "alienvault_otx",
  "last_successful_timestamp": "2024-01-01T12:00:00Z",
  "last_run_timestamp": "2024-01-01T12:05:00Z",
  "status": "success",
  "records_collected": 150
}

Response 404:
Watermark not found (first collection)
```

### Update Watermark
```bash
PUT /api/v1/watermarks/{source_id}

Request:
{
  "timestamp": "2024-01-01T12:30:00Z",
  "status": "success",
  "error_message": null
}

Response 200/201:
{
  "source_id": "alienvault_otx",
  "last_successful_timestamp": "2024-01-01T12:30:00Z",
  "status": "success"
}
```

### Health Check
```bash
GET /health

Response 200:
{
  "status": "healthy"
}
```

## Deployment Configurations

### Local Development
```bash
# Terminal 1: Start Storage Service
cd services/storage
python -m src.main

# Terminal 2: Start Collection Service
cd services/collection
export STORAGE_SERVICE_URL=http://localhost:8000
python -m src.main
```

### Docker Compose
```yaml
version: '3.8'

services:
  storage:
    build: ./services/storage
    ports:
      - "8000:8000"
    environment:
      - ENVIRONMENT=development

  collection:
    build: ./services/collection
    ports:
      - "8001:8000"
    environment:
      - STORAGE_SERVICE_URL=http://storage:8000
      - ENVIRONMENT=development
    depends_on:
      - storage
```

### Kubernetes
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: collection-config
data:
  STORAGE_SERVICE_URL: "http://storage-service.default.svc.cluster.local:8000"

---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: collection-service
spec:
  template:
    spec:
      containers:
      - name: collection
        image: gcr.io/project/collection-service
        envFrom:
        - configMapRef:
            name: collection-config
```

## Troubleshooting

### Issue: "Storage Service health check failed"

**Symptoms:**
```
WARNING: Storage Service health check failed - watermarks will not persist
```

**Causes:**
1. Storage Service is not running
2. Wrong URL in `STORAGE_SERVICE_URL`
3. Network connectivity issues

**Solutions:**
```bash
# Check if Storage Service is running
curl http://storage-service:8000/health

# Verify environment variable
echo $STORAGE_SERVICE_URL

# Test connectivity
nc -zv storage-service 8000
```

### Issue: Watermarks not persisting between restarts

**Symptoms:**
- Collectors restart from default lookback period each time
- Duplicate data collection

**Causes:**
1. Using `MockStorageClient` (no `STORAGE_SERVICE_URL` set)
2. Storage Service database not persisted (Redis/Firestore not configured)

**Solutions:**
```bash
# Set storage service URL
export STORAGE_SERVICE_URL=http://storage-service:8000

# Verify Storage Service has persistent storage configured
# Check Storage Service logs for Redis/Firestore connection
```

### Issue: High latency in collection

**Symptoms:**
- Slow collection runs
- Timeout errors

**Causes:**
- Storage Service slow to respond
- Network latency

**Solutions:**
```bash
# Increase timeout
storage_client = StorageServiceClient(
    base_url=config.storage_service_url,
    timeout=60  # Increase from 30 to 60 seconds
)

# Check Storage Service performance
curl http://storage-service:8000/status
```

## Testing

### Unit Tests

Test with MockStorageClient:
```python
@pytest.mark.asyncio
async def test_collection_with_mock_storage():
    storage_client = MockStorageClient()
    watermark_manager = WatermarkManager(storage_client)

    # First run - no watermark
    watermark = await watermark_manager.get_watermark("test_source")
    assert watermark is None

    # Update watermark
    await watermark_manager.update_watermark(
        source_id="test_source",
        timestamp=datetime.utcnow(),
        status="success"
    )

    # Second run - watermark exists
    watermark = await watermark_manager.get_watermark("test_source")
    assert watermark is not None
    assert watermark["status"] == "success"
```

### Integration Tests

Test with real Storage Service:
```python
@pytest.mark.integration
@pytest.mark.asyncio
async def test_collection_with_storage_service():
    storage_client = StorageServiceClient(
        base_url="http://localhost:8000"
    )

    # Verify connection
    is_healthy = await storage_client.health_check()
    assert is_healthy is True

    # Test watermark flow
    watermark = await storage_client.get_watermark("test_source")
    # ... test collection logic
```

## Monitoring

Key metrics to monitor:

1. **Watermark Age**: Time since last successful collection
```python
watermark = await storage_client.get_watermark("alienvault_otx")
if watermark:
    age = datetime.utcnow() - watermark["last_successful_timestamp"]
    if age > timedelta(hours=2):
        logger.warning(f"Watermark is {age} old - collection may be stuck")
```

2. **Storage Client Errors**: Failed requests to Storage Service
3. **Collection Failures**: Sources with status="failed" in watermarks

## Best Practices

1. **Always set STORAGE_SERVICE_URL in production** - Don't rely on MockStorageClient
2. **Monitor watermark age** - Alert if watermarks haven't updated in expected interval
3. **Handle Storage Service outages gracefully** - Collection Service continues to work even if Storage Service is down (watermarks won't persist but collection continues)
4. **Use health checks** - Verify Storage Service is healthy on startup
5. **Set appropriate timeouts** - Balance between responsiveness and handling slow requests

## Summary

✅ **Storage Client Created**: HTTP client for Storage Service communication
✅ **Auto-Initialization**: Automatically connects on startup
✅ **Graceful Degradation**: Falls back to MockStorageClient if Storage Service unavailable
✅ **Production Ready**: Includes health checks, error handling, and cleanup
✅ **Testing Support**: MockStorageClient for unit tests

The Collection Service is now fully integrated with the Storage Service! 🎉
