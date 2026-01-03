# Collection Service

The Collection Service is responsible for ingesting Indicators of Compromise (IOCs) from threat intelligence feeds and activity logs from various data sources. It implements watermark-based incremental collection to efficiently process high-volume data streams.

## Features

- **Multi-Source Collection**: Supports IOC feeds (AlienVault OTX, abuse.ch, MISP) and activity logs (Trino, BigQuery)
- **Watermark Management**: Incremental collection using persistent watermarks
- **Pub/Sub Publishing**: Publishes raw events to Google Cloud Pub/Sub for downstream processing
- **Automatic Retry**: Built-in retry logic with exponential backoff
- **Health Monitoring**: REST API endpoints for health checks and status monitoring
- **Concurrent Collection**: Runs multiple collectors in parallel on configurable schedules

## Architecture

```
┌─────────────────┐
│  IOC Feeds      │
│  - AlienVault   │
│  - abuse.ch     │
│  - MISP         │
└────────┬────────┘
         │
         v
┌─────────────────┐     ┌──────────────┐
│  Collection     │────>│ Watermark    │
│  Service        │<────│ Manager      │
└────────┬────────┘     └──────────────┘
         │
         v
┌─────────────────┐
│  Pub/Sub        │
│  - raw-ioc-     │
│    events       │
│  - raw-activity-│
│    events       │
└─────────────────┘
```

## Data Sources

### IOC Feeds

- **AlienVault OTX**: Threat intelligence pulses with malware, C2, and phishing indicators
- **abuse.ch**: ThreatFox, URLhaus, and MalwareBazaar feeds
- **MISP**: Open-source threat intelligence platform with customizable filters

### Activity Logs

- **Trino**: SQL query engine for accessing proxy, DNS, and network logs
- **BigQuery**: Google Cloud data warehouse for high-volume activity logs

## Configuration

Configuration is loaded from environment variables:

```bash
# Environment
ENVIRONMENT=development|staging|production
LOG_LEVEL=DEBUG|INFO|WARNING|ERROR

# Pub/Sub
PUBSUB_PROJECT_ID=your-gcp-project
PUBSUB_RAW_IOC_EVENTS_TOPIC=raw-ioc-events
PUBSUB_RAW_ACTIVITY_EVENTS_TOPIC=raw-activity-events

# Storage Service (for watermarks)
STORAGE_SERVICE_URL=http://storage-service:8000
```

Data source configurations are typically loaded from a YAML or JSON file:

```yaml
data_sources:
  - id: alienvault_otx
    name: AlienVault OTX
    source_type: ioc_feed
    collector_type: alienvault_otx
    enabled: true
    collection_interval_minutes: 30
    api_key: ${ALIENVAULT_API_KEY}
    pubsub_topic: raw-ioc-events

  - id: mde_logs
    name: Microsoft Defender for Endpoint Logs
    source_type: activity_log
    collector_type: trino
    enabled: true
    collection_interval_minutes: 3
    host: trino.example.com
    catalog: hive
    schema: security_logs
    table: mde_events
    pubsub_topic: raw-activity-events
```

## API Endpoints

### Health Check
```bash
GET /health
```

Returns health status of all collectors.

**Response:**
```json
{
  "status": "healthy",
  "collectors": {
    "alienvault_otx": true,
    "mde_logs": true
  }
}
```

### Service Status
```bash
GET /status
```

Returns detailed status including watermarks and collection metrics.

**Response:**
```json
{
  "service": "collection",
  "total_collectors": 2,
  "running_tasks": 2,
  "collectors": {
    "alienvault_otx": {
      "name": "AlienVault OTX",
      "collector_type": "alienvault_otx",
      "source_type": "ioc_feed",
      "enabled": true,
      "interval_minutes": 30,
      "watermark": {
        "last_successful_timestamp": "2024-01-01T12:00:00Z",
        "status": "success",
        "records_collected": 150
      },
      "is_running": true
    }
  }
}
```

### Trigger Collection
```bash
POST /collect/{source_id}
```

Triggers a one-time collection for a specific source.

**Response:**
```json
{
  "source_id": "alienvault_otx",
  "events_collected": 150,
  "events_failed": 0,
  "batches_processed": 2,
  "duration_seconds": 8.5
}
```

### Trigger All Collections
```bash
POST /collect
```

Triggers one-time collection for all enabled sources.

## Development

### Installation

```bash
cd services/collection
pip install -r requirements.txt
```

### Running Locally

```bash
cd services/collection
python -m src.main
```

The service will start on `http://localhost:8000`.

### Running Tests

```bash
pytest tests/ -v --cov=src
```

### Running with Docker

```bash
docker build -t collection-service .
docker run -p 8000:8000 collection-service
```

## Deployment

The Collection Service is deployed as a Cloud Run service:

```bash
# Build and push image
gcloud builds submit --tag gcr.io/PROJECT_ID/collection-service

# Deploy to Cloud Run
gcloud run deploy collection-service \
  --image gcr.io/PROJECT_ID/collection-service \
  --region us-central1 \
  --set-env-vars ENVIRONMENT=production
```

## Collectors

### Base Collector

All collectors inherit from `BaseCollector` which provides:

- Watermark-based incremental collection
- Automatic retry with exponential backoff
- Batch publishing to Pub/Sub
- Collection metrics tracking

### Implementing a New Collector

```python
from collectors.base import BaseCollector

class MyCollector(BaseCollector):
    async def validate_connection(self) -> bool:
        # Test connection to data source
        pass

    async def collect(self) -> Dict[str, Any]:
        # 1. Get watermark
        watermark = await self.watermark_manager.get_watermark(self.config.id)

        # 2. Fetch data since watermark
        events = await self._fetch_events(watermark)

        # 3. Publish to Pub/Sub
        for batch in self._batch_events(events, self.config.batch_size):
            await self._publish_batch(batch, self.config.pubsub_topic)

        # 4. Update watermark
        await self.watermark_manager.update_watermark(
            source_id=self.config.id,
            timestamp=latest_timestamp,
            status="success",
            records_collected=len(events)
        )

        return self.metrics.to_dict()
```

## Watermark Management

Watermarks track the last successfully collected timestamp for each data source:

```python
{
  "source_id": "alienvault_otx",
  "last_successful_timestamp": "2024-01-01T12:00:00Z",
  "last_run_timestamp": "2024-01-01T12:05:00Z",
  "status": "success",
  "records_collected": 150,
  "error_message": null
}
```

Watermarks are stored in Firestore via the Storage Service and cached in memory.

## Performance Considerations

- **Batch Size**: Configure appropriate batch sizes based on event volume (default: 10,000 for IOCs, 100,000 for activity logs)
- **Collection Intervals**: IOC feeds typically update every 15-30 minutes; activity logs every 1-5 minutes
- **Concurrent Requests**: Limit parallel requests to external APIs to avoid rate limiting
- **BigQuery Costs**: Always use partition filters to minimize data scanned

## Monitoring

Key metrics to monitor:

- `collection_events_per_second`: Throughput
- `collection_errors_total`: Error rate
- `collection_latency_seconds`: Collection duration
- `watermark_lag_seconds`: Time since last successful collection

## Troubleshooting

### Collector keeps failing

Check the watermark status and error message:
```bash
curl http://localhost:8000/status | jq '.collectors.SOURCE_ID'
```

### No events being collected

1. Verify data source connectivity: `GET /health`
2. Check watermark - may be up to date
3. Review logs for API errors or rate limiting

### High latency

- Reduce batch size
- Increase collection interval
- Check network latency to data sources

## License

Copyright (c) 2024 LADON Team
