# Collection Service Configuration Guide

This guide explains how to configure the LADON Collection Service to collect IOCs from threat intelligence feeds and activity logs from your organizational data sources.

## Table of Contents

1. [Quick Start](#quick-start)
2. [Configuration Methods](#configuration-methods)
3. [IOC Feed Configuration](#ioc-feed-configuration)
4. [Activity Log Configuration](#activity-log-configuration)
5. [Performance Tuning](#performance-tuning)
6. [Troubleshooting](#troubleshooting)

---

## Quick Start

### Option 1: Using YAML Configuration (Recommended)

```bash
# 1. Copy the example configuration
cp config.example.yaml config.yaml

# 2. Edit with your credentials
vim config.yaml

# 3. Set environment variable
export COLLECTION_CONFIG_FILE=/path/to/config.yaml

# 4. Start the service
python -m src.main
```

### Option 2: Using Environment Variables

```bash
# 1. Copy the example .env file
cp ../.env.example ../.env

# 2. Edit with your credentials
vim ../.env

# 3. Load environment variables
source ../.env

# 4. Start the service
python -m src.main
```

### Option 3: Docker Compose

```bash
# 1. Edit docker-compose.yml with your config
vim docker-compose.yml

# 2. Start services
docker-compose up -d
```

---

## Configuration Methods

The Collection Service supports three configuration methods (in order of precedence):

### 1. Environment Variables (Highest Priority)
- Override any configuration value
- Best for: Secrets, dynamic configurations, CI/CD
- Example: `ALIENVAULT_API_KEY=abc123`

### 2. YAML Configuration File
- Comprehensive configuration with comments
- Best for: Complex setups, multiple sources
- Load via: `COLLECTION_CONFIG_FILE=config.yaml`

### 3. Python Code (Default Values)
- Fallback defaults in `src/config.py`
- Best for: Development, minimal setups

**Priority Example:**
```yaml
# config.yaml
alienvault_api_key: default_key

# .env
ALIENVAULT_API_KEY=override_key  # <-- This wins!
```

---

## IOC Feed Configuration

### AlienVault OTX

**What:** Open threat intelligence exchange with 100,000+ contributors
**Free Tier:** 10,000 pulses/day
**Best For:** Broad threat visibility, community intelligence

```yaml
ioc_feeds:
  - id: alienvault_otx
    collector_type: alienvault_otx
    enabled: true
    collection_interval_minutes: 30
    api_key: YOUR_API_KEY  # Get from: https://otx.alienvault.com/api
    pulses_limit: 100
    pubsub_topic: raw-ioc-events
```

**Environment Variable Alternative:**
```bash
ALIENVAULT_API_KEY=your_key_here
ALIENVAULT_COLLECTION_INTERVAL_MINUTES=30
```

**Rate Limits:**
- Free: 10,000 pulses/day (~7 pulses/minute)
- Recommended interval: 30 minutes
- Each pulse contains 10-100 IOCs

**Configuration Tips:**
- Use `query_config.modified_since_days` to limit historical data
- Filter by `types` to collect only specific IOC types
- Set `subscribed_only: true` to collect only your subscribed pulses

### abuse.ch

**What:** High-quality malware IOCs (ThreatFox, URLhaus, MalwareBazaar)
**Free Tier:** Unlimited (rate-limited)
**Best For:** Malware-focused detection, high-confidence IOCs

```yaml
ioc_feeds:
  - id: abuse_ch
    collector_type: abuse_ch
    enabled: true
    collection_interval_minutes: 15  # High update frequency
    threatfox_url: https://threatfox-api.abuse.ch/api/v1/
    urlhaus_url: https://urlhaus-api.abuse.ch/v1/
    api_key: null  # Optional - increases rate limits
    pubsub_topic: raw-ioc-events
    query_config:
      threatfox_days: 3
      confidence_threshold: 50
```

**Rate Limits:**
- Anonymous: 100 requests/hour
- With API key: 500 requests/hour
- Recommended interval: 15 minutes

**Configuration Tips:**
- Set low interval (15 min) for near real-time malware IOCs
- Use `confidence_threshold` to filter low-quality indicators
- abuse.ch IOCs are generally high-confidence (90%+)

### MISP

**What:** Enterprise threat intelligence platform (self-hosted)
**Free Tier:** N/A (self-hosted)
**Best For:** Private threat sharing, internal intelligence

```yaml
ioc_feeds:
  - id: misp_enterprise
    collector_type: misp
    enabled: true
    collection_interval_minutes: 30
    url: https://misp.your-company.com
    api_key: YOUR_MISP_API_KEY
    verify_ssl: true
    published: true  # Only published events
    to_ids: true     # Only IOCs marked for detection
    tags:            # Filter by TLP/type
      - tlp:white
      - tlp:green
    pubsub_topic: raw-ioc-events
```

**Configuration Tips:**
- Use `published: true` to avoid unpublished/draft events
- Use `to_ids: true` to get only detection-ready IOCs
- Filter by `tags` for TLP restrictions
- MISP queries can be slow - increase `timeout_seconds`

---

## Activity Log Configuration

### Trino (Proxy Logs)

**What:** SQL query engine for your data lake (Zscaler, Cisco Umbrella, etc.)
**Volume:** Millions of events/day
**Best For:** HTTP/HTTPS traffic analysis

```yaml
activity_logs:
  - id: trino_proxy
    collector_type: trino
    enabled: true
    collection_interval_minutes: 3  # Near real-time
    host: trino.your-company.com
    port: 8080
    catalog: security_logs
    schema: proxy
    table: http_requests
    timestamp_column: request_timestamp
    batch_size: 100000  # Large batches for high volume
    pubsub_topic: raw-activity-events
```

**Performance Tips:**
- Use large `batch_size` (100K-500K) for high-volume logs
- Set `collection_interval_minutes: 3` for near real-time
- Add `where_clause` to filter irrelevant traffic
- Ensure `timestamp_column` is indexed for fast queries

**Common Issues:**
- **Slow queries:** Increase `timeout_seconds`, add WHERE filters
- **Memory errors:** Reduce `batch_size`
- **Duplicate events:** Check watermark persistence (Storage Service)

### Trino (DNS Logs)

**Volume:** Very high (millions/day)
**Best For:** DNS threat detection, DGA detection

```yaml
activity_logs:
  - id: trino_dns
    collector_type: trino
    enabled: true
    collection_interval_minutes: 3
    table: dns_queries
    timestamp_column: query_timestamp
    batch_size: 150000  # Even larger for DNS
    query_config:
      where_clause: "response_code = 'NOERROR'"  # Only successful queries
```

**Performance Tips:**
- DNS logs have highest volume - use largest `batch_size`
- Filter failed queries with `where_clause`
- Consider aggregating queries (1 event per unique domain/hour)

### BigQuery (Sinkhole Logs)

**What:** Known malicious traffic (DNS sinkhole, honeypots)
**Volume:** Low (thousands/day)
**Best For:** High-confidence threat detection

```yaml
activity_logs:
  - id: bigquery_sinkhole
    collector_type: bigquery
    enabled: true
    collection_interval_minutes: 3
    project_id: your-gcp-project
    dataset: security_logs
    table: sinkhole_queries
    partition_field: timestamp  # Cost optimization
    batch_size: 10000
    pubsub_topic: raw-activity-events
    query_config:
      partition_filter_days: 1  # Only query recent partitions
```

**Cost Optimization:**
- **Always** use `partition_field` for partitioned tables
- Use `partition_filter_days: 1` to scan less data
- Monitor BigQuery costs in GCP Console
- Expected cost: ~$0.01-$0.10 per collection run

### BigQuery (MDE/CrowdStrike)

**What:** Endpoint detection and response (EDR) alerts
**Volume:** Medium (thousands/day)
**Best For:** Endpoint threat detection

```yaml
activity_logs:
  - id: bigquery_mde
    collector_type: bigquery
    enabled: true
    collection_interval_minutes: 5
    project_id: your-gcp-project
    dataset: endpoint_security
    table: mde_alerts
    partition_field: alert_time
    query_config:
      where_clause: "severity IN ('High', 'Medium')"  # Filter low-severity
```

---

## Performance Tuning

### Batch Sizing Guide

| Data Source | Events/Day | Recommended Batch Size | Interval |
|-------------|------------|------------------------|----------|
| Proxy Logs | 10M+ | 100,000 - 500,000 | 3 min |
| DNS Logs | 50M+ | 150,000 - 1,000,000 | 3 min |
| Sinkhole | 10K | 5,000 - 10,000 | 3 min |
| MDE/CrowdStrike | 50K | 5,000 - 10,000 | 5 min |
| AlienVault OTX | 1K | 1,000 | 30 min |
| abuse.ch | 5K | 5,000 | 15 min |

### Memory Estimation

```
Memory per event = ~1 KB (JSON)
Batch of 100K events = ~100 MB

Recommended settings:
- max_memory_mb: 4096 (4 GB)
- max_events_in_memory: 100000
- batch_size: 100000 for high volume, 10000 for low volume
```

### Collection Intervals

**Real-time (<5 min):** Proxy, DNS, Sinkhole, EDR
- Interval: 3-5 minutes
- Tradeoff: Lower latency, higher load

**Near real-time (15-30 min):** IOC feeds
- Interval: 15-30 minutes
- Tradeoff: Balanced

**Periodic (1+ hour):** Historical analysis, manual triggers
- Interval: 60+ minutes
- Tradeoff: Lower load, higher latency

### Watermark Strategy

**How it works:**
1. Service queries: `SELECT * FROM table WHERE timestamp > last_watermark`
2. Collects events in batches
3. Updates watermark after successful publish
4. Persists to Storage Service

**Configuration:**
```yaml
performance:
  watermark_update_interval_seconds: 30  # How often to save
  watermark_persist_on_shutdown: true    # Save on graceful shutdown
```

**Failure Recovery:**
- If collection fails: Watermark not updated (retry same data)
- If service crashes: Loads last watermark from Storage Service
- If Storage Service down: Uses in-memory watermarks (lost on restart)

---

## Troubleshooting

### Common Issues

#### 1. "Collector not found" Error

```
KeyError: Collector 'alienvault_otx' not found
```

**Fix:**
- Check `enabled: true` in config
- Verify collector ID matches exactly
- Check logs for initialization errors

#### 2. API Rate Limit Errors

```
ERROR: AlienVault API rate limit exceeded (429)
```

**Fix:**
- Increase `collection_interval_minutes`
- Reduce `pulses_limit` or `batch_size`
- Check if you have API key set (increases limits)

#### 3. Watermark Not Persisting

```
WARNING: Storage Service health check failed - watermarks will not persist
```

**Fix:**
- Check `COLLECTION_STORAGE_SERVICE_URL` is set
- Verify Storage Service is running: `curl http://storage-service:8080/health`
- Use mock storage in development: `USE_MOCK_STORAGE=true`

#### 4. High Memory Usage

```
MemoryError: Cannot allocate memory
```

**Fix:**
- Reduce `batch_size`
- Reduce `max_events_in_memory`
- Increase pod/container memory limit

#### 5. Slow Collection

```
INFO: Collection completed for 'trino_proxy': duration: 456.23s
```

**Fix:**
- Add `where_clause` filters
- Reduce `batch_size`
- Increase `timeout_seconds`
- Check Trino/BigQuery query performance

### Health Checks

```bash
# Check service health
curl http://localhost:8000/health

# Check detailed status
curl http://localhost:8000/status

# Trigger manual collection
curl -X POST http://localhost:8000/collect/alienvault_otx
```

### Logs

```bash
# View logs
tail -f /var/log/ladon/collection.log

# Search for errors
grep ERROR /var/log/ladon/collection.log

# Monitor specific collector
grep "alienvault_otx" /var/log/ladon/collection.log
```

### Metrics

```bash
# Prometheus metrics endpoint
curl http://localhost:9090/metrics

# Key metrics:
# - collection_events_per_second
# - collection_errors_total
# - collection_latency_seconds
# - watermark_lag_seconds
```

---

## Example Configurations

### Minimal (Development)

```yaml
service:
  environment: development
  storage_service_url: null  # Use mock

pubsub:
  project_id: ladon-dev

ioc_feeds:
  - id: alienvault_otx
    collector_type: alienvault_otx
    enabled: true
    api_key: dev_key
    collection_interval_minutes: 60  # Slow for dev
    pubsub_topic: raw-ioc-events
```

### Production (Full Setup)

See `config.example.yaml` for complete production configuration with:
- 3 IOC feeds (AlienVault, abuse.ch, MISP)
- 5 activity log sources (Proxy, DNS, Sinkhole, MDE, CrowdStrike)
- Performance tuning
- Monitoring enabled
- Watermark persistence

---

## Next Steps

1. **Configure Sources:** Edit `config.yaml` with your credentials
2. **Test Connection:** Run health check: `curl http://localhost:8000/health`
3. **Monitor Metrics:** Check Prometheus: `http://localhost:9090/metrics`
4. **Tune Performance:** Adjust batch sizes and intervals based on volume
5. **Set Up Alerts:** Configure alerts for collection failures

## Additional Resources

- [AlienVault OTX API Docs](https://otx.alienvault.com/api)
- [abuse.ch API Docs](https://threatfox.abuse.ch/api/)
- [MISP API Docs](https://www.misp-project.org/openapi/)
- [BigQuery Best Practices](https://cloud.google.com/bigquery/docs/best-practices)
- [Trino Documentation](https://trino.io/docs/current/)
