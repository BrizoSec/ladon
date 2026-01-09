# Collection Service - Quick Start Guide

Get up and running in 5 minutes.

## Step 1: Copy Configuration Files

```bash
cd services/collection

# Copy example config
cp config/config.example.yaml config/config.yaml

# Copy environment variables
cp .env.example .env
```

## Step 2: Get API Keys

### Required (Choose ONE):

**Option A: AlienVault OTX (Free)**
1. Sign up: https://otx.alienvault.com/
2. Get API key: https://otx.alienvault.com/api
3. Add to `.env`:
   ```bash
   ALIENVAULT_API_KEY=your_key_here
   ```

**Option B: Use abuse.ch (No key needed)**
- Works immediately, no signup required
- High-quality malware IOCs

### Optional:

- **MISP:** Requires self-hosted instance
- **Activity Logs:** Requires Trino/BigQuery access

## Step 3: Edit Configuration

### Minimal Setup (Development)

Edit `config/config.yaml`:

```yaml
service:
  environment: development
  storage_service_url: null  # Use mock in dev

pubsub:
  project_id: ladon-dev

ioc_feeds:
  # Enable AlienVault OTX
  - id: alienvault_otx
    name: "AlienVault OTX"
    source_type: ioc_feed
    collector_type: alienvault_otx
    enabled: true
    collection_interval_minutes: 60  # 1 hour for dev
    api_key: ${ALIENVAULT_API_KEY}  # From .env
    pubsub_topic: raw-ioc-events

  # Enable abuse.ch
  - id: abuse_ch
    name: "abuse.ch ThreatFox"
    source_type: ioc_feed
    collector_type: abuse_ch
    enabled: true
    collection_interval_minutes: 30
    api_key: null  # No key needed
    pubsub_topic: raw-ioc-events

activity_logs: []  # No activity logs in dev
```

### Production Setup

Enable all sources in `config.yaml`, set real credentials in `.env`.

## Step 4: Install Dependencies

```bash
# Install Python dependencies
pip install -r requirements.txt

# Or use Poetry
poetry install
```

## Step 5: Run the Service

### Local Development

```bash
# Set config file path
export COLLECTION_CONFIG_FILE=config/config.yaml

# Run service
python -m src.main

# Or use uvicorn directly
uvicorn src.main:app --reload --port 8000
```

### Docker

```bash
# Build image
docker build -t ladon-collection:latest .

# Run container
docker run -d \
  -p 8000:8000 \
  -v $(pwd)/config:/app/config \
  --env-file .env \
  ladon-collection:latest
```

### Docker Compose

```bash
# Edit docker-compose.yml with your config
vim docker-compose.yml

# Start all services
docker-compose up -d

# View logs
docker-compose logs -f collection-service
```

## Step 6: Verify It's Working

### Check Health

```bash
curl http://localhost:8000/health
```

Expected response:
```json
{
  "status": "healthy",
  "collectors": {
    "alienvault_otx": true,
    "abuse_ch": true
  }
}
```

### Check Status

```bash
curl http://localhost:8000/status
```

### Manual Collection Test

```bash
# Collect from AlienVault OTX
curl -X POST http://localhost:8000/collect/alienvault_otx

# Collect from all sources
curl -X POST http://localhost:8000/collect
```

Expected response:
```json
{
  "source_id": "alienvault_otx",
  "events_collected": 1523,
  "events_failed": 0,
  "batches_processed": 2,
  "duration_seconds": 12.34
}
```

## Troubleshooting

### "Collector not found"

**Cause:** Collector not enabled or failed to initialize

**Fix:**
```bash
# Check initialization logs
docker-compose logs collection-service | grep "initialized"

# Verify config
python config/config_loader.py config/config.yaml
```

### "API key invalid"

**Cause:** Invalid or missing API key

**Fix:**
```bash
# Check .env file
cat .env | grep ALIENVAULT_API_KEY

# Test API key directly
curl -H "X-OTX-API-KEY: your_key" https://otx.alienvault.com/api/v1/pulses/subscribed
```

### "Storage Service connection failed"

**Cause:** Storage Service not running or wrong URL

**Fix:**
```bash
# In development, use mock storage
export COLLECTION_STORAGE_SERVICE_URL=

# Or start Storage Service
cd ../storage && docker-compose up -d
```

### "Pub/Sub permission denied"

**Cause:** Missing GCP credentials or permissions

**Fix:**
```bash
# In development, use mock Pub/Sub
export COLLECTION_ENVIRONMENT=development

# In production, set service account
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/key.json
```

## What's Next?

1. **Add More Sources:** Edit `config/config.yaml` to enable more collectors
2. **Configure Activity Logs:** Add Trino/BigQuery sources for your logs
3. **Monitor Metrics:** Check Prometheus at http://localhost:9090/metrics
4. **View Collected IOCs:** Check Pub/Sub topics or BigQuery tables
5. **Tune Performance:** Adjust batch sizes and intervals

## Configuration Cheat Sheet

| Collector | Interval | Batch Size | Rate Limit |
|-----------|----------|------------|------------|
| AlienVault OTX | 30 min | 1,000 | 10K/day |
| abuse.ch | 15 min | 5,000 | 100/hour |
| MISP | 30 min | 1,000 | Varies |
| Trino (Proxy) | 3 min | 100,000 | N/A |
| Trino (DNS) | 3 min | 150,000 | N/A |
| BigQuery | 3-5 min | 10,000-50,000 | Costs $ |

## Common Commands

```bash
# View logs
docker-compose logs -f collection-service

# Restart service
docker-compose restart collection-service

# Check configuration
python config/config_loader.py config/config.yaml

# Manual collection (all sources)
curl -X POST http://localhost:8000/collect

# Health check
curl http://localhost:8000/health

# Detailed status
curl http://localhost:8000/status | jq
```

## Getting Help

- **Detailed Docs:** See `config/README.md`
- **Configuration Examples:** See `config/config.example.yaml`
- **Issues:** Check GitHub issues or create new one
- **Logs:** Always check logs first: `docker-compose logs -f`

## Production Checklist

Before deploying to production:

- [ ] All API keys configured in Secret Manager (not .env)
- [ ] Storage Service running and accessible
- [ ] Pub/Sub topics created
- [ ] Service account has Pub/Sub Publisher role
- [ ] Monitoring/alerting configured
- [ ] Resource limits set (CPU, memory)
- [ ] Health checks configured in load balancer
- [ ] Logs forwarded to central logging
- [ ] Tested manual collection from each source
- [ ] Collection intervals tuned for volume
- [ ] Cost estimates reviewed (for BigQuery)

---

**Ready to go!** 🚀

For detailed configuration options, see [README.md](README.md).
