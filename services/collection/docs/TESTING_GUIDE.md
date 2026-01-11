# Collection Service Testing Guide

## Current Status

✅ **Working:** Docker container running with configuration file
✅ **Working:** AlienVault OTX collector - collecting IOCs successfully
❌ **Needs Setup:** abuse.ch collectors - requires Auth-Key

## What's Working

### AlienVault OTX Collection
- **Status:** Fully operational
- **IOCs Collected:** 282 IOCs per collection
- **Collection Interval:** Every 5 minutes (for testing)
- **IOC Types:** domains, IPv4, URLs, file hashes (SHA256)
- **API Key:** ✅ Configured and working

**Latest Collection:**
```json
{
  "source_id": "alienvault_otx_test",
  "events_collected": 282,
  "events_failed": 0,
  "batches_processed": 3,
  "duration_seconds": 0.12
}
```

### Service Health
```bash
$ curl http://localhost:8000/health
{
  "status": "healthy",
  "collectors": {
    "alienvault_otx_test": true,
    "abuse_ch_test": false
  }
}
```

---

## Setup Required for abuse.ch

### Why It's Failing
abuse.ch ThreatFox, URLhaus, and MalwareBazaar APIs **require authentication for ALL queries**. You're getting `401 Unauthorized` errors because no Auth-Key is provided.

### How to Fix It

#### Step 1: Get a Free Auth-Key
1. Visit: https://auth.abuse.ch/
2. Create a free account
3. Generate an Auth-Key (takes 2 minutes)

#### Step 2: Update Environment Variable
Once you have your Auth-Key, restart the container with:

```bash
docker stop ladon-test

docker run -d --rm --name ladon-test -p 8000:8000 \
  -e COLLECTION_ENVIRONMENT=development \
  -e COLLECTION_CONFIG_FILE=/app/config/config.test.yaml \
  -e ALIENVAULT_API_KEY='686e15af1e5e703ddeb452830b34c800c6403ed7d8bc438c9a65ba30ca01274d' \
  -e ABUSECH_API_KEY='YOUR_ABUSE_CH_AUTH_KEY_HERE' \
  collection-service:local
```

**Note:** The environment variable is `ABUSECH_API_KEY` (not `ABUSECH_AUTH_KEY`).

#### Step 3: Verify
```bash
# Check health
curl http://localhost:8000/health

# Should show both collectors as healthy:
{
  "status": "healthy",
  "collectors": {
    "alienvault_otx_test": true,
    "abuse_ch_test": true
  }
}

# Trigger manual collection
curl -X POST http://localhost:8000/collect/abuse_ch_test
```

---

## Running the Container

### Current Test Setup

```bash
docker run -d --rm --name ladon-test -p 8000:8000 \
  -e COLLECTION_ENVIRONMENT=development \
  -e COLLECTION_CONFIG_FILE=/app/config/config.test.yaml \
  -e ALIENVAULT_API_KEY='686e15af1e5e703ddeb452830b34c800c6403ed7d8bc438c9a65ba30ca01274d' \
  collection-service:local
```

### What This Does
- ✅ Uses **development mode** (MockPubSubPublisher, no GCP)
- ✅ Loads **config.test.yaml** (2 collectors: AlienVault + abuse.ch)
- ✅ Collects IOCs **every 5 minutes** (faster than production 30 min)
- ✅ Limits **10 pulses** per collection (vs 100 in production)
- ✅ Uses **mock storage** (no Firestore/BigQuery)

---

## API Endpoints

### Health Check
```bash
curl http://localhost:8000/health
```

### Service Status
```bash
curl http://localhost:8000/status
```

### Trigger Collection (All Sources)
```bash
curl -X POST http://localhost:8000/collect
```

### Trigger Collection (Single Source)
```bash
# AlienVault
curl -X POST http://localhost:8000/collect/alienvault_otx_test

# abuse.ch
curl -X POST http://localhost:8000/collect/abuse_ch_test
```

### View Logs
```bash
# Follow logs in real-time
docker logs -f ladon-test

# Last 50 lines
docker logs --tail 50 ladon-test

# Filter for collection events
docker logs ladon-test | grep "Collected.*IOCs"
```

---

## Configuration Files

### Test Configuration
**File:** `/app/config/config.test.yaml` (inside container)
**Local:** `services/collection/config/config.test.yaml`

**Current Settings:**
- **AlienVault OTX:** Enabled, 10 pulses, 5 min interval
- **abuse.ch:** Enabled, 5 min interval (needs Auth-Key)
- **Environment:** development
- **Pub/Sub:** Mock (in-memory)

### Customizing Config

Edit `services/collection/config/config.test.yaml`:

```yaml
ioc_feeds:
  - id: alienvault_otx_test
    enabled: true  # Set to false to disable
    collection_interval_minutes: 5  # Change interval
    pulses_limit: 10  # Change limit (max 100)

  - id: abuse_ch_test
    enabled: true  # Set to false to disable
    collection_interval_minutes: 5
```

After editing, **rebuild the image**:
```bash
./services/collection/build.sh
```

---

## Troubleshooting

### Container Crashes
```bash
# Check logs for error
docker logs ladon-test

# Common issues:
# 1. Config file not found
# 2. Invalid API key
# 3. Missing required env var
```

### No IOCs Collected
```bash
# Check if collector is enabled
curl http://localhost:8000/status | grep enabled

# Check if API key is set
docker exec ladon-test env | grep ALIENVAULT

# Trigger manual collection to see error
curl -X POST http://localhost:8000/collect/alienvault_otx_test
```

### abuse.ch 401 Errors
- **Cause:** No Auth-Key provided
- **Fix:** Get Auth-Key from https://auth.abuse.ch/
- **Set:** `-e ABUSECH_API_KEY='your-key-here'`

---

## Next Steps

### 1. Get abuse.ch Auth-Key
Visit https://auth.abuse.ch/ to enable the second collector.

### 2. Monitor Collection
```bash
# Watch logs for IOC collection
docker logs -f ladon-test | grep "Collected"

# Check watermarks (track progress)
curl http://localhost:8000/status | jq '.collectors[].watermark'
```

### 3. Deploy to Local K8s
Once satisfied with Docker testing:

```bash
cd /Users/chemch/ladon/services/collection
kubectl apply -f k8s-local/
```

See `LOCAL_K8S_GUIDE.md` for detailed steps.

### 4. Add More Collectors
Edit `config/config.test.yaml` to add:
- MISP instance (if you have one)
- Custom data sources
- Activity log collectors (Trino, BigQuery)

---

## Performance Metrics

### Current Test Run
- **AlienVault OTX:** 282 IOCs in 0.12s
- **abuse.ch:** 0 IOCs (needs Auth-Key)
- **Total:** 282 IOCs collected
- **Batches:** 3 batches (100 IOCs each)
- **Memory:** ~150MB container
- **CPU:** <5% (idle between collections)

### Production Expectations
With both collectors enabled and production settings:
- **AlienVault (100 pulses):** ~3,000-5,000 IOCs per collection
- **abuse.ch (3 days):** ~1,000-2,000 IOCs per collection
- **Total:** 4,000-7,000 IOCs per 30-min cycle
- **Daily:** ~200K-350K IOCs

---

## API Documentation

### Interactive Docs
Open in browser:
```bash
open http://localhost:8000/docs
```

This provides Swagger UI with all endpoints and models.

---

## Stopping the Container

```bash
# Stop and remove
docker stop ladon-test

# Container is automatically removed (--rm flag)
```

---

## Quick Reference

```bash
# Start
docker run -d --rm --name ladon-test -p 8000:8000 \
  -e COLLECTION_ENVIRONMENT=development \
  -e COLLECTION_CONFIG_FILE=/app/config/config.test.yaml \
  -e ALIENVAULT_API_KEY='YOUR_KEY' \
  collection-service:local

# Check health
curl http://localhost:8000/health

# View logs
docker logs -f ladon-test

# Trigger collection
curl -X POST http://localhost:8000/collect

# Stop
docker stop ladon-test
```

---

**Questions?** Check `DOCKER_RUN_LOCAL.md` or `LOCAL_K8S_GUIDE.md` for more details.
