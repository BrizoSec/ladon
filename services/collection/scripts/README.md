# AlienVault OTX Collection Testing Guide

## Prerequisites

1. **Get AlienVault OTX API Key**
   - Sign up at https://otx.alienvault.com/
   - Go to **Settings** → **API Integration**
   - Copy your API key

2. **Set Environment Variable**
   ```bash
   export ALIENVAULT_API_KEY="your_api_key_here"
   ```

## Quick Test (Recommended)

Run the test script to verify AlienVault collection:

```bash
cd /Users/chemch/ladon/services/collection

# Activate virtual environment
source venv/bin/activate

# Run test script
python scripts/test_alienvault.py
```

### Expected Output

```
================================================================================
AlienVault OTX Collection Test
================================================================================

🔍 Fetching pulses from AlienVault OTX...
   URL: https://otx.alienvault.com/api/v1/pulses/subscribed
   Params: {'limit': 5}
✅ Retrieved 5 pulses

📊 Processing 5 pulses...

--- Pulse 1: Malicious Domains Associated with APT28 ---
   Author: AlienVault
   Created: 2024-12-15T10:30:00
   Tags: apt28, malware, russia, espionage
   Indicators: 45

   Sample IOCs:
      • domain: malicious-domain.com
        Threat: c2, Confidence: 0.80
      • IPv4: 192.0.2.1
        Threat: c2, Confidence: 0.80
      • FileHash-SHA256: abc123...
        Threat: malware, Confidence: 0.80

================================================================================
✅ Collection Complete!
   Total Pulses: 5
   Total IOCs: 234
   Average IOCs per pulse: 46.8
================================================================================

💾 Sample data saved to: scripts/sample_alienvault_output.json
```

## Full Integration Test

To test the complete pipeline (Collection → Normalization):

### 1. Start Pub/Sub Emulator (Local Testing)

```bash
# Install Pub/Sub emulator
gcloud components install pubsub-emulator

# Start emulator
gcloud beta emulators pubsub start --host-port=0.0.0.0:8085
```

### 2. Set Environment Variables

```bash
export PUBSUB_EMULATOR_HOST=localhost:8085
export PUBSUB_PROJECT_ID=ladon-dev
export ALIENVAULT_API_KEY="your_api_key"
```

### 3. Run Collection Service

```bash
cd /Users/chemch/ladon/services/collection
source venv/bin/activate
python -m uvicorn src.main:app --reload --port 8001
```

### 4. Run Normalization Service

```bash
cd /Users/chemch/ladon/services/normalization
source venv/bin/activate
python -m uvicorn src.main:app --reload --port 8002
```

### 5. Trigger Collection

```bash
# Trigger AlienVault collection via API
curl -X POST http://localhost:8001/collect/alienvault_otx
```

## Test Data Structure

### Raw IOC Event (from Collection Service)
```json
{
  "source": "alienvault",
  "pulse_id": "abc123",
  "pulse_name": "Malicious Domains Associated with APT28",
  "ioc_value": "malicious-domain.com",
  "ioc_type": "domain",
  "tags": ["apt28", "malware", "russia"],
  "threat_type": "c2",
  "confidence": 0.80,
  "created": "2024-12-15T10:30:00"
}
```

### Normalized IOC (from Normalization Service)
```json
{
  "ioc_value": "malicious-domain.com",
  "ioc_type": "domain",
  "threat_type": "c2",
  "confidence": 0.80,
  "source": "alienvault",
  "first_seen": "2024-12-15T10:30:00+00:00",
  "last_seen": "2024-12-15T10:30:00+00:00",
  "tags": ["apt28", "malware", "russia"],
  "metadata": {
    "pulse_id": "abc123",
    "pulse_name": "Malicious Domains Associated with APT28"
  }
}
```

## AlienVault OTX API Endpoints

The collector uses these endpoints:

| Endpoint | Purpose | Rate Limit |
|----------|---------|------------|
| `/api/v1/pulses/subscribed` | Get subscribed pulses | 10 req/min (free) |
| `/api/v1/pulses/{pulse_id}` | Get specific pulse | 10 req/min (free) |
| `/api/v1/indicators/{type}/{indicator}` | Get indicator details | 10 req/min (free) |

**Note**: Free tier has rate limits. For production, consider AlienVault OTX Pro.

## Troubleshooting

### Error: "Invalid API Key"
- Verify API key is correct
- Check key hasn't expired
- Ensure key has proper permissions

### Error: "Rate limit exceeded"
- Free tier: 10 requests/minute
- Wait 60 seconds between requests
- Consider upgrading to Pro tier

### No IOCs Retrieved
- Check if you're subscribed to any pulses
- Go to https://otx.alienvault.com/ and subscribe to threat feeds
- Default subscriptions may take 24 hours to activate

### Connection Timeout
- Check internet connectivity
- Verify no firewall blocking otx.alienvault.com
- Try: `curl https://otx.alienvault.com/api/v1/pulses/subscribed -H "X-OTX-API-KEY: your_key"`

## Next Steps

After testing AlienVault collection:

1. **Add Other Feeds**: Test abuse.ch, MISP collectors
2. **Test Normalization**: Verify IOCs are normalized correctly
3. **Test Detection**: Correlate IOCs against activity logs
4. **Production Deployment**: Set up scheduled collection (cron/Cloud Scheduler)

## Production Configuration

For production, configure in `config.yaml`:

```yaml
data_sources:
  - id: alienvault_otx
    type: threat_intel
    enabled: true
    api_key_secret: projects/PROJECT_ID/secrets/alienvault-api-key
    collection_schedule: "0 */6 * * *"  # Every 6 hours
    batch_size: 100
    rate_limit:
      requests_per_minute: 8  # Stay under 10/min limit
      retry_backoff: exponential
```

## Resources

- AlienVault OTX API Docs: https://otx.alienvault.com/api
- LADON Collection Service: `/services/collection/README.md`
- LADON Normalization Service: `/services/normalization/README.md`
