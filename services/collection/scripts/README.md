# Threat Intelligence Collection Testing Guide

This directory contains test scripts for validating threat intelligence collection from multiple sources.

## 📋 Available Test Scripts

| Script | Source | Status | IOCs Collected |
|--------|--------|--------|----------------|
| `test_alienvault.py` | AlienVault OTX | ✅ Tested | 43 IOCs |
| `test_abusech.py` | abuse.ch (ThreatFox + URLhaus) | ✅ Tested | 20 IOCs |
| `test_misp.py` | MISP | ⏳ Ready | - |
| `test_normalization.py` | Normalization Pipeline | ✅ Tested | 100% success |
| `test_storage.py` | Storage Pipeline | ✅ Tested | 100% success |

---

## 🔧 Quick Start

### 1. Set Up Environment

```bash
cd /Users/chemch/ladon/services/collection

# Copy .env example
cp .env.example .env

# Edit .env and add your API keys
# nano .env
```

### 2. Activate Virtual Environment

```bash
source venv/bin/activate
```

### 3. Run Tests

```bash
# Test AlienVault OTX
python scripts/test_alienvault.py

# Test abuse.ch
python scripts/test_abusech.py

# Test MISP
python scripts/test_misp.py

# Test normalization
python scripts/test_normalization.py

# Test storage pipeline
python scripts/test_storage.py
```

---

## 🌐 Source 1: AlienVault OTX

### Prerequisites

1. **Get API Key**
   - Sign up at https://otx.alienvault.com/
   - Go to **Settings** → **API Integration**
   - Copy your API key (also called "OTX Key")

2. **Add to .env**
   ```bash
   ALIENVAULT_API_KEY=your_api_key_here
   ```

### Run Test

```bash
python scripts/test_alienvault.py
```

### Expected Output

```
✅ Retrieved 5 pulses
📊 Processing 5 pulses...

--- Pulse 1: Malicious Domains Associated with APT28 ---
   Author: AlienVault
   Indicators: 45

✅ Collection Complete!
   Total Pulses: 5
   Total IOCs: 43
```

### Features
- **Coverage**: Broad threat intelligence from community pulses
- **IOC Types**: IPs, domains, URLs, file hashes
- **Metadata**: Threat classifications, MITRE ATT&CK tags
- **Rate Limit**: 10 requests/min (free tier)

---

## 🛡️ Source 2: abuse.ch

### Prerequisites

1. **Get Auth-Key** (FREE)
   - Go to https://auth.abuse.ch/
   - Sign up using X, LinkedIn, Google, or GitHub
   - **Connect at least 2 authentication providers** (required!)
   - Create an Auth-Key in the "Optional" section

2. **Add to .env**
   ```bash
   ABUSECH_AUTH_KEY=your_auth_key_here
   ```

### Run Test

```bash
python scripts/test_abusech.py
```

### Expected Output

```
✅ Retrieved 10 IOCs from ThreatFox
✅ Retrieved 10 URLs from URLhaus

--- Sample ThreatFox IOCs ---
   IOC #1: http://195.178.136.19/5
   Malware: win.phorpiex
   Confidence: 1.00

--- Sample URLhaus IOCs ---
   URL #1: http://195.178.136.19/5
   Status: online
   Confidence: 0.80

✅ Collection Complete!
   ThreatFox IOCs: 10
   URLhaus IOCs:   10
   Total IOCs:     20
```

### Features
- **ThreatFox**: C2 servers, malware distribution IOCs
- **URLhaus**: Malicious URLs with online/offline status
- **MalwareBazaar**: Malware samples (hashes)
- **No Cost**: Completely free with Auth-Key
- **High Quality**: Vetted, high-confidence IOCs

### Troubleshooting

**Error: "unknown_auth_key"**
- Make sure you connected **at least 2 authentication providers**
- Regenerate your Auth-Key in the abuse.ch portal
- Copy the key exactly (no extra spaces)

---

## 🔍 Source 3: MISP

### Prerequisites

1. **Get MISP Access**
   - Option A: Use a public MISP instance (https://www.misp-project.org/communities/)
   - Option B: Self-host MISP (https://www.misp-project.org/)
   - Option C: Use CIRCL MISP (https://www.circl.lu/services/misp-malware-information-sharing-platform/)

2. **Get API Key**
   - Log into your MISP instance
   - Go to **Global Actions** → **My Profile** → **Auth Keys**
   - Create or copy your API key

3. **Add to .env**
   ```bash
   MISP_URL=https://your-misp-instance.com
   MISP_API_KEY=your_api_key_here
   MISP_VERIFY_SSL=true  # Set to false for self-signed certs
   ```

### Run Test

```bash
python scripts/test_misp.py
```

### Expected Output

```
✅ Retrieved 5 events from MISP
✅ Retrieved 20 attributes from MISP

--- Sample MISP Events ---
   Event #1:
      ID:            12345
      Info:          APT28 Campaign Indicators
      Threat Level:  1
      Attributes:    25

--- Sample MISP IOCs ---
   IOC #1:
      Type:          domain
      Value:         malicious.com
      Category:      Network activity
      To IDS:        True
      Confidence:    0.90

✅ Collection Complete!
   MISP Events:    5
   MISP IOCs:      20
```

### Features
- **Structured Events**: Events with multiple related IOCs
- **Community Sharing**: Collaborative threat intelligence
- **MISP Taxonomies**: Rich tagging and classification
- **Custom Types**: Supports 100+ attribute types

---

## 🧪 Testing Normalization

After collecting IOCs, test the normalization pipeline:

```bash
python scripts/test_normalization.py
```

This script:
1. Loads sample AlienVault data
2. Feeds it through the normalizer
3. Shows before/after transformation
4. Validates output format

### Expected Output

```
📂 Loading sample AlienVault data...
   Found 2 pulses in sample data

🔧 Creating AlienVaultOTXNormalizer...
   Extracted 11 raw IOCs from pulses

📊 Statistics:
   Total Raw IOCs:        11
   ✅ Successfully Normalized: 11
   ❌ Failed to Normalize:     0
   📈 Success Rate:            100.0%
```

---

## 💾 Testing Storage

Test the complete pipeline from collection to storage:

```bash
python scripts/test_storage.py
```

This script:
1. Loads normalized IOCs
2. Sends them to Storage Service (or mock)
3. Validates data format for BigQuery + Redis
4. Shows pipeline statistics

### Expected Output

```
📦 Creating MockStorageClient...
📂 Loading sample AlienVault data...
🔧 Normalizing IOCs...
💾 Storing IOCs in Mock Storage...

✅ Successfully stored 11 IOCs to mock storage

📊 Pipeline Statistics:
   Raw IOCs collected:        11
   IOCs normalized:           11
   IOCs stored:               11
   Success rate:              100.0%
```

---

## 📊 Comparison: All Sources

| Feature | AlienVault OTX | abuse.ch | MISP |
|---------|---------------|----------|------|
| **Cost** | Free (with limits) | Free | Free (public instances) |
| **Auth** | API Key | Auth-Key | API Key + Instance |
| **Coverage** | Broad, community | Malware-focused | Customizable |
| **Confidence** | Medium-High | High | Varies |
| **Rate Limits** | 10 req/min | Moderate | Instance-dependent |
| **Best For** | General threat intel | Malware C2s & URLs | Structured events |

**Recommendation**: Use all three sources for comprehensive threat intelligence coverage! 🎯

---

## 🔄 Complete Pipeline Test

To test the full end-to-end pipeline:

```bash
# 1. Collect from AlienVault
python scripts/test_alienvault.py

# 2. Collect from abuse.ch
python scripts/test_abusech.py

# 3. Test normalization
python scripts/test_normalization.py

# 4. Test storage
python scripts/test_storage.py
```

This validates: **Collection → Normalization → Storage** ✅

---

## 📁 Sample Data Files

After running tests, these files are created:

- `sample_alienvault_output.json` - AlienVault OTX sample data
- `sample_abusech_output.json` - abuse.ch sample data
- `sample_misp_output.json` - MISP sample data

These files can be used for:
- Offline testing
- Normalization development
- Detection rule testing
- Demo purposes

---

## 🚀 Next Steps

After validating collection, normalization, and storage:

1. **Detection Service** - Correlate IOCs against activity logs
2. **Enrichment Service** - Add context from VirusTotal, PassiveTotal
3. **Scoring Service** - Calculate threat severity scores
4. **Notification Service** - ServiceNow integration
5. **Production Deployment** - Scheduled collection with Cloud Scheduler

---

## 🐛 Common Issues

### SSL Certificate Errors
```
SSLCertVerificationError: certificate verify failed
```
**Fix**: The test scripts already disable SSL verification for development. For production, ensure proper SSL certificates.

### Missing Dependencies
```
ModuleNotFoundError: No module named 'aiohttp'
```
**Fix**: Make sure virtual environment is activated:
```bash
source venv/bin/activate
pip install -r requirements.txt
```

### API Key Not Found
```
❌ Error: ALIENVAULT_API_KEY environment variable not set
```
**Fix**: Add your API key to the `.env` file.

---

## 📚 Resources

- **AlienVault OTX**: https://otx.alienvault.com/api
- **abuse.ch**: https://abuse.ch/
  - ThreatFox: https://threatfox.abuse.ch/api/
  - URLhaus: https://urlhaus.abuse.ch/api/
- **MISP**: https://www.misp-project.org/
  - OpenAPI Docs: https://www.misp-project.org/openapi/
- **LADON Documentation**: `/docs/`
