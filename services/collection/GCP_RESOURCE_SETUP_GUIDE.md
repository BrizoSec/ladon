# GCP Resource Setup Guide

This guide walks you through creating all required GCP resources for the Collection Service.

## Overview

The Collection Service requires the following GCP resources:

| Resource | Purpose | Estimated Cost/Month |
|----------|---------|---------------------|
| **Pub/Sub Topics (6)** | Event streaming between services | ~$10-50 (depends on volume) |
| **Firestore** | Watermark storage for incremental collection | ~$5-20 |
| **BigQuery Dataset + Tables (4)** | Data warehouse for IOCs, activities, threats | ~$50-500 (depends on data volume) |
| **Service Account** | GCP authentication and authorization | Free |
| **Secret Manager (3 secrets)** | Secure API key storage | ~$1 |
| **Total** | | **~$66-571/month** |

## Prerequisites

Before starting:

1. **GCP Project**: You need a GCP project with billing enabled
   - Create one: https://console.cloud.google.com/projectcreate
   - Enable billing: https://console.cloud.google.com/billing

2. **gcloud CLI**: Installed and authenticated
   ```bash
   # Install: https://cloud.google.com/sdk/docs/install

   # Authenticate
   gcloud auth login

   # Verify
   gcloud projects list
   ```

3. **Permissions**: You need these IAM roles on the project:
   - `roles/owner` OR
   - `roles/editor` + `roles/iam.securityAdmin`

4. **API Keys**: Gather these before running the script:
   - **AlienVault OTX API Key**: Get from https://otx.alienvault.com/api
   - **MISP API Key**: From your MISP instance
   - **Trino Password**: From your Trino cluster admin

---

## Option 1: Automated Setup (Recommended)

### Step 1: Run the Setup Script

```bash
cd /Users/chemch/ladon/services/collection

# Run the automated setup script
./scripts/setup-gcp-resources.sh
```

The script will prompt you for:
- **Project ID** (e.g., `ladon-production`)
- **Region** (e.g., `us-central1`)
- **BigQuery Location** (e.g., `US`)
- **API Keys** (AlienVault, MISP, Trino password)

### Step 2: Follow the Prompts

The script will:
1. ✅ Enable required GCP APIs (~2 min)
2. ✅ Create 6 Pub/Sub topics (~1 min)
3. ✅ Create 3 Pub/Sub subscriptions (~1 min)
4. ✅ Create Firestore database (~2 min)
5. ✅ Create BigQuery dataset and 4 tables (~2 min)
6. ✅ Create service account with IAM roles (~1 min)
7. ✅ Create 3 secrets in Secret Manager (~2 min)
8. ✅ Verify all resources (~1 min)

**Total time: ~12 minutes**

### Step 3: Verify Setup

After the script completes:

```bash
# Run pre-deployment checks
./scripts/pre-deploy-check.sh production
```

If all checks pass ✅, you're ready to deploy!

---

## Option 2: Manual Setup

If you prefer to create resources manually or the script fails:

### 1. Enable APIs

```bash
export PROJECT_ID="ladon-production"
gcloud config set project $PROJECT_ID

# Enable required APIs
gcloud services enable pubsub.googleapis.com
gcloud services enable firestore.googleapis.com
gcloud services enable bigquery.googleapis.com
gcloud services enable container.googleapis.com
gcloud services enable secretmanager.googleapis.com
gcloud services enable iam.googleapis.com
```

**Why needed**: These APIs provide the services the Collection Service depends on.

### 2. Create Pub/Sub Topics

```bash
# Create topics for raw events
gcloud pubsub topics create raw-ioc-events
gcloud pubsub topics create raw-activity-events
gcloud pubsub topics create raw-threat-events

# Create topics for normalized events
gcloud pubsub topics create normalized-ioc-events
gcloud pubsub topics create normalized-activity-events
gcloud pubsub topics create normalized-threat-events

# Verify
gcloud pubsub topics list
```

**Why needed**: Pub/Sub topics enable asynchronous event streaming between services. The Collection Service publishes raw events, which downstream services (Normalization, Storage) consume.

**Data flow**:
```
Collection Service → raw-*-events → Normalization Service → normalized-*-events → Storage Service
```

### 3. Create Pub/Sub Subscriptions

```bash
# Create subscriptions for normalization service
gcloud pubsub subscriptions create normalization-raw-ioc \
  --topic=raw-ioc-events \
  --ack-deadline=60 \
  --message-retention-duration=7d

gcloud pubsub subscriptions create normalization-raw-activity \
  --topic=raw-activity-events \
  --ack-deadline=60 \
  --message-retention-duration=7d

gcloud pubsub subscriptions create normalization-raw-threat \
  --topic=raw-threat-events \
  --ack-deadline=60 \
  --message-retention-duration=7d

# Verify
gcloud pubsub subscriptions list
```

**Why needed**: Subscriptions allow downstream services to pull messages from topics. The 7-day retention ensures messages aren't lost if a service is down.

### 4. Create Firestore Database

```bash
gcloud firestore databases create \
  --location=us-central1 \
  --type=firestore-native

# Verify (check in console or with gcloud)
gcloud firestore databases list
```

**Why needed**: Firestore stores watermarks (timestamps) for each data source. This enables incremental collection - the service only fetches new data since the last successful collection.

**Example watermark document**:
```json
{
  "source_id": "alienvault_otx",
  "last_successful_timestamp": "2026-01-10T12:00:00Z",
  "last_attempt_timestamp": "2026-01-10T12:05:00Z",
  "status": "success"
}
```

### 5. Create BigQuery Dataset

```bash
bq mk --dataset \
  --location=US \
  --description="LADON data warehouse" \
  ladon

# Verify
bq ls
```

**Why needed**: BigQuery is the data warehouse for all threat intelligence data. It provides fast SQL queries over billions of records.

### 6. Create BigQuery Tables

#### IOCs Table

```bash
bq mk --table \
  --description="Indicators of Compromise from threat intelligence feeds" \
  --time_partitioning_field=first_seen \
  --time_partitioning_type=DAY \
  --clustering_fields=ioc_type,source \
  ladon.iocs \
  ioc_value:STRING,ioc_type:STRING,threat_type:STRING,confidence:FLOAT64,source:STRING,first_seen:TIMESTAMP,last_seen:TIMESTAMP,tags:STRING,metadata:JSON,enrichment:JSON
```

**Schema**:
- `ioc_value`: IP address, domain, hash, etc.
- `ioc_type`: ip, domain, url, hash_md5, hash_sha256
- `threat_type`: malware, c2, phishing, ransomware
- `confidence`: 0.0-1.0 confidence score
- `source`: alienvault, abuse.ch, misp
- `first_seen`, `last_seen`: Temporal tracking
- `tags`: Comma-separated tags
- `metadata`: Raw metadata from source
- `enrichment`: VirusTotal, PassiveTotal data

**Partitioning**: By day on `first_seen` reduces query costs by only scanning relevant partitions.

**Clustering**: By `ioc_type` and `source` optimizes queries that filter on these fields.

#### Activity Logs Table

```bash
bq mk --table \
  --description="Activity logs from various sources (Proxy, DNS, MDE, CrowdStrike, Sinkhole)" \
  --time_partitioning_field=timestamp \
  --time_partitioning_type=DAY \
  --clustering_fields=source,event_type \
  ladon.activity_logs \
  event_id:STRING,timestamp:TIMESTAMP,source:STRING,event_type:STRING,src_ip:STRING,dst_ip:STRING,domain:STRING,url:STRING,hostname:STRING,user:STRING,process_name:STRING,file_hash:STRING,enrichment:JSON,raw_event:JSON
```

**Schema**:
- `event_id`: Unique event identifier
- `timestamp`: When the event occurred
- `source`: proxy, dns, mde, crowdstrike, sinkhole
- `event_type`: dns_query, http_request, process_create
- Network fields: `src_ip`, `dst_ip`, `domain`, `url`
- Host fields: `hostname`, `user`, `process_name`, `file_hash`
- `enrichment`: User/asset context from CMDB
- `raw_event`: Original event for forensics

#### Threats Table

```bash
bq mk --table \
  --description="Threat actors, campaigns, and malware families" \
  --time_partitioning_field=first_seen \
  --time_partitioning_type=DAY \
  --clustering_fields=category,source \
  ladon.threats \
  threat_id:STRING,name:STRING,category:STRING,description:STRING,source:STRING,first_seen:TIMESTAMP,last_seen:TIMESTAMP,tags:STRING,metadata:JSON
```

**Schema**:
- `threat_id`: Unique threat identifier
- `name`: Threat name (e.g., "APT28", "Emotet")
- `category`: threat_actor, campaign, malware_family
- `description`: Threat description
- `source`: Feed that reported the threat
- Temporal and metadata fields

#### Threat-IOC Associations Table

```bash
bq mk --table \
  --description="Associations between threats and IOCs" \
  --time_partitioning_field=first_seen \
  --time_partitioning_type=DAY \
  ladon.threat_ioc_associations \
  threat_id:STRING,ioc_value:STRING,ioc_type:STRING,relationship_type:STRING,confidence:FLOAT64,first_seen:TIMESTAMP,last_seen:TIMESTAMP
```

**Schema**:
- Links threats to their IOCs
- `relationship_type`: uses, hosts, communicates_with, drops
- Enables queries like "show all IPs used by APT28"

#### Verify Tables

```bash
bq ls ladon
```

### 7. Create Service Account

```bash
export PROJECT_ID="ladon-production"

# Create service account
gcloud iam service-accounts create collection-service \
  --display-name="Collection Service" \
  --description="Service account for LADON Collection Service"

export SA_EMAIL="collection-service@${PROJECT_ID}.iam.gserviceaccount.com"

# Grant IAM roles
gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:${SA_EMAIL}" \
  --role="roles/pubsub.publisher"

gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:${SA_EMAIL}" \
  --role="roles/datastore.user"

gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:${SA_EMAIL}" \
  --role="roles/bigquery.dataEditor"

gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:${SA_EMAIL}" \
  --role="roles/bigquery.jobUser"

gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:${SA_EMAIL}" \
  --role="roles/secretmanager.secretAccessor"

# Verify
gcloud iam service-accounts describe $SA_EMAIL
```

**Why needed**: The service account provides identity and permissions for the Collection Service pods. Using Workload Identity (configured during deployment), pods can authenticate to GCP services without storing keys.

**Permissions explained**:
- `pubsub.publisher`: Publish events to Pub/Sub topics
- `datastore.user`: Read/write Firestore watermarks
- `bigquery.dataEditor`: Insert data into BigQuery (used by Storage Service)
- `bigquery.jobUser`: Run BigQuery queries (for activity collection)
- `secretmanager.secretAccessor`: Read API keys from Secret Manager

### 8. Create Secrets

```bash
export PROJECT_ID="ladon-production"
export SA_EMAIL="collection-service@${PROJECT_ID}.iam.gserviceaccount.com"

# AlienVault API Key
echo -n "YOUR_ALIENVAULT_API_KEY" | gcloud secrets create alienvault-api-key \
  --data-file=- \
  --replication-policy=automatic

gcloud secrets add-iam-policy-binding alienvault-api-key \
  --member="serviceAccount:${SA_EMAIL}" \
  --role="roles/secretmanager.secretAccessor"

# MISP API Key
echo -n "YOUR_MISP_API_KEY" | gcloud secrets create misp-api-key \
  --data-file=- \
  --replication-policy=automatic

gcloud secrets add-iam-policy-binding misp-api-key \
  --member="serviceAccount:${SA_EMAIL}" \
  --role="roles/secretmanager.secretAccessor"

# Trino Password
echo -n "YOUR_TRINO_PASSWORD" | gcloud secrets create trino-password \
  --data-file=- \
  --replication-policy=automatic

gcloud secrets add-iam-policy-binding trino-password \
  --member="serviceAccount:${SA_EMAIL}" \
  --role="roles/secretmanager.secretAccessor"

# Verify
gcloud secrets list
```

**Why needed**: Secrets Manager securely stores API keys and credentials. The Collection Service reads these at runtime (no keys in code or containers).

**How to get API keys**:

1. **AlienVault OTX**:
   - Sign up: https://otx.alienvault.com/
   - Go to Settings → API Key
   - Copy the API key

2. **MISP**:
   - Log in to your MISP instance
   - Go to Event Actions → Automation
   - Copy your authentication key

3. **Trino**:
   - Get the password from your Trino administrator
   - Or check your Trino connection string

### 9. Verify All Resources

```bash
cd /Users/chemch/ladon/services/collection

# Run pre-deployment checks
./scripts/pre-deploy-check.sh production
```

Expected output:
```
[✓] gcloud authenticated
[✓] Project ladon-production exists and is accessible
[✓] GKE cluster ladon-production-gke exists
[✓] Pub/Sub topic: raw-ioc-events
[✓] Pub/Sub topic: raw-activity-events
...
[✓] All checks passed!
```

---

## Troubleshooting

### Permission Denied Errors

**Error**: `Permission denied on resource project`

**Solution**: Ensure you have the necessary IAM roles:
```bash
# Check your permissions
gcloud projects get-iam-policy $PROJECT_ID \
  --flatten="bindings[].members" \
  --filter="bindings.members:user:YOUR_EMAIL"

# Ask project owner to grant you roles/owner or roles/editor
```

### Billing Not Enabled

**Error**: `Billing must be enabled for project`

**Solution**: Enable billing in GCP Console:
1. Go to https://console.cloud.google.com/billing
2. Link a billing account to your project

### API Not Enabled

**Error**: `API [service] is not enabled for project`

**Solution**: Enable the API:
```bash
gcloud services enable SERVICE_NAME.googleapis.com
```

### Secret Already Exists

**Error**: `Resource already exists`

**Solution**: Update the existing secret:
```bash
# Add a new version
echo -n "NEW_VALUE" | gcloud secrets versions add SECRET_NAME --data-file=-
```

### Firestore Database Already Exists

**Error**: `Only one database is allowed`

**Solution**: This is fine - Firestore only allows one database per project. Skip this step.

---

## Cost Estimation

### Pub/Sub
- **Free tier**: First 10 GB/month free
- **After free tier**: $0.06 per GB
- **Estimated**: ~$10-50/month (depends on message volume)

### Firestore
- **Storage**: $0.18 per GB/month (watermarks ~1 MB)
- **Reads**: $0.06 per 100K (minimal for watermarks)
- **Writes**: $0.18 per 100K (one write per collection cycle)
- **Estimated**: ~$5-20/month

### BigQuery
- **Storage**: $0.02 per GB/month (first 10 GB free)
- **Queries**: $6.25 per TB scanned (first 1 TB/month free)
- **Estimated**: ~$50-500/month (highly depends on data volume and query patterns)

### Secret Manager
- **Storage**: $0.06 per secret version/month
- **Access operations**: Free for first 10K, then $0.03 per 10K
- **Estimated**: ~$1/month

**Total**: ~$66-571/month

**Cost optimization tips**:
1. Use BigQuery table partitioning (already configured)
2. Use clustering on common filter fields (already configured)
3. Set query quotas to prevent runaway costs
4. Monitor costs in GCP Console

---

## Next Steps

After GCP resources are created:

1. **Verify resources** - Run `./scripts/pre-deploy-check.sh production`
2. **Build Docker image** - See `DEPLOY_QUICKSTART.md`
3. **Deploy to GKE** - Run `./scripts/deploy.sh production`
4. **Monitor collection** - Check logs and BigQuery for data

---

## Support

If you encounter issues:
- **Check logs**: All commands output detailed error messages
- **Documentation**: See `DEPLOYMENT_GUIDE.md` for detailed reference
- **GCP Console**: Verify resources at https://console.cloud.google.com
