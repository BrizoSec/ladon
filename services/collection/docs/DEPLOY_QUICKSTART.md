# Collection Service - Quick Deploy Guide

Fast-track guide to deploy Collection Service to production in ~30 minutes.

## Prerequisites

Ensure you have:
- GCP project created
- GKE cluster running
- `gcloud`, `kubectl`, `docker` installed
- Authentication configured

## Step-by-Step Deployment

### Step 1: Run Pre-Deployment Check (2 min)

```bash
cd /Users/chemch/ladon/services/collection

# Check if all resources are ready
./scripts/pre-deploy-check.sh production
```

**If checks fail**, follow the error messages to create missing resources.

### Step 2: Create GCP Resources (10 min)

If resources don't exist, create them:

```bash
# Set your project
export PROJECT_ID="ladon-production"
gcloud config set project $PROJECT_ID

# Create Pub/Sub topics (1 min)
for topic in raw-ioc-events raw-activity-events raw-threat-events \
             normalized-ioc-events normalized-activity-events normalized-threat-events; do
  gcloud pubsub topics create $topic
done

# Create Firestore database (2 min)
gcloud firestore databases create --location=us-central1

# Create BigQuery dataset and tables (3 min)
bq mk --dataset --location=US threat_xdr

bq mk --table threat_xdr.iocs \
  ioc_value:STRING,ioc_type:STRING,threat_type:STRING,confidence:FLOAT64,source:STRING,first_seen:TIMESTAMP,last_seen:TIMESTAMP,tags:STRING,metadata:JSON,enrichment:JSON \
  --time_partitioning_field=first_seen \
  --clustering_fields=ioc_type,source

bq mk --table threat_xdr.activity_logs \
  event_id:STRING,timestamp:TIMESTAMP,source:STRING,event_type:STRING,src_ip:STRING,dst_ip:STRING,domain:STRING,url:STRING,hostname:STRING,user:STRING,process_name:STRING,file_hash:STRING,enrichment:JSON,raw_event:JSON \
  --time_partitioning_field=timestamp \
  --clustering_fields=source,event_type

bq mk --table threat_xdr.threats \
  threat_id:STRING,name:STRING,category:STRING,description:STRING,source:STRING,first_seen:TIMESTAMP,last_seen:TIMESTAMP,tags:STRING,metadata:JSON \
  --time_partitioning_field=first_seen \
  --clustering_fields=category,source

bq mk --table threat_xdr.threat_ioc_associations \
  threat_id:STRING,ioc_value:STRING,ioc_type:STRING,relationship_type:STRING,confidence:FLOAT64,first_seen:TIMESTAMP,last_seen:TIMESTAMP

# Create service account (2 min)
gcloud iam service-accounts create collection-service \
  --display-name="Collection Service"

SA_EMAIL="collection-service@${PROJECT_ID}.iam.gserviceaccount.com"

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

# Create secrets (2 min)
echo -n "YOUR_ALIENVAULT_API_KEY" | gcloud secrets create alienvault-api-key --data-file=-
echo -n "YOUR_MISP_API_KEY" | gcloud secrets create misp-api-key --data-file=-
echo -n "YOUR_TRINO_PASSWORD" | gcloud secrets create trino-password --data-file=-

gcloud secrets add-iam-policy-binding alienvault-api-key \
  --member="serviceAccount:${SA_EMAIL}" \
  --role="roles/secretmanager.secretAccessor"

gcloud secrets add-iam-policy-binding misp-api-key \
  --member="serviceAccount:${SA_EMAIL}" \
  --role="roles/secretmanager.secretAccessor"

gcloud secrets add-iam-policy-binding trino-password \
  --member="serviceAccount:${SA_EMAIL}" \
  --role="roles/secretmanager.secretAccessor"
```

### Step 3: Verify Configuration (1 min)

```bash
# Update production overlay if needed
cat k8s/overlays/production/kustomization.yaml

# Ensure PROJECT_ID and image tags are correct
```

### Step 4: Run Automated Deployment (15 min)

```bash
# Deploy to production
./scripts/deploy.sh production
```

This script will:
1. Build Docker image
2. Push to GCR
3. Update Kubernetes manifests
4. Deploy to GKE
5. Wait for pods to be ready
6. Verify health endpoints

### Step 5: Verify Deployment (2 min)

```bash
# Check pods
kubectl get pods -n ladon -l app=collection-service

# Check logs
kubectl logs -n ladon -l app=collection-service --tail=50

# Verify health
kubectl port-forward -n ladon svc/prod-collection-service 8080:8080 &
curl http://localhost:8080/health
kill %1
```

### Step 6: Verify Data Collection (5 min)

```bash
# Check Pub/Sub messages
gcloud pubsub topics list-subscriptions raw-ioc-events

# Check Firestore watermarks
gcloud firestore export gs://${PROJECT_ID}-firestore-export --collection-ids=watermarks

# Query BigQuery
bq query --use_legacy_sql=false \
  'SELECT source, COUNT(*) as count FROM threat_xdr.iocs
   WHERE DATE(first_seen) = CURRENT_DATE()
   GROUP BY source'
```

## Troubleshooting

### Pods Not Starting

```bash
# Check pod status
kubectl describe pod -n ladon <pod-name>

# Common fixes:
# - ImagePullBackOff: Verify image exists in GCR
# - CrashLoopBackOff: Check logs for errors
```

### No Data Collected

```bash
# Check logs for errors
kubectl logs -n ladon -l app=collection-service | grep -i error

# Verify API credentials
kubectl exec -n ladon <pod-name> -- env | grep API_KEY

# Test external connectivity
kubectl exec -n ladon <pod-name> -- curl -I https://otx.alienvault.com
```

## Rollback

If deployment fails:

```bash
./scripts/deploy.sh production rollback
```

## Manual Deployment (Alternative)

If the automated script doesn't work:

```bash
# 1. Build and push image
docker build -t gcr.io/${PROJECT_ID}/collection-service:v1.0.0 .
gcloud auth configure-docker
docker push gcr.io/${PROJECT_ID}/collection-service:v1.0.0

# 2. Deploy to Kubernetes
gcloud container clusters get-credentials ladon-production-gke --region=us-central1
kubectl apply -k k8s/overlays/production/

# 3. Check status
kubectl rollout status deployment/prod-collection-service -n ladon
```

## Next Steps

After successful deployment:

1. **Monitor for 1 hour** - Watch logs for errors
2. **Verify data flow** - Check BigQuery tables for new data
3. **Configure alerts** - Set up GCP monitoring alerts
4. **Deploy next service** - Normalization Service

## Support

- **Documentation**: `DEPLOYMENT_GUIDE.md` (detailed guide)
- **Scripts**: `./scripts/deploy.sh` (deployment), `./scripts/pre-deploy-check.sh` (verification)
- **Logs**: `kubectl logs -n ladon -l app=collection-service -f`
