# Collection Service - Production Deployment Guide

This guide walks you through deploying the Collection Service to production on GKE.

## Prerequisites

Before deploying to production, ensure you have:

- [x] GKE cluster running
- [x] `kubectl` configured for your production cluster
- [x] `gcloud` CLI authenticated
- [x] Docker installed for building images
- [x] Access to Google Container Registry (GCR) or Artifact Registry

## Deployment Checklist

### Phase 1: Prepare GCP Resources

#### 1.1 Create Pub/Sub Topics

```bash
# Set project
export PROJECT_ID="ladon-production"
gcloud config set project $PROJECT_ID

# Create Pub/Sub topics
gcloud pubsub topics create raw-ioc-events
gcloud pubsub topics create raw-activity-events
gcloud pubsub topics create raw-threat-events
gcloud pubsub topics create normalized-ioc-events
gcloud pubsub topics create normalized-activity-events
gcloud pubsub topics create normalized-threat-events

# Create subscriptions (for downstream services)
gcloud pubsub subscriptions create normalization-raw-ioc \
  --topic=raw-ioc-events \
  --ack-deadline=60

gcloud pubsub subscriptions create normalization-raw-activity \
  --topic=raw-activity-events \
  --ack-deadline=60

gcloud pubsub subscriptions create normalization-raw-threat \
  --topic=raw-threat-events \
  --ack-deadline=60

# Verify topics
gcloud pubsub topics list
```

#### 1.2 Create Firestore Database

```bash
# Create Firestore database (if not exists)
gcloud firestore databases create --location=us-central1

# Firestore will be used for watermark storage
# Collections will be auto-created by the service:
# - watermarks/{source_id}
```

#### 1.3 Create BigQuery Dataset and Tables

```bash
# Create dataset
bq mk --dataset \
  --location=US \
  --description="LADON data warehouse" \
  ladon

# Create IOCs table
bq mk --table \
  ladon.iocs \
  ioc_value:STRING,ioc_type:STRING,threat_type:STRING,confidence:FLOAT64,source:STRING,first_seen:TIMESTAMP,last_seen:TIMESTAMP,tags:STRING,metadata:JSON,enrichment:JSON \
  --time_partitioning_field=first_seen \
  --clustering_fields=ioc_type,source

# Create activity logs table
bq mk --table \
  ladon.activity_logs \
  event_id:STRING,timestamp:TIMESTAMP,source:STRING,event_type:STRING,src_ip:STRING,dst_ip:STRING,domain:STRING,url:STRING,hostname:STRING,user:STRING,process_name:STRING,file_hash:STRING,enrichment:JSON,raw_event:JSON \
  --time_partitioning_field=timestamp \
  --clustering_fields=source,event_type

# Create threats table
bq mk --table \
  ladon.threats \
  threat_id:STRING,name:STRING,category:STRING,description:STRING,source:STRING,first_seen:TIMESTAMP,last_seen:TIMESTAMP,tags:STRING,metadata:JSON \
  --time_partitioning_field=first_seen \
  --clustering_fields=category,source

# Create threat-IOC associations table
bq mk --table \
  ladon.threat_ioc_associations \
  threat_id:STRING,ioc_value:STRING,ioc_type:STRING,relationship_type:STRING,confidence:FLOAT64,first_seen:TIMESTAMP,last_seen:TIMESTAMP

# Verify tables
bq ls ladon
```

#### 1.4 Create Service Account

```bash
# Create GCP service account for collection service
gcloud iam service-accounts create collection-service \
  --display-name="Collection Service" \
  --description="Service account for LADON Collection Service"

export SA_EMAIL="collection-service@${PROJECT_ID}.iam.gserviceaccount.com"

# Grant required permissions
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
```

#### 1.5 Store Secrets in Secret Manager

```bash
# Create secrets for API keys
echo -n "YOUR_ALIENVAULT_API_KEY" | gcloud secrets create alienvault-api-key \
  --data-file=- \
  --replication-policy=automatic

echo -n "YOUR_MISP_API_KEY" | gcloud secrets create misp-api-key \
  --data-file=- \
  --replication-policy=automatic

echo -n "YOUR_TRINO_PASSWORD" | gcloud secrets create trino-password \
  --data-file=- \
  --replication-policy=automatic

# Grant service account access
gcloud secrets add-iam-policy-binding alienvault-api-key \
  --member="serviceAccount:${SA_EMAIL}" \
  --role="roles/secretmanager.secretAccessor"

gcloud secrets add-iam-policy-binding misp-api-key \
  --member="serviceAccount:${SA_EMAIL}" \
  --role="roles/secretmanager.secretAccessor"

gcloud secrets add-iam-policy-binding trino-password \
  --member="serviceAccount:${SA_EMAIL}" \
  --role="roles/secretmanager.secretAccessor"

# Verify secrets
gcloud secrets list
```

### Phase 2: Build and Push Docker Image

#### 2.1 Build Docker Image

```bash
# Navigate to collection service directory
cd /Users/chemch/ladon/services/collection

# Build Docker image
docker build -t gcr.io/${PROJECT_ID}/collection-service:v1.0.0 .

# Tag as latest
docker tag gcr.io/${PROJECT_ID}/collection-service:v1.0.0 \
  gcr.io/${PROJECT_ID}/collection-service:latest
```

#### 2.2 Test Docker Image Locally

```bash
# Run container locally for testing
docker run -p 8080:8080 \
  -e GCP_PROJECT_ID=$PROJECT_ID \
  -e COLLECTION_ENVIRONMENT=local \
  -e COLLECTION_LOG_LEVEL=DEBUG \
  gcr.io/${PROJECT_ID}/collection-service:v1.0.0

# In another terminal, test health endpoint
curl http://localhost:8080/health

# Stop the container
docker stop $(docker ps -q --filter ancestor=gcr.io/${PROJECT_ID}/collection-service:v1.0.0)
```

#### 2.3 Push Image to GCR

```bash
# Configure Docker for GCR
gcloud auth configure-docker

# Push image
docker push gcr.io/${PROJECT_ID}/collection-service:v1.0.0
docker push gcr.io/${PROJECT_ID}/collection-service:latest

# Verify image
gcloud container images list --repository=gcr.io/${PROJECT_ID}
gcloud container images describe gcr.io/${PROJECT_ID}/collection-service:v1.0.0
```

### Phase 3: Configure Kubernetes

#### 3.1 Update Production Overlay

```bash
# Update image tag in production kustomization.yaml
cd k8s/overlays/production

# Edit kustomization.yaml and update the image tag
cat > kustomization.yaml <<EOF
---
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

bases:
  - ../../

namespace: ladon

namePrefix: prod-

commonLabels:
  environment: production

patchesStrategicMerge:
  - deployment-patch.yaml
  - hpa-patch.yaml

images:
  - name: gcr.io/ladon-production/collection-service
    newName: gcr.io/${PROJECT_ID}/collection-service
    newTag: v1.0.0

replicas:
  - name: collection-service
    count: 3
EOF
```

#### 3.2 Create Production Secrets

```bash
# Create Kubernetes secret for API keys
# Note: In production, use External Secrets Operator to sync from Secret Manager

kubectl create namespace ladon --dry-run=client -o yaml | kubectl apply -f -

kubectl create secret generic collection-secrets \
  --from-literal=ALIENVAULT_API_KEY="secret://alienvault-api-key" \
  --from-literal=MISP_API_KEY="secret://misp-api-key" \
  --from-literal=TRINO_PASSWORD="secret://trino-password" \
  --namespace=ladon \
  --dry-run=client -o yaml > /tmp/collection-secrets.yaml

kubectl apply -f /tmp/collection-secrets.yaml
```

#### 3.3 Configure Workload Identity

```bash
# Get GKE cluster name and region
export CLUSTER_NAME="ladon-production-gke"
export CLUSTER_REGION="us-central1"

# Ensure Workload Identity is enabled on cluster
gcloud container clusters describe $CLUSTER_NAME \
  --region=$CLUSTER_REGION \
  --format="value(workloadIdentityConfig.workloadPool)"

# If not enabled, enable it:
# gcloud container clusters update $CLUSTER_NAME \
#   --region=$CLUSTER_REGION \
#   --workload-pool=${PROJECT_ID}.svc.id.goog

# Bind Kubernetes SA to GCP SA
kubectl annotate serviceaccount collection-service \
  --namespace=ladon \
  iam.gke.io/gcp-service-account=${SA_EMAIL} \
  --overwrite

# Allow Kubernetes SA to impersonate GCP SA
gcloud iam service-accounts add-iam-policy-binding ${SA_EMAIL} \
  --role=roles/iam.workloadIdentityUser \
  --member="serviceAccount:${PROJECT_ID}.svc.id.goog[ladon/collection-service]"

# Verify binding
gcloud iam service-accounts get-iam-policy ${SA_EMAIL}
```

### Phase 4: Deploy to Production

#### 4.1 Verify Kustomize Output

```bash
# Preview what will be deployed
cd /Users/chemch/ladon/services/collection
kubectl kustomize k8s/overlays/production

# Verify all resources look correct
```

#### 4.2 Apply Kubernetes Manifests

```bash
# Deploy to production
kubectl apply -k k8s/overlays/production/

# Verify namespace
kubectl get namespace ladon

# Verify resources
kubectl get all -n ladon -l app=collection-service
```

#### 4.3 Check Deployment Status

```bash
# Watch deployment rollout
kubectl rollout status deployment/prod-collection-service -n ladon

# Check pod status
kubectl get pods -n ladon -l app=collection-service

# Expected output:
# NAME                                      READY   STATUS    RESTARTS   AGE
# prod-collection-service-xxxxxxxxx-xxxxx   1/1     Running   0          2m
# prod-collection-service-xxxxxxxxx-xxxxx   1/1     Running   0          2m
# prod-collection-service-xxxxxxxxx-xxxxx   1/1     Running   0          2m
```

#### 4.4 Verify Service Health

```bash
# Check service endpoint
kubectl get svc -n ladon prod-collection-service

# Port-forward to test health endpoint
kubectl port-forward -n ladon svc/prod-collection-service 8080:8080 &

# Test health endpoint
curl http://localhost:8080/health

# Expected output:
# {"status":"healthy","timestamp":"2026-01-10T..."}

# Test metrics endpoint
curl http://localhost:8080/metrics

# Kill port-forward
kill %1
```

### Phase 5: Verify Data Collection

#### 5.1 Check Logs

```bash
# View logs from all pods
kubectl logs -n ladon -l app=collection-service --tail=100 -f

# Look for successful collection messages:
# - "AlienVault collector started"
# - "Published X IOCs to raw-ioc-events"
# - "Watermark updated successfully"
```

#### 5.2 Verify Pub/Sub Messages

```bash
# Check Pub/Sub topic message counts
gcloud pubsub topics list-subscriptions raw-ioc-events
gcloud pubsub subscriptions pull normalization-raw-ioc --limit=5

# You should see messages being published
```

#### 5.3 Verify Firestore Watermarks

```bash
# Check watermarks in Firestore
gcloud firestore collections list

# Query watermarks collection
gcloud firestore export gs://${PROJECT_ID}-firestore-export \
  --collection-ids=watermarks

# Or use Firestore console:
# https://console.cloud.google.com/firestore/data/watermarks
```

#### 5.4 Check BigQuery Data

```bash
# Query IOCs table
bq query --use_legacy_sql=false \
  'SELECT source, COUNT(*) as count
   FROM ladon.iocs
   WHERE DATE(first_seen) = CURRENT_DATE()
   GROUP BY source
   ORDER BY count DESC'

# Query activity logs
bq query --use_legacy_sql=false \
  'SELECT source, COUNT(*) as count
   FROM ladon.activity_logs
   WHERE DATE(timestamp) >= CURRENT_DATE()
   GROUP BY source
   ORDER BY count DESC'

# Check threats
bq query --use_legacy_sql=false \
  'SELECT category, COUNT(*) as count
   FROM ladon.threats
   WHERE DATE(first_seen) = CURRENT_DATE()
   GROUP BY category'
```

### Phase 6: Monitor and Validate

#### 6.1 Check HPA Status

```bash
# Check Horizontal Pod Autoscaler
kubectl get hpa -n ladon prod-collection-service-hpa

# Expected output:
# NAME                         REFERENCE                         TARGETS         MINPODS   MAXPODS   REPLICAS   AGE
# prod-collection-service-hpa  Deployment/prod-collection-service 45%/70%        3         10        3          5m
```

#### 6.2 Monitor Resource Usage

```bash
# Check resource usage
kubectl top pods -n ladon -l app=collection-service

# Expected output:
# NAME                                      CPU(cores)   MEMORY(bytes)
# prod-collection-service-xxxxxxxxx-xxxxx   850m         2100Mi
# prod-collection-service-xxxxxxxxx-xxxxx   900m         2300Mi
# prod-collection-service-xxxxxxxxx-xxxxx   820m         2000Mi
```

#### 6.3 Set Up Alerts

```bash
# Create alert policies in GCP Monitoring
# Alert if pod restarts > 3 in 5 minutes
# Alert if memory usage > 85%
# Alert if CPU usage > 90%
# Alert if error rate > 5%
```

### Phase 7: Post-Deployment Tasks

#### 7.1 Update Documentation

- [ ] Document deployed version (v1.0.0)
- [ ] Update runbook with production endpoints
- [ ] Share deployment summary with team

#### 7.2 Configure Monitoring Dashboard

```bash
# Import Grafana dashboard for collection service
# Dashboard includes:
# - Collection rate per source
# - Error rate
# - Watermark lag
# - Resource utilization
# - Pub/Sub publish rate
```

#### 7.3 Test Failure Scenarios

```bash
# Test pod failure recovery
kubectl delete pod -n ladon -l app=collection-service | head -1

# Watch pod recreate
kubectl get pods -n ladon -l app=collection-service -w

# Verify watermarks resume correctly after restart
```

#### 7.4 Schedule First Maintenance Window

- [ ] Plan for first patch release
- [ ] Schedule configuration updates
- [ ] Plan for scaling adjustments based on metrics

---

## Rollback Procedure

If issues are detected after deployment:

### Quick Rollback

```bash
# Rollback to previous version
kubectl rollout undo deployment/prod-collection-service -n ladon

# Check rollback status
kubectl rollout status deployment/prod-collection-service -n ladon
```

### Full Rollback

```bash
# Delete deployment
kubectl delete -k k8s/overlays/production/

# Redeploy previous version
# Update kustomization.yaml with previous image tag
# kubectl apply -k k8s/overlays/production/
```

---

## Troubleshooting

### Pods Not Starting

```bash
# Check pod events
kubectl describe pod -n ladon <pod-name>

# Common issues:
# - ImagePullBackOff: Check image exists in GCR
# - CrashLoopBackOff: Check logs for startup errors
# - Pending: Check resource limits and node capacity
```

### No Data Being Collected

```bash
# Check collector logs
kubectl logs -n ladon -l app=collection-service | grep "collector"

# Check API credentials
kubectl get secret collection-secrets -n ladon -o jsonpath='{.data.ALIENVAULT_API_KEY}' | base64 -d

# Test external API connectivity from pod
kubectl exec -it -n ladon <pod-name> -- curl https://otx.alienvault.com/api/v1/pulses/subscribed
```

### Pub/Sub Not Publishing

```bash
# Check Pub/Sub permissions
gcloud pubsub topics get-iam-policy raw-ioc-events

# Verify Workload Identity
kubectl describe serviceaccount collection-service -n ladon | grep Annotations

# Check for Pub/Sub errors in logs
kubectl logs -n ladon -l app=collection-service | grep "pubsub"
```

### High Memory Usage

```bash
# Check for memory leaks
kubectl top pods -n ladon -l app=collection-service

# Increase memory limit in deployment-patch.yaml if needed
# Then re-apply: kubectl apply -k k8s/overlays/production/
```

---

## Production Checklist

Before considering deployment complete:

- [ ] All pods running and healthy
- [ ] Health endpoint returns 200 OK
- [ ] Metrics endpoint accessible
- [ ] Data flowing to Pub/Sub topics
- [ ] Watermarks updating in Firestore
- [ ] Data appearing in BigQuery tables
- [ ] HPA functioning correctly
- [ ] Logs showing successful collections
- [ ] No errors in last 30 minutes
- [ ] Monitoring dashboard configured
- [ ] Alerts configured
- [ ] Team notified of deployment
- [ ] Documentation updated

---

## Next Steps

After successful deployment:

1. **Monitor for 24 hours** - Watch for any issues or anomalies
2. **Tune collection intervals** - Adjust based on data volume and freshness requirements
3. **Deploy normalization service** - Next service in the pipeline
4. **Deploy storage service** - To persist data to BigQuery
5. **Deploy detection service** - To start correlating IOCs against activities

---

## Support

For issues during deployment:

- **Logs**: `kubectl logs -n ladon -l app=collection-service -f`
- **Slack**: #ladon-deployments
- **On-call**: Page SRE team
- **Runbook**: `/Users/chemch/ladon/docs/runbooks/collection-service.md`
