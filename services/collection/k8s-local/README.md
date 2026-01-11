# Local Kubernetes Deployment

This directory contains Kubernetes manifests optimized for **local development** on your laptop.

## Differences from Production

**Simplified:**
- ✅ No GCP dependencies (Pub/Sub, BigQuery, Firestore)
- ✅ PostgreSQL instead of Firestore + BigQuery
- ✅ Local storage (EmptyDir/HostPath)
- ✅ Single replica (not HA)
- ✅ Minimal resources (512MB RAM)

**Perfect for:**
- Development and testing
- Learning Kubernetes
- Validating changes before GCP deployment
- Running on laptop/workstation

## Quick Start

### 1. Build Docker Image Locally

```bash
# From the collection service directory
cd /Users/chemch/ladon/services/collection

# Build the image
docker build -t collection-service:local .

# Verify image exists
docker images | grep collection-service
```

### 2. Create Secrets

```bash
# Create secrets with your API keys
kubectl create secret generic collection-secrets \
  --from-literal=ALIENVAULT_API_KEY='YOUR_ALIENVAULT_KEY' \
  --from-literal=ABUSECH_AUTH_KEY='YOUR_ABUSECH_KEY' \
  --from-literal=POSTGRES_PASSWORD='ladon123' \
  -n ladon-local

# Verify secret created
kubectl get secrets -n ladon-local
```

### 3. Deploy All Services

```bash
# Apply all manifests
kubectl apply -f k8s-local/

# Watch pods come up
kubectl get pods -n ladon-local -w
```

Expected output:
```
NAME                                   READY   STATUS    RESTARTS   AGE
postgres-0                             1/1     Running   0          30s
redis-xxxxx-xxxxx                      1/1     Running   0          30s
collection-service-xxxxx-xxxxx         1/1     Running   0          30s
```

### 4. Access the Service

```bash
# Port forward to localhost
kubectl port-forward -n ladon-local svc/collection-service 8000:8000

# In another terminal, test
curl http://localhost:8000/health

# Expected: {"status":"healthy"}
```

### 5. View Logs

```bash
# Collection service logs
kubectl logs -n ladon-local -l app=collection-service -f

# PostgreSQL logs
kubectl logs -n ladon-local -l app=postgres

# Redis logs
kubectl logs -n ladon-local -l app=redis
```

### 6. Check Database

```bash
# Connect to PostgreSQL
kubectl exec -it -n ladon-local postgres-0 -- psql -U ladon -d ladon

# Query IOCs
ladon=# SELECT source, COUNT(*) FROM iocs GROUP BY source;
ladon=# \q
```

## Troubleshooting

### Pods Not Starting

```bash
# Check pod status
kubectl get pods -n ladon-local

# Describe pod for events
kubectl describe pod -n ladon-local collection-service-xxxxx

# Common issues:
# 1. Image not found → Build locally: docker build -t collection-service:local .
# 2. Secrets not found → Create secrets first
# 3. Resource limits → Increase Docker Desktop memory to 4GB+
```

### Image Pull Errors

If you see `ImagePullBackOff`:

```bash
# Option 1: Build image locally
docker build -t collection-service:local .

# Option 2: Load image into K8s (for Docker Desktop)
docker save collection-service:local | docker load

# Option 3: For Minikube
eval $(minikube docker-env)
docker build -t collection-service:local .
```

### PostgreSQL Connection Errors

```bash
# Check if PostgreSQL is running
kubectl get pods -n ladon-local -l app=postgres

# Check logs
kubectl logs -n ladon-local postgres-0

# Test connection from another pod
kubectl run -it --rm debug --image=postgres:16-alpine --restart=Never -n ladon-local -- \
  psql -h postgres.ladon-local.svc.cluster.local -U ladon -d ladon
```

## Resource Requirements

**Minimum:**
- CPU: 2 cores
- RAM: 4 GB
- Disk: 10 GB

**Recommended:**
- CPU: 4 cores
- RAM: 8 GB
- Disk: 20 GB

### Adjusting Docker Desktop Resources

1. Open Docker Desktop
2. Settings → Resources
3. Set:
   - CPUs: 4
   - Memory: 8 GB
   - Disk: 20 GB
4. Apply & Restart

## Cleanup

```bash
# Delete everything
kubectl delete namespace ladon-local

# Or delete specific resources
kubectl delete -f k8s-local/

# Remove PVCs
kubectl delete pvc -n ladon-local --all
```

## Next Steps

### Add More Features

1. **Add Kafka** (for full pipeline testing)
2. **Add Grafana** (for dashboards)
3. **Add more feeds** (MISP, etc.)

### Migrate to Production

Once tested locally:
1. Use production K8s manifests (`k8s/`)
2. Deploy to GKE or your PowerEdge cluster
3. Enable GCP services (Pub/Sub, BigQuery)

## Files in This Directory

- `00-namespace.yaml` - Namespace for isolation
- `01-postgres.yaml` - PostgreSQL database
- `02-redis.yaml` - Redis cache
- `03-configmap.yaml` - Configuration
- `04-collection-service.yaml` - Main application
- `README.md` - This file
