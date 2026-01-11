# LADON on Local Kubernetes (Laptop)
## Complete Guide for Running on Your Laptop

This guide walks you through running LADON on **Kubernetes on your laptop** (Docker Desktop, Minikube, k3d, etc.).

**Perfect for:**
- Testing before GCP deployment
- Development and debugging
- Learning Kubernetes
- Running without cloud costs

---

## What You'll Get

✅ **Full LADON stack** running locally
✅ **PostgreSQL** (replaces GCP Firestore + BigQuery)
✅ **Redis** for caching
✅ **AlienVault OTX + abuse.ch** threat feeds
✅ **Real-time IOC collection** and storage
✅ **No cloud dependencies** or costs

**Time:** 30 minutes
**Cost:** $0

---

## Prerequisites

### 1. Local Kubernetes

You need **one** of these:

| Option | Best For | Installation |
|--------|----------|--------------|
| **Docker Desktop** | Mac/Windows users | Easiest ⭐ |
| **Minikube** | Cross-platform | Most popular |
| **k3d** | Lightweight | Fast setup |
| **kind** | CI/CD | Docker-based |

**Recommended:** Docker Desktop (if on Mac/Windows)

### 2. Tools

```bash
# Check kubectl
kubectl version --client

# Check Docker
docker --version

# Check cluster is running
kubectl cluster-info
```

### 3. Resources

- **CPU:** 2+ cores
- **RAM:** 4GB+ (8GB recommended)
- **Disk:** 10GB+ free space

---

## Quick Setup Guides

### Option 1: Docker Desktop (Recommended)

**Mac:**
```bash
# Install Docker Desktop
brew install --cask docker

# Open Docker Desktop app
# Settings → Kubernetes → Enable Kubernetes
# Apply & Restart (takes 2-3 minutes)

# Verify
kubectl get nodes
```

**Windows:**
1. Download from: https://www.docker.com/products/docker-desktop/
2. Install and run
3. Settings → Kubernetes → Enable
4. Apply & Restart

### Option 2: Minikube

```bash
# Install
brew install minikube  # Mac
# or: choco install minikube  # Windows
# or: apt install minikube  # Linux

# Start with enough resources
minikube start --memory=8192 --cpus=4

# Verify
kubectl get nodes
```

### Option 3: k3d

```bash
# Install
brew install k3d  # Mac

# Create cluster
k3d cluster create ladon --agents 1

# Verify
kubectl get nodes
```

---

## Deployment Steps

### Step 1: Build Docker Image

```bash
# Navigate to REPOSITORY ROOT (important!)
cd /Users/chemch/ladon

# Build using the script (easiest)
./services/collection/build.sh

# OR build manually
docker build -f services/collection/Dockerfile -t collection-service:local .

# For Minikube users only:
# eval $(minikube docker-env)
# docker build -f services/collection/Dockerfile -t collection-service:local .

# Verify image exists
docker images | grep collection-service
```

**Important:** Build from repository root, not from `services/collection`! See `BUILD_INSTRUCTIONS.md` for why.

### Step 2: Create Namespace & Secrets

```bash
# Create namespace
kubectl create namespace ladon-local

# Create secrets with YOUR API keys
kubectl create secret generic collection-secrets \
  --from-literal=ALIENVAULT_API_KEY='your_actual_alienvault_key_here' \
  --from-literal=ABUSECH_AUTH_KEY='your_actual_abusech_key_here' \
  --from-literal=POSTGRES_PASSWORD='ladon123' \
  -n ladon-local

# Verify
kubectl get secrets -n ladon-local
```

### Step 3: Deploy All Services

```bash
# Deploy everything
kubectl apply -f k8s-local/

# Watch pods starting (this takes 1-2 minutes)
kubectl get pods -n ladon-local -w
```

**Wait for all pods to show `Running`:**
```
NAME                                   READY   STATUS    RESTARTS   AGE
postgres-0                             1/1     Running   0          2m
redis-7c8f9d5b6-xk2np                  1/1     Running   0          2m
collection-service-5d7b8c9f-h4j6m      1/1     Running   0          1m
```

Press `Ctrl+C` to stop watching.

### Step 4: Verify Everything Works

```bash
# Check all resources
kubectl get all -n ladon-local

# Check logs
kubectl logs -n ladon-local -l app=collection-service --tail=50

# Look for these success messages:
# ✅ "Database connection successful"
# ✅ "Redis connection successful"
# ✅ "AlienVault collector initialized"
```

### Step 5: Access the Service

```bash
# Port forward to localhost (keep this terminal open)
kubectl port-forward -n ladon-local svc/collection-service 8000:8000
```

**In a NEW terminal:**
```bash
# Test health
curl http://localhost:8000/health

# Expected: {"status":"healthy","timestamp":"2026-01-10T..."}

# View API docs in browser
open http://localhost:8000/docs
```

### Step 6: Verify Data Collection

```bash
# Trigger manual collection
curl -X POST http://localhost:8000/api/v1/collect/alienvault_otx

# Watch logs
kubectl logs -n ladon-local -l app=collection-service -f

# Look for:
# "Collecting AlienVault OTX pulses..."
# "Fetched X pulses"
# "Extracted Y IOCs"
```

### Step 7: Query Database

```bash
# Connect to PostgreSQL
kubectl exec -it -n ladon-local postgres-0 -- psql -U ladon -d ladon

# Query IOCs
ladon=# SELECT COUNT(*) FROM iocs;
ladon=# SELECT source, COUNT(*) FROM iocs GROUP BY source;
ladon=# SELECT * FROM iocs LIMIT 5;
ladon=# \q
```

---

## What's Deployed

### Architecture

```
┌─────────────────────────────────────────┐
│         Your Laptop (Kubernetes)        │
│                                         │
│  ┌─────────────────┐                   │
│  │   Collection    │─────┐             │
│  │    Service      │     │             │
│  │  (Port 8000)    │     │             │
│  └────────┬────────┘     │             │
│           │              │             │
│           v              v             │
│  ┌─────────────┐   ┌──────────┐       │
│  │  PostgreSQL │   │  Redis   │       │
│  │  (Database) │   │  (Cache) │       │
│  └─────────────┘   └──────────┘       │
│                                         │
└─────────────────────────────────────────┘
         │
         v
  Internet (AlienVault, abuse.ch)
```

### Services

| Service | Purpose | Port | Resource |
|---------|---------|------|----------|
| **collection-service** | Main app | 8000 | 512MB RAM, 0.25 CPU |
| **postgres** | Database | 5432 | 512MB RAM, 0.5 CPU |
| **redis** | Cache | 6379 | 256MB RAM, 0.2 CPU |

**Total:** ~1.3GB RAM, 1 CPU

---

## Common Commands

### Monitoring

```bash
# Watch all pods
kubectl get pods -n ladon-local -w

# Get pod logs (follow)
kubectl logs -n ladon-local -l app=collection-service -f

# Get all logs
kubectl logs -n ladon-local -l app=collection-service --tail=100

# Check resource usage
kubectl top pods -n ladon-local
```

### Debugging

```bash
# Describe pod (see events/errors)
kubectl describe pod -n ladon-local <pod-name>

# Shell into collection service
kubectl exec -it -n ladon-local <collection-pod> -- /bin/sh

# Shell into postgres
kubectl exec -it -n ladon-local postgres-0 -- bash

# Check environment variables
kubectl exec -n ladon-local <pod-name> -- env | sort
```

### Management

```bash
# Restart collection service
kubectl rollout restart deployment/collection-service -n ladon-local

# Scale replicas
kubectl scale deployment/collection-service -n ladon-local --replicas=2

# Delete a pod (auto-recreates)
kubectl delete pod -n ladon-local <pod-name>

# Edit configuration
kubectl edit configmap collection-config -n ladon-local
```

### Cleanup

```bash
# Delete everything
kubectl delete namespace ladon-local

# Or delete specific resources
kubectl delete -f k8s-local/

# Remove persistent volumes
kubectl delete pvc -n ladon-local --all
```

---

## Troubleshooting

### Issue 1: Image Not Found (`ImagePullBackOff`)

**Symptom:** Pod status shows `ImagePullBackOff` or `ErrImagePull`

**Solution:**
```bash
# Check if image exists
docker images | grep collection-service

# If not, build it
docker build -t collection-service:local .

# For Minikube:
eval $(minikube docker-env)
docker build -t collection-service:local .

# For k3d:
k3d image import collection-service:local
```

### Issue 2: Pods Stuck in Pending

**Symptom:** Pods stay in `Pending` state

**Solution:**
```bash
# Check why
kubectl describe pod -n ladon-local <pod-name>

# Common causes:
# 1. Insufficient resources
#    → Increase Docker Desktop memory:
#      Docker Desktop → Settings → Resources → Memory: 8GB

# 2. Storage class not found
kubectl get sc  # Check storage class exists
```

### Issue 3: Collection Service CrashLoopBackOff

**Symptom:** Pod keeps restarting

**Solution:**
```bash
# Check logs
kubectl logs -n ladon-local <pod-name> --previous

# Common causes:
# 1. Missing API key
kubectl get secret collection-secrets -n ladon-local -o yaml

# 2. Can't connect to PostgreSQL
kubectl logs -n ladon-local postgres-0

# 3. Configuration error
kubectl describe configmap collection-config -n ladon-local
```

### Issue 4: "No Space Left on Device"

**Symptom:** Deployment fails with disk space errors

**Solution:**
```bash
# Clean up Docker
docker system prune -a --volumes

# Increase Docker Desktop disk:
# Settings → Resources → Disk image size: 40GB+
```

### Issue 5: PostgreSQL Won't Start

**Symptom:** postgres pod stuck in `CrashLoopBackOff`

**Solution:**
```bash
# Check logs
kubectl logs -n ladon-local postgres-0

# Delete and recreate PVC
kubectl delete pvc -n ladon-local postgres-storage-postgres-0
kubectl delete pod -n ladon-local postgres-0
# Pod will recreate with fresh PVC
```

---

## Performance Optimization

### For Limited Resources

If your laptop struggles, reduce resource usage:

**1. Edit configmap to reduce collection frequency:**
```bash
kubectl edit configmap collection-config -n ladon-local

# Change:
ALIENVAULT_COLLECTION_INTERVAL_MINUTES: "60"  # instead of 30
ALIENVAULT_PULSES_LIMIT: "10"  # instead of 100
```

**2. Reduce pod resources:**
```bash
kubectl edit deployment collection-service -n ladon-local

# Change:
resources:
  requests:
    memory: "256Mi"  # instead of 512Mi
    cpu: "100m"      # instead of 250m
```

**3. Stop when not in use:**
```bash
# Scale to zero
kubectl scale deployment/collection-service -n ladon-local --replicas=0

# Scale back up
kubectl scale deployment/collection-service -n ladon-local --replicas=1
```

---

## What's Different from Production?

| Feature | Local (Laptop) | Production (GCP) |
|---------|----------------|------------------|
| **Database** | PostgreSQL | Firestore + BigQuery |
| **Messaging** | Direct writes | Pub/Sub |
| **Cache** | Redis (256MB) | Memorystore (2GB+) |
| **Storage** | EmptyDir/HostPath | Persistent Disks |
| **High Availability** | No | Yes (multi-zone) |
| **Auto-scaling** | Manual | Automatic |
| **Cost** | $0 | $50-250/month |

---

## Next Steps

### 1. Explore the Data

```bash
# Query IOCs
kubectl exec -it -n ladon-local postgres-0 -- psql -U ladon -d ladon

# Useful queries:
SELECT source, ioc_type, COUNT(*) FROM iocs GROUP BY source, ioc_type;
SELECT * FROM iocs WHERE threat_type = 'ransomware';
SELECT * FROM watermarks;
```

### 2. Add More Feeds

```bash
# Enable abuse.ch more frequently
kubectl set env deployment/collection-service -n ladon-local \
  ABUSECH_COLLECTION_INTERVAL_MINUTES=15
```

### 3. Add Monitoring

Coming soon: Grafana dashboard for local K8s

### 4. Migrate to Production

Once you're happy with local testing:
- Deploy to GKE: Follow `GCP_RESOURCE_SETUP_GUIDE.md`
- Or deploy to PowerEdge: Follow `POWEREDGE_SETUP.md`

---

## Cleanup & Reset

```bash
# Full cleanup (removes everything)
kubectl delete namespace ladon-local

# Or just stop services (keep data)
kubectl scale deployment -n ladon-local --all --replicas=0
kubectl scale statefulset -n ladon-local --all --replicas=0

# Restart later
kubectl scale deployment -n ladon-local --all --replicas=1
kubectl scale statefulset -n ladon-local --all --replicas=1
```

---

## Resources

- **Local K8s manifests:** `k8s-local/README.md`
- **Production K8s:** `k8s/README.md`
- **GCP deployment:** `GCP_RESOURCE_SETUP_GUIDE.md`
- **PowerEdge deployment:** `POWEREDGE_SETUP.md`

---

**You're now running LADON on your laptop! 🚀**

**Questions?** Check `k8s-local/README.md` or open an issue.
