# How to Build the Collection Service Docker Image

## Quick Build

```bash
# Navigate to repository root
cd /Users/chemch/ladon

# Run the build script
./services/collection/build.sh
```

That's it! The script handles everything.

---

## Manual Build (If Script Fails)

### From Repository Root

```bash
# Navigate to repository root
cd /Users/chemch/ladon

# Build the image
docker build -f services/collection/Dockerfile -t collection-service:local .
```

**Important:** You MUST build from the repository root (`/Users/chemch/ladon`), not from the `services/collection` directory. This is because the Dockerfile needs access to the shared libraries in `libs/python/`.

---

## Why Build from Root?

The Dockerfile needs to copy these shared libraries:
- `libs/python/ladon-common` - Common utilities
- `libs/python/ladon-models` - Data models

Docker can only access files in the build context (the directory you specify), so we build from the repository root to include both `libs/` and `services/collection/`.

---

## Verify Build

```bash
# Check image exists
docker images | grep collection-service

# Expected output:
# collection-service   local   abc123...   2 minutes ago   500MB

# Test run locally
docker run -p 8000:8000 \
  -e ALIENVAULT_API_KEY='your_key' \
  -e COLLECTION_ENVIRONMENT='local' \
  collection-service:local

# In another terminal, test
curl http://localhost:8000/health
```

---

## Troubleshooting

### Issue 1: "libs/python/ladon-common not found"

**Problem:** You're building from the wrong directory.

**Solution:**
```bash
# Wrong (from service directory)
cd /Users/chemch/ladon/services/collection
docker build -t collection-service:local .  # ❌ FAILS

# Right (from repository root)
cd /Users/chemch/ladon
docker build -f services/collection/Dockerfile -t collection-service:local .  # ✅ WORKS
```

### Issue 2: "COPY failed: no source files were specified"

**Problem:** You're not in the repository root.

**Solution:**
```bash
# Check where you are
pwd
# Should output: /Users/chemch/ladon

# If not, navigate there
cd /Users/chemch/ladon
```

### Issue 3: Build Script Permission Denied

**Problem:** Script not executable.

**Solution:**
```bash
chmod +x /Users/chemch/ladon/services/collection/build.sh
```

---

## Advanced: Build with Custom Tag

```bash
# Build with custom image name
IMAGE_NAME=my-collection-service IMAGE_TAG=v1.0.0 ./services/collection/build.sh

# Or manually
docker build -f services/collection/Dockerfile -t my-collection-service:v1.0.0 .
```

---

## For Different Environments

### Local Development (Default)
```bash
./services/collection/build.sh
# Creates: collection-service:local
```

### Push to GCR (Google Container Registry)
```bash
# Build
docker build -f services/collection/Dockerfile -t gcr.io/PROJECT_ID/collection-service:latest .

# Push
docker push gcr.io/PROJECT_ID/collection-service:latest
```

### Push to Docker Hub
```bash
# Build
docker build -f services/collection/Dockerfile -t username/collection-service:latest .

# Login
docker login

# Push
docker push username/collection-service:latest
```

---

## Build for Multiple Platforms (ARM + x86)

```bash
# Create builder
docker buildx create --use

# Build for multiple platforms
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -f services/collection/Dockerfile \
  -t collection-service:multi \
  --load \
  .
```

---

## Clean Up

```bash
# Remove old images
docker rmi collection-service:local

# Clean up build cache
docker builder prune

# Full cleanup (removes all unused images)
docker system prune -a
```

---

## Next Steps

After building:

1. **Test Locally:**
   ```bash
   docker run -p 8000:8000 collection-service:local
   curl http://localhost:8000/health
   ```

2. **Deploy to Local K8s:**
   ```bash
   cd services/collection
   kubectl apply -f k8s-local/
   ```

3. **Deploy to Production:**
   - See `GCP_RESOURCE_SETUP_GUIDE.md` for GCP deployment
   - See `POWEREDGE_SETUP.md` for on-prem deployment

---

## Quick Reference

```bash
# Always start here
cd /Users/chemch/ladon

# Build
./services/collection/build.sh

# Test
docker run -p 8000:8000 collection-service:local

# Deploy to K8s
kubectl apply -f services/collection/k8s-local/
```
