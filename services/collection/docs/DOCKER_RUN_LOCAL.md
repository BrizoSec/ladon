# Running Collection Service Locally with Docker

Quick guide for testing the Docker image locally before K8s deployment.

---

## Quick Test (No Dependencies)

This runs the service with mock Pub/Sub and storage (no database needed):

```bash
docker run -p 8000:8000 \
  -e COLLECTION_ENVIRONMENT=development \
  -e ALIENVAULT_API_KEY='686e15af1e5e703ddeb452830b34c800c6403ed7d8bc438c9a65ba30ca01274d' \
  collection-service:local
```

**Test it:**
```bash
curl http://localhost:8000/health
# Expected: {"status":"healthy"}

curl http://localhost:8000/docs
# Opens API documentation
```

---

## What "development" Environment Does

When `COLLECTION_ENVIRONMENT=development`:
- ✅ Uses `MockPubSubPublisher` (stores messages in memory, no GCP)
- ✅ Uses mock storage client (no Firestore/BigQuery)
- ✅ Still collects real IOCs from AlienVault/abuse.ch
- ✅ Perfect for testing without infrastructure

**Note:** The Dockerfile now defaults to `COLLECTION_ENVIRONMENT=development` so you don't need to pass it explicitly. The service will automatically use mock services unless you override it with `-e COLLECTION_ENVIRONMENT=production`.

---

## With PostgreSQL (More Realistic)

If you want to test with a real database:

### Step 1: Start PostgreSQL

```bash
docker run -d \
  --name ladon-postgres \
  -e POSTGRES_DB=ladon \
  -e POSTGRES_USER=ladon \
  -e POSTGRES_PASSWORD=ladon123 \
  -p 5432:5432 \
  postgres:16-alpine
```

### Step 2: Run Collection Service

```bash
docker run -p 8000:8000 \
  --link ladon-postgres:postgres \
  -e COLLECTION_ENVIRONMENT=development \
  -e STORAGE_TYPE=postgresql \
  -e POSTGRES_HOST=postgres \
  -e POSTGRES_PORT=5432 \
  -e POSTGRES_DB=ladon \
  -e POSTGRES_USER=ladon \
  -e POSTGRES_PASSWORD=ladon123 \
  -e ALIENVAULT_API_KEY='686e15af1e5e703ddeb452830b34c800c6403ed7d8bc438c9a65ba30ca01274d' \
  collection-service:local
```

### Step 3: Query Database

```bash
docker exec -it ladon-postgres psql -U ladon -d ladon

ladon=# SELECT COUNT(*) FROM iocs;
ladon=# \q
```

### Cleanup

```bash
docker stop ladon-postgres
docker rm ladon-postgres
```

---

## With Docker Compose (Full Stack)

Use the standalone Docker Compose for the full stack:

```bash
cd /Users/chemch/ladon/services/collection

# Start everything
docker-compose -f docker-compose.standalone.yml up -d

# Check logs
docker-compose -f docker-compose.standalone.yml logs -f collection-service

# Stop everything
docker-compose -f docker-compose.standalone.yml down
```

---

## Environment Variables Reference

### Required

| Variable | Description | Example |
|----------|-------------|---------|
| `COLLECTION_ENVIRONMENT` | Environment mode | `development`, `production` |
| `ALIENVAULT_API_KEY` | AlienVault OTX API key | `686e15af...` |

### Optional (for development)

| Variable | Description | Default |
|----------|-------------|---------|
| `ABUSECH_AUTH_KEY` | abuse.ch auth key | None |
| `COLLECTION_LOG_LEVEL` | Log level | `INFO` |
| `ALIENVAULT_PULSES_LIMIT` | Max pulses to fetch | `100` |

### For PostgreSQL

| Variable | Description | Default |
|----------|-------------|---------|
| `STORAGE_TYPE` | Storage backend | `mock` |
| `POSTGRES_HOST` | PostgreSQL host | `localhost` |
| `POSTGRES_PORT` | PostgreSQL port | `5432` |
| `POSTGRES_DB` | Database name | `ladon` |
| `POSTGRES_USER` | Database user | `ladon` |
| `POSTGRES_PASSWORD` | Database password | Required |

---

## Common Issues

### Issue 1: Port Already in Use

**Error:** `Bind for 0.0.0.0:8000 failed: port is already allocated`

**Solution:**
```bash
# Use different port
docker run -p 8001:8000 -e COLLECTION_ENVIRONMENT=development collection-service:local

# Or stop conflicting container
docker ps
docker stop <container-id>
```

### Issue 2: GCP Credentials Error

**Error:** `DefaultCredentialsError: Your default credentials were not found`

**Solution:**
```bash
# Make sure you set COLLECTION_ENVIRONMENT=development
docker run -p 8000:8000 \
  -e COLLECTION_ENVIRONMENT=development \
  collection-service:local
```

### Issue 3: Can't Connect to PostgreSQL

**Error:** `could not translate host name "postgres" to address`

**Solution:**
```bash
# Use --link to connect containers
docker run --link ladon-postgres:postgres ...

# Or use host.docker.internal on Mac/Windows
-e POSTGRES_HOST=host.docker.internal
```

---

## Interactive Shell (Debugging)

```bash
# Start container with shell
docker run -it --entrypoint /bin/bash collection-service:local

# Inside container:
python -c "from src.main import app; print('Imports OK')"
ls -la /app/src/
env | grep COLLECTION
```

---

## View Logs

```bash
# Follow logs
docker logs -f <container-id>

# Last 100 lines
docker logs --tail 100 <container-id>

# Get container ID
docker ps | grep collection-service
```

---

## Performance Testing

```bash
# Run with resource limits
docker run -p 8000:8000 \
  --memory="512m" \
  --cpus="0.5" \
  -e COLLECTION_ENVIRONMENT=development \
  collection-service:local

# Monitor resource usage
docker stats
```

---

## Production Mode (with GCP)

For production with real GCP services:

```bash
docker run -p 8000:8000 \
  -e COLLECTION_ENVIRONMENT=production \
  -e GOOGLE_APPLICATION_CREDENTIALS=/secrets/gcp-key.json \
  -v /path/to/gcp-key.json:/secrets/gcp-key.json:ro \
  -e PUBSUB_PROJECT_ID=your-gcp-project \
  -e ALIENVAULT_API_KEY='your-key' \
  collection-service:local
```

---

## Next Steps

After testing locally:

1. **Deploy to K8s:**
   ```bash
   kubectl apply -f k8s-local/
   ```

2. **Deploy to GCP:**
   - See `GCP_RESOURCE_SETUP_GUIDE.md`

3. **Deploy to PowerEdge:**
   - See `docker-compose.standalone.yml`

---

## Quick Commands

```bash
# Test run (development mode)
docker run -p 8000:8000 -e COLLECTION_ENVIRONMENT=development collection-service:local

# Test health
curl http://localhost:8000/health

# View logs
docker logs -f $(docker ps -q --filter ancestor=collection-service:local)

# Stop
docker stop $(docker ps -q --filter ancestor=collection-service:local)
```
