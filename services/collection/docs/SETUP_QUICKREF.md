# GCP Resource Setup - Quick Reference

Single-page reference for creating GCP resources for Collection Service.

## 🎯 Automated Setup (5 commands)

```bash
cd /Users/chemch/ladon/services/collection

# Run the setup script
./scripts/setup-gcp-resources.sh

# Follow prompts, enter:
# - Project ID (e.g., ladon-production)
# - Region (e.g., us-central1)
# - API keys when prompted

# Verify setup
./scripts/pre-deploy-check.sh production

# If checks pass, deploy
./scripts/deploy.sh production
```

**Time: ~15 minutes**

---

## 📋 What Gets Created

| Resource | Count | Purpose |
|----------|-------|---------|
| Pub/Sub Topics | 6 | Event streaming (raw + normalized) |
| Pub/Sub Subscriptions | 3 | For downstream services |
| Firestore Database | 1 | Watermark storage |
| BigQuery Dataset | 1 | Data warehouse (threat_xdr) |
| BigQuery Tables | 4 | iocs, activity_logs, threats, associations |
| Service Account | 1 | GCP authentication |
| Secrets | 3 | API keys (AlienVault, MISP, Trino) |

---

## 🔑 API Keys Needed

Before running the script, get these:

1. **AlienVault OTX API Key**
   - Sign up: https://otx.alienvault.com/
   - Settings → API Key

2. **MISP API Key**
   - Your MISP instance → Event Actions → Automation
   - Copy authentication key

3. **Trino Password**
   - From your Trino cluster admin

---

## ✅ Pre-Deployment Checklist

Before running the setup:

- [ ] GCP project created
- [ ] Billing enabled on project
- [ ] `gcloud` installed and authenticated (`gcloud auth login`)
- [ ] IAM permissions (roles/owner or roles/editor)
- [ ] API keys gathered (see above)

---

## 🔍 Verification Commands

After setup, verify resources:

```bash
# Check Pub/Sub topics
gcloud pubsub topics list

# Check Firestore
gcloud firestore databases list

# Check BigQuery
bq ls threat_xdr

# Check service account
gcloud iam service-accounts list | grep collection

# Check secrets
gcloud secrets list

# Run automated checks
./scripts/pre-deploy-check.sh production
```

---

## 💰 Estimated Costs

| Service | Monthly Cost |
|---------|-------------|
| Pub/Sub | $10-50 |
| Firestore | $5-20 |
| BigQuery | $50-500 |
| Secret Manager | $1 |
| **Total** | **$66-571** |

*Depends on data volume and query patterns*

---

## 🐛 Common Issues

### "Permission denied"
**Fix**: Ensure you have roles/owner or roles/editor on the project
```bash
gcloud projects get-iam-policy PROJECT_ID
```

### "Billing not enabled"
**Fix**: Enable billing at https://console.cloud.google.com/billing

### "API not enabled"
**Fix**: APIs are auto-enabled by the script. If manual setup:
```bash
gcloud services enable pubsub.googleapis.com
gcloud services enable firestore.googleapis.com
gcloud services enable bigquery.googleapis.com
```

### "Secret already exists"
**Fix**: Update the secret instead of creating:
```bash
echo -n "NEW_VALUE" | gcloud secrets versions add SECRET_NAME --data-file=-
```

---

## 📚 Detailed Guides

- **Full walkthrough**: `GCP_RESOURCE_SETUP_GUIDE.md`
- **Deployment guide**: `DEPLOYMENT_GUIDE.md`
- **Quick deploy**: `DEPLOY_QUICKSTART.md`

---

## 🚀 Next Steps After Setup

1. ✅ Resources created
2. ✅ Pre-deployment checks passed
3. ➡️ Build Docker image
4. ➡️ Deploy to GKE
5. ➡️ Verify data collection

Run: `./scripts/deploy.sh production`
