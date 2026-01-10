#!/bin/bash

# Pre-deployment Checklist Script
# Verifies all required GCP resources before deployment

ENVIRONMENT=${1:-production}

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Logging
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[✓]${NC} $1"; }
log_error() { echo -e "${RED}[✗]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[!]${NC} $1"; }

# Configuration
case $ENVIRONMENT in
    production)
        PROJECT_ID="ladon-production"
        CLUSTER_NAME="ladon-production-gke"
        CLUSTER_REGION="us-central1"
        ;;
    staging)
        PROJECT_ID="ladon-staging"
        CLUSTER_NAME="ladon-staging-gke"
        CLUSTER_REGION="us-central1"
        ;;
    dev)
        PROJECT_ID="ladon-dev"
        CLUSTER_NAME="ladon-dev-gke"
        CLUSTER_REGION="us-central1"
        ;;
    *)
        log_error "Unknown environment: $ENVIRONMENT"
        exit 1
        ;;
esac

CHECKS_PASSED=0
CHECKS_FAILED=0

check_passed() {
    log_success "$1"
    ((CHECKS_PASSED++))
}

check_failed() {
    log_error "$1"
    ((CHECKS_FAILED++))
}

log_info "Running pre-deployment checks for: $ENVIRONMENT"
log_info "Project: $PROJECT_ID"
echo

# Check 1: gcloud authenticated
log_info "Checking gcloud authentication..."
if gcloud auth list --filter=status:ACTIVE --format="value(account)" &> /dev/null; then
    check_passed "gcloud authenticated"
else
    check_failed "gcloud not authenticated - run: gcloud auth login"
fi

# Check 2: Project exists and accessible
log_info "Checking GCP project..."
if gcloud projects describe "$PROJECT_ID" &> /dev/null; then
    check_passed "Project $PROJECT_ID exists and is accessible"
else
    check_failed "Project $PROJECT_ID not accessible"
fi

# Check 3: GKE cluster exists
log_info "Checking GKE cluster..."
if gcloud container clusters describe "$CLUSTER_NAME" --region="$CLUSTER_REGION" --project="$PROJECT_ID" &> /dev/null; then
    check_passed "GKE cluster $CLUSTER_NAME exists"
else
    check_failed "GKE cluster $CLUSTER_NAME not found"
fi

# Check 4: Pub/Sub topics exist
log_info "Checking Pub/Sub topics..."
REQUIRED_TOPICS=(
    "raw-ioc-events"
    "raw-activity-events"
    "raw-threat-events"
    "normalized-ioc-events"
    "normalized-activity-events"
    "normalized-threat-events"
)

for topic in "${REQUIRED_TOPICS[@]}"; do
    if gcloud pubsub topics describe "$topic" --project="$PROJECT_ID" &> /dev/null; then
        check_passed "Pub/Sub topic: $topic"
    else
        check_failed "Pub/Sub topic missing: $topic"
        log_info "  Create with: gcloud pubsub topics create $topic"
    fi
done

# Check 5: Firestore database exists
log_info "Checking Firestore..."
if gcloud firestore databases list --project="$PROJECT_ID" --format="value(name)" | grep -q .; then
    check_passed "Firestore database exists"
else
    check_failed "Firestore database not found"
    log_info "  Create with: gcloud firestore databases create --location=us-central1"
fi

# Check 6: BigQuery dataset exists
log_info "Checking BigQuery dataset..."
if bq show --project_id="$PROJECT_ID" threat_xdr &> /dev/null; then
    check_passed "BigQuery dataset: threat_xdr"
else
    check_failed "BigQuery dataset missing: threat_xdr"
    log_info "  Create with: bq mk --dataset threat_xdr"
fi

# Check 7: BigQuery tables exist
log_info "Checking BigQuery tables..."
REQUIRED_TABLES=(
    "iocs"
    "activity_logs"
    "threats"
    "threat_ioc_associations"
)

for table in "${REQUIRED_TABLES[@]}"; do
    if bq show --project_id="$PROJECT_ID" "threat_xdr.$table" &> /dev/null; then
        check_passed "BigQuery table: threat_xdr.$table"
    else
        check_failed "BigQuery table missing: threat_xdr.$table"
    fi
done

# Check 8: Service account exists
log_info "Checking service account..."
SA_EMAIL="collection-service@${PROJECT_ID}.iam.gserviceaccount.com"
if gcloud iam service-accounts describe "$SA_EMAIL" --project="$PROJECT_ID" &> /dev/null; then
    check_passed "Service account: $SA_EMAIL"
else
    check_failed "Service account missing: $SA_EMAIL"
    log_info "  Create with: gcloud iam service-accounts create collection-service"
fi

# Check 9: Required secrets exist
log_info "Checking secrets..."
REQUIRED_SECRETS=(
    "alienvault-api-key"
    "misp-api-key"
    "trino-password"
)

for secret in "${REQUIRED_SECRETS[@]}"; do
    if gcloud secrets describe "$secret" --project="$PROJECT_ID" &> /dev/null; then
        check_passed "Secret: $secret"
    else
        check_failed "Secret missing: $secret"
        log_info "  Create with: gcloud secrets create $secret --data-file=-"
    fi
done

# Check 10: kubectl configured
log_info "Checking kubectl configuration..."
if kubectl config current-context &> /dev/null; then
    check_passed "kubectl configured"
else
    check_failed "kubectl not configured"
    log_info "  Configure with: gcloud container clusters get-credentials $CLUSTER_NAME --region=$CLUSTER_REGION"
fi

# Check 11: Docker daemon running
log_info "Checking Docker..."
if docker ps &> /dev/null; then
    check_passed "Docker daemon running"
else
    check_failed "Docker daemon not running"
fi

# Check 12: GCR access configured
log_info "Checking GCR access..."
if grep -q "gcr.io" ~/.docker/config.json 2>/dev/null; then
    check_passed "Docker configured for GCR"
else
    log_warning "Docker not configured for GCR"
    log_info "  Configure with: gcloud auth configure-docker"
fi

# Summary
echo
echo "======================================"
echo "Pre-deployment Check Summary"
echo "======================================"
log_success "Checks passed: $CHECKS_PASSED"
if [ $CHECKS_FAILED -gt 0 ]; then
    log_error "Checks failed: $CHECKS_FAILED"
    echo
    log_error "Please fix the failed checks before deploying"
    exit 1
else
    log_success "All checks passed!"
    echo
    log_success "Ready to deploy to $ENVIRONMENT"
    echo
    log_info "To deploy, run:"
    echo "  ./scripts/deploy.sh $ENVIRONMENT"
    exit 0
fi
