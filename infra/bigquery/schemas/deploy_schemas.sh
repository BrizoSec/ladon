#!/bin/bash
# =============================================================================
# BigQuery Schema Deployment Script
# Description: Deploys threat intelligence tables to BigQuery
# Usage: ./deploy_schemas.sh PROJECT_ID [DATASET]
# =============================================================================

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
PROJECT_ID="${1}"
DATASET="${2:-threat_xdr}"
LOCATION="${3:-US}"

# Validate inputs
if [ -z "$PROJECT_ID" ]; then
    echo -e "${RED}Error: PROJECT_ID is required${NC}"
    echo "Usage: $0 PROJECT_ID [DATASET] [LOCATION]"
    echo "Example: $0 my-gcp-project threat_xdr US"
    exit 1
fi

echo -e "${GREEN}==============================================================================${NC}"
echo -e "${GREEN}BigQuery Threat Intelligence Schema Deployment${NC}"
echo -e "${GREEN}==============================================================================${NC}"
echo ""
echo "Project ID: $PROJECT_ID"
echo "Dataset:    $DATASET"
echo "Location:   $LOCATION"
echo ""

# Check if bq CLI is installed
if ! command -v bq &> /dev/null; then
    echo -e "${RED}Error: 'bq' command not found. Please install Google Cloud SDK.${NC}"
    exit 1
fi

# Check if user is authenticated
if ! gcloud auth list --filter=status:ACTIVE --format="value(account)" &> /dev/null; then
    echo -e "${YELLOW}Warning: Not authenticated to Google Cloud${NC}"
    echo "Please run: gcloud auth login"
    exit 1
fi

# Set project
echo -e "${YELLOW}Setting active project...${NC}"
gcloud config set project "$PROJECT_ID"

# Create dataset if it doesn't exist
echo -e "${YELLOW}Creating dataset (if not exists)...${NC}"
bq mk \
    --dataset \
    --location="$LOCATION" \
    --description="LADON Threat XDR Platform - Threat Intelligence and IOC Storage" \
    --label="service:ladon-threat-xdr" \
    --label="managed_by:script" \
    "${PROJECT_ID}:${DATASET}" 2>/dev/null || echo "Dataset already exists"

# Function to replace placeholder in SQL files
replace_placeholders() {
    local file=$1
    sed "s/threat_xdr/${DATASET}/g" "$file"
}

# Deploy threats table
echo ""
echo -e "${YELLOW}Deploying 'threats' table...${NC}"
if replace_placeholders "threats.sql" | bq query \
    --use_legacy_sql=false \
    --project_id="$PROJECT_ID"; then
    echo -e "${GREEN}✓ 'threats' table deployed successfully${NC}"
else
    echo -e "${RED}✗ Failed to deploy 'threats' table${NC}"
    exit 1
fi

# Deploy threat_ioc_associations table
echo ""
echo -e "${YELLOW}Deploying 'threat_ioc_associations' table...${NC}"
if replace_placeholders "threat_ioc_associations.sql" | bq query \
    --use_legacy_sql=false \
    --project_id="$PROJECT_ID"; then
    echo -e "${GREEN}✓ 'threat_ioc_associations' table deployed successfully${NC}"
else
    echo -e "${RED}✗ Failed to deploy 'threat_ioc_associations' table${NC}"
    exit 1
fi

# Verify tables exist
echo ""
echo -e "${YELLOW}Verifying table deployment...${NC}"
TABLES=$(bq ls --max_results=100 "${PROJECT_ID}:${DATASET}" | grep -E "threats|threat_ioc" | wc -l)

if [ "$TABLES" -ge 2 ]; then
    echo -e "${GREEN}✓ All tables verified${NC}"
else
    echo -e "${RED}✗ Table verification failed${NC}"
    exit 1
fi

# Show table information
echo ""
echo -e "${YELLOW}Table Information:${NC}"
echo ""
bq show "${PROJECT_ID}:${DATASET}.threats" | head -20
echo ""
bq show "${PROJECT_ID}:${DATASET}.threat_ioc_associations" | head -20

# Summary
echo ""
echo -e "${GREEN}==============================================================================${NC}"
echo -e "${GREEN}Deployment Complete!${NC}"
echo -e "${GREEN}==============================================================================${NC}"
echo ""
echo "Tables deployed:"
echo "  ✓ ${PROJECT_ID}:${DATASET}.threats"
echo "  ✓ ${PROJECT_ID}:${DATASET}.threat_ioc_associations"
echo ""
echo "Views created:"
echo "  ✓ ${PROJECT_ID}:${DATASET}.active_threats"
echo "  ✓ ${PROJECT_ID}:${DATASET}.apt_threats"
echo "  ✓ ${PROJECT_ID}:${DATASET}.high_confidence_associations"
echo "  ✓ ${PROJECT_ID}:${DATASET}.ioc_threat_lookup"
echo ""
echo "Materialized views:"
echo "  ✓ ${PROJECT_ID}:${DATASET}.threat_stats_mv"
echo "  ✓ ${PROJECT_ID}:${DATASET}.threat_ioc_stats_mv"
echo ""
echo "Next steps:"
echo "  1. Grant appropriate IAM permissions to services"
echo "  2. Configure Storage Service to use these tables"
echo "  3. Update Collection Service to extract threat data"
echo "  4. Test with sample threat data"
echo ""
echo "Sample query:"
echo "  bq query --use_legacy_sql=false 'SELECT * FROM \`${PROJECT_ID}.${DATASET}.active_threats\` LIMIT 10'"
echo ""
