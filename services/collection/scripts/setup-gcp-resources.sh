#!/bin/bash
set -e

# GCP Resource Setup Script for Collection Service
# This script creates all required GCP resources for the Collection Service

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

log_error() {
    echo -e "${RED}[✗]${NC} $1"
}

log_step() {
    echo -e "${CYAN}[STEP]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    log_step "Checking prerequisites..."

    if ! command -v gcloud &> /dev/null; then
        log_error "gcloud CLI not found. Please install Google Cloud SDK."
        exit 1
    fi

    if ! command -v bq &> /dev/null; then
        log_error "bq command not found. Please install Google Cloud SDK."
        exit 1
    fi

    log_success "Prerequisites satisfied"
}

# Prompt for configuration
get_configuration() {
    log_step "Configuration"
    echo

    # Project ID
    read -p "Enter GCP Project ID [ladon-production]: " PROJECT_ID
    PROJECT_ID=${PROJECT_ID:-ladon-production}
    export PROJECT_ID

    # Region
    read -p "Enter GCP Region [us-central1]: " REGION
    REGION=${REGION:-us-central1}
    export REGION

    # Dataset location
    read -p "Enter BigQuery Dataset Location [US]: " BQ_LOCATION
    BQ_LOCATION=${BQ_LOCATION:-US}
    export BQ_LOCATION

    # API Keys (will be prompted when creating secrets)
    echo
    log_info "Configuration Summary:"
    echo "  Project ID: $PROJECT_ID"
    echo "  Region: $REGION"
    echo "  BigQuery Location: $BQ_LOCATION"
    echo

    read -p "Continue with this configuration? (yes/no): " -r
    if [[ ! $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
        log_info "Setup cancelled"
        exit 0
    fi
}

# Set GCP project
set_project() {
    log_step "Setting GCP project..."

    if gcloud config set project "$PROJECT_ID" 2>&1; then
        log_success "Project set to: $PROJECT_ID"
    else
        log_error "Failed to set project. Does project $PROJECT_ID exist?"
        log_info "Create project: gcloud projects create $PROJECT_ID"
        exit 1
    fi
}

# Enable required APIs
enable_apis() {
    log_step "Enabling required GCP APIs..."

    APIS=(
        "pubsub.googleapis.com"
        "firestore.googleapis.com"
        "bigquery.googleapis.com"
        "container.googleapis.com"
        "secretmanager.googleapis.com"
        "iam.googleapis.com"
    )

    for api in "${APIS[@]}"; do
        log_info "Enabling $api..."
        if gcloud services enable "$api" --project="$PROJECT_ID" 2>&1; then
            log_success "$api enabled"
        else
            log_warning "Failed to enable $api (may already be enabled)"
        fi
    done

    log_success "All APIs enabled"
}

# Create Pub/Sub topics
create_pubsub_topics() {
    log_step "Creating Pub/Sub topics..."

    TOPICS=(
        "raw-ioc-events"
        "raw-activity-events"
        "raw-threat-events"
        "normalized-ioc-events"
        "normalized-activity-events"
        "normalized-threat-events"
    )

    for topic in "${TOPICS[@]}"; do
        log_info "Creating topic: $topic"
        if gcloud pubsub topics describe "$topic" --project="$PROJECT_ID" &> /dev/null; then
            log_warning "Topic $topic already exists"
        else
            if gcloud pubsub topics create "$topic" --project="$PROJECT_ID"; then
                log_success "Topic created: $topic"
            else
                log_error "Failed to create topic: $topic"
            fi
        fi
    done

    log_success "All Pub/Sub topics created"
}

# Create Pub/Sub subscriptions
create_pubsub_subscriptions() {
    log_step "Creating Pub/Sub subscriptions..."

    # Subscriptions for normalization service (downstream)
    declare -A SUBSCRIPTIONS=(
        ["normalization-raw-ioc"]="raw-ioc-events"
        ["normalization-raw-activity"]="raw-activity-events"
        ["normalization-raw-threat"]="raw-threat-events"
    )

    for sub in "${!SUBSCRIPTIONS[@]}"; do
        topic="${SUBSCRIPTIONS[$sub]}"
        log_info "Creating subscription: $sub -> $topic"

        if gcloud pubsub subscriptions describe "$sub" --project="$PROJECT_ID" &> /dev/null; then
            log_warning "Subscription $sub already exists"
        else
            if gcloud pubsub subscriptions create "$sub" \
                --topic="$topic" \
                --ack-deadline=60 \
                --message-retention-duration=7d \
                --project="$PROJECT_ID"; then
                log_success "Subscription created: $sub"
            else
                log_error "Failed to create subscription: $sub"
            fi
        fi
    done

    log_success "All Pub/Sub subscriptions created"
}

# Create Firestore database
create_firestore() {
    log_step "Creating Firestore database..."

    # Check if Firestore database exists
    if gcloud firestore databases list --project="$PROJECT_ID" --format="value(name)" | grep -q .; then
        log_warning "Firestore database already exists"
    else
        log_info "Creating Firestore database in $REGION..."
        if gcloud firestore databases create \
            --location="$REGION" \
            --project="$PROJECT_ID" \
            --type=firestore-native; then
            log_success "Firestore database created"
        else
            log_error "Failed to create Firestore database"
            exit 1
        fi
    fi
}

# Create BigQuery dataset
create_bigquery_dataset() {
    log_step "Creating BigQuery dataset..."

    if bq show --project_id="$PROJECT_ID" threat_xdr &> /dev/null; then
        log_warning "BigQuery dataset 'threat_xdr' already exists"
    else
        log_info "Creating BigQuery dataset: threat_xdr"
        if bq mk --dataset \
            --location="$BQ_LOCATION" \
            --description="LADON XDR data warehouse" \
            --project_id="$PROJECT_ID" \
            threat_xdr; then
            log_success "BigQuery dataset created: threat_xdr"
        else
            log_error "Failed to create BigQuery dataset"
            exit 1
        fi
    fi
}

# Create BigQuery tables
create_bigquery_tables() {
    log_step "Creating BigQuery tables..."

    # IOCs table
    log_info "Creating table: threat_xdr.iocs"
    if bq show --project_id="$PROJECT_ID" threat_xdr.iocs &> /dev/null; then
        log_warning "Table threat_xdr.iocs already exists"
    else
        bq mk --table \
            --project_id="$PROJECT_ID" \
            --description="Indicators of Compromise from threat intelligence feeds" \
            --time_partitioning_field=first_seen \
            --time_partitioning_type=DAY \
            --clustering_fields=ioc_type,source \
            threat_xdr.iocs \
            ioc_value:STRING,ioc_type:STRING,threat_type:STRING,confidence:FLOAT64,source:STRING,first_seen:TIMESTAMP,last_seen:TIMESTAMP,tags:STRING,metadata:JSON,enrichment:JSON
        log_success "Table created: threat_xdr.iocs"
    fi

    # Activity logs table
    log_info "Creating table: threat_xdr.activity_logs"
    if bq show --project_id="$PROJECT_ID" threat_xdr.activity_logs &> /dev/null; then
        log_warning "Table threat_xdr.activity_logs already exists"
    else
        bq mk --table \
            --project_id="$PROJECT_ID" \
            --description="Activity logs from various sources (Proxy, DNS, MDE, CrowdStrike, Sinkhole)" \
            --time_partitioning_field=timestamp \
            --time_partitioning_type=DAY \
            --clustering_fields=source,event_type \
            threat_xdr.activity_logs \
            event_id:STRING,timestamp:TIMESTAMP,source:STRING,event_type:STRING,src_ip:STRING,dst_ip:STRING,domain:STRING,url:STRING,hostname:STRING,user:STRING,process_name:STRING,file_hash:STRING,enrichment:JSON,raw_event:JSON
        log_success "Table created: threat_xdr.activity_logs"
    fi

    # Threats table
    log_info "Creating table: threat_xdr.threats"
    if bq show --project_id="$PROJECT_ID" threat_xdr.threats &> /dev/null; then
        log_warning "Table threat_xdr.threats already exists"
    else
        bq mk --table \
            --project_id="$PROJECT_ID" \
            --description="Threat actors, campaigns, and malware families" \
            --time_partitioning_field=first_seen \
            --time_partitioning_type=DAY \
            --clustering_fields=category,source \
            threat_xdr.threats \
            threat_id:STRING,name:STRING,category:STRING,description:STRING,source:STRING,first_seen:TIMESTAMP,last_seen:TIMESTAMP,tags:STRING,metadata:JSON
        log_success "Table created: threat_xdr.threats"
    fi

    # Threat-IOC associations table
    log_info "Creating table: threat_xdr.threat_ioc_associations"
    if bq show --project_id="$PROJECT_ID" threat_xdr.threat_ioc_associations &> /dev/null; then
        log_warning "Table threat_xdr.threat_ioc_associations already exists"
    else
        bq mk --table \
            --project_id="$PROJECT_ID" \
            --description="Associations between threats and IOCs" \
            --time_partitioning_field=first_seen \
            --time_partitioning_type=DAY \
            threat_xdr.threat_ioc_associations \
            threat_id:STRING,ioc_value:STRING,ioc_type:STRING,relationship_type:STRING,confidence:FLOAT64,first_seen:TIMESTAMP,last_seen:TIMESTAMP
        log_success "Table created: threat_xdr.threat_ioc_associations"
    fi

    log_success "All BigQuery tables created"
}

# Create service account
create_service_account() {
    log_step "Creating service account..."

    SA_NAME="collection-service"
    SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"

    if gcloud iam service-accounts describe "$SA_EMAIL" --project="$PROJECT_ID" &> /dev/null; then
        log_warning "Service account $SA_EMAIL already exists"
    else
        log_info "Creating service account: $SA_NAME"
        if gcloud iam service-accounts create "$SA_NAME" \
            --display-name="Collection Service" \
            --description="Service account for LADON Collection Service" \
            --project="$PROJECT_ID"; then
            log_success "Service account created: $SA_EMAIL"
        else
            log_error "Failed to create service account"
            exit 1
        fi
    fi

    # Grant IAM roles
    log_info "Granting IAM roles to service account..."

    ROLES=(
        "roles/pubsub.publisher"
        "roles/datastore.user"
        "roles/bigquery.dataEditor"
        "roles/bigquery.jobUser"
        "roles/secretmanager.secretAccessor"
    )

    for role in "${ROLES[@]}"; do
        log_info "Granting role: $role"
        if gcloud projects add-iam-policy-binding "$PROJECT_ID" \
            --member="serviceAccount:${SA_EMAIL}" \
            --role="$role" \
            --condition=None \
            --quiet > /dev/null; then
            log_success "Role granted: $role"
        else
            log_warning "Failed to grant role: $role (may already be granted)"
        fi
    done

    log_success "Service account configured"
}

# Create secrets
create_secrets() {
    log_step "Creating secrets in Secret Manager..."

    echo
    log_info "You'll be prompted to enter API keys and credentials."
    log_info "Press Ctrl+D (EOF) when done entering each secret."
    echo

    SA_EMAIL="collection-service@${PROJECT_ID}.iam.gserviceaccount.com"

    # AlienVault API Key
    log_info "Creating secret: alienvault-api-key"
    if gcloud secrets describe alienvault-api-key --project="$PROJECT_ID" &> /dev/null; then
        log_warning "Secret 'alienvault-api-key' already exists"
        read -p "Update with new value? (yes/no): " -r
        if [[ $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
            echo "Enter AlienVault OTX API key (paste and press Ctrl+D):"
            gcloud secrets versions add alienvault-api-key \
                --data-file=- \
                --project="$PROJECT_ID"
            log_success "Secret updated: alienvault-api-key"
        fi
    else
        echo "Enter AlienVault OTX API key (paste and press Ctrl+D):"
        if gcloud secrets create alienvault-api-key \
            --data-file=- \
            --replication-policy=automatic \
            --project="$PROJECT_ID"; then
            log_success "Secret created: alienvault-api-key"
        fi
    fi

    # Grant access
    gcloud secrets add-iam-policy-binding alienvault-api-key \
        --member="serviceAccount:${SA_EMAIL}" \
        --role="roles/secretmanager.secretAccessor" \
        --project="$PROJECT_ID" \
        --quiet > /dev/null

    # MISP API Key
    log_info "Creating secret: misp-api-key"
    if gcloud secrets describe misp-api-key --project="$PROJECT_ID" &> /dev/null; then
        log_warning "Secret 'misp-api-key' already exists"
        read -p "Update with new value? (yes/no): " -r
        if [[ $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
            echo "Enter MISP API key (paste and press Ctrl+D):"
            gcloud secrets versions add misp-api-key \
                --data-file=- \
                --project="$PROJECT_ID"
            log_success "Secret updated: misp-api-key"
        fi
    else
        echo "Enter MISP API key (paste and press Ctrl+D):"
        if gcloud secrets create misp-api-key \
            --data-file=- \
            --replication-policy=automatic \
            --project="$PROJECT_ID"; then
            log_success "Secret created: misp-api-key"
        fi
    fi

    # Grant access
    gcloud secrets add-iam-policy-binding misp-api-key \
        --member="serviceAccount:${SA_EMAIL}" \
        --role="roles/secretmanager.secretAccessor" \
        --project="$PROJECT_ID" \
        --quiet > /dev/null

    # Trino Password
    log_info "Creating secret: trino-password"
    if gcloud secrets describe trino-password --project="$PROJECT_ID" &> /dev/null; then
        log_warning "Secret 'trino-password' already exists"
        read -p "Update with new value? (yes/no): " -r
        if [[ $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
            echo "Enter Trino password (paste and press Ctrl+D):"
            gcloud secrets versions add trino-password \
                --data-file=- \
                --project="$PROJECT_ID"
            log_success "Secret updated: trino-password"
        fi
    else
        echo "Enter Trino password (paste and press Ctrl+D):"
        if gcloud secrets create trino-password \
            --data-file=- \
            --replication-policy=automatic \
            --project="$PROJECT_ID"; then
            log_success "Secret created: trino-password"
        fi
    fi

    # Grant access
    gcloud secrets add-iam-policy-binding trino-password \
        --member="serviceAccount:${SA_EMAIL}" \
        --role="roles/secretmanager.secretAccessor" \
        --project="$PROJECT_ID" \
        --quiet > /dev/null

    log_success "All secrets created and permissions granted"
}

# Verify all resources
verify_resources() {
    log_step "Verifying all resources..."

    VERIFICATION_PASSED=true

    # Check Pub/Sub topics
    log_info "Verifying Pub/Sub topics..."
    TOPICS=(
        "raw-ioc-events"
        "raw-activity-events"
        "raw-threat-events"
        "normalized-ioc-events"
        "normalized-activity-events"
        "normalized-threat-events"
    )
    for topic in "${TOPICS[@]}"; do
        if gcloud pubsub topics describe "$topic" --project="$PROJECT_ID" &> /dev/null; then
            echo "  ✓ $topic"
        else
            echo "  ✗ $topic"
            VERIFICATION_PASSED=false
        fi
    done

    # Check Firestore
    log_info "Verifying Firestore..."
    if gcloud firestore databases list --project="$PROJECT_ID" --format="value(name)" | grep -q .; then
        echo "  ✓ Firestore database"
    else
        echo "  ✗ Firestore database"
        VERIFICATION_PASSED=false
    fi

    # Check BigQuery dataset
    log_info "Verifying BigQuery dataset..."
    if bq show --project_id="$PROJECT_ID" threat_xdr &> /dev/null; then
        echo "  ✓ threat_xdr dataset"
    else
        echo "  ✗ threat_xdr dataset"
        VERIFICATION_PASSED=false
    fi

    # Check BigQuery tables
    log_info "Verifying BigQuery tables..."
    TABLES=("iocs" "activity_logs" "threats" "threat_ioc_associations")
    for table in "${TABLES[@]}"; do
        if bq show --project_id="$PROJECT_ID" "threat_xdr.$table" &> /dev/null; then
            echo "  ✓ threat_xdr.$table"
        else
            echo "  ✗ threat_xdr.$table"
            VERIFICATION_PASSED=false
        fi
    done

    # Check service account
    log_info "Verifying service account..."
    SA_EMAIL="collection-service@${PROJECT_ID}.iam.gserviceaccount.com"
    if gcloud iam service-accounts describe "$SA_EMAIL" --project="$PROJECT_ID" &> /dev/null; then
        echo "  ✓ $SA_EMAIL"
    else
        echo "  ✗ $SA_EMAIL"
        VERIFICATION_PASSED=false
    fi

    # Check secrets
    log_info "Verifying secrets..."
    SECRETS=("alienvault-api-key" "misp-api-key" "trino-password")
    for secret in "${SECRETS[@]}"; do
        if gcloud secrets describe "$secret" --project="$PROJECT_ID" &> /dev/null; then
            echo "  ✓ $secret"
        else
            echo "  ✗ $secret"
            VERIFICATION_PASSED=false
        fi
    done

    echo
    if [ "$VERIFICATION_PASSED" = true ]; then
        log_success "All resources verified successfully!"
    else
        log_error "Some resources failed verification"
        return 1
    fi
}

# Main execution
main() {
    echo
    echo "========================================"
    echo "  LADON Collection Service Setup"
    echo "  GCP Resource Creation"
    echo "========================================"
    echo

    check_prerequisites
    get_configuration

    echo
    log_info "Starting GCP resource creation..."
    echo

    set_project
    enable_apis
    create_pubsub_topics
    create_pubsub_subscriptions
    create_firestore
    create_bigquery_dataset
    create_bigquery_tables
    create_service_account
    create_secrets

    echo
    verify_resources

    echo
    echo "========================================"
    log_success "Setup Complete!"
    echo "========================================"
    echo
    log_info "Next steps:"
    echo "  1. Review the created resources in GCP Console"
    echo "  2. Run pre-deployment checks:"
    echo "     ./scripts/pre-deploy-check.sh production"
    echo "  3. Deploy the Collection Service:"
    echo "     ./scripts/deploy.sh production"
    echo
}

# Run main function
main
