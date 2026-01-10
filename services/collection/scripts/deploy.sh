#!/bin/bash
set -e

# Collection Service Deployment Script
# Usage: ./scripts/deploy.sh [environment]
# Example: ./scripts/deploy.sh production

ENVIRONMENT=${1:-production}
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVICE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."

    # Check kubectl
    if ! command -v kubectl &> /dev/null; then
        log_error "kubectl not found. Please install kubectl."
        exit 1
    fi

    # Check gcloud
    if ! command -v gcloud &> /dev/null; then
        log_error "gcloud not found. Please install Google Cloud SDK."
        exit 1
    fi

    # Check docker
    if ! command -v docker &> /dev/null; then
        log_error "docker not found. Please install Docker."
        exit 1
    fi

    # Check kustomize
    if ! command -v kustomize &> /dev/null; then
        log_warning "kustomize not found. Using kubectl kustomize instead."
    fi

    log_success "All prerequisites satisfied"
}

# Get configuration based on environment
get_config() {
    case $ENVIRONMENT in
        dev|development)
            export PROJECT_ID="ladon-dev"
            export CLUSTER_NAME="ladon-dev-gke"
            export CLUSTER_REGION="us-central1"
            export NAMESPACE="ladon-dev"
            export IMAGE_TAG="dev-latest"
            ;;
        staging)
            export PROJECT_ID="ladon-staging"
            export CLUSTER_NAME="ladon-staging-gke"
            export CLUSTER_REGION="us-central1"
            export NAMESPACE="ladon-staging"
            export IMAGE_TAG="staging-$(git rev-parse --short HEAD)"
            ;;
        prod|production)
            export PROJECT_ID="ladon-production"
            export CLUSTER_NAME="ladon-production-gke"
            export CLUSTER_REGION="us-central1"
            export NAMESPACE="ladon"
            export IMAGE_TAG="v1.0.0"
            ;;
        *)
            log_error "Unknown environment: $ENVIRONMENT"
            log_info "Valid environments: dev, staging, production"
            exit 1
            ;;
    esac

    export IMAGE_NAME="gcr.io/${PROJECT_ID}/collection-service"
    export SA_EMAIL="collection-service@${PROJECT_ID}.iam.gserviceaccount.com"

    log_info "Configuration for environment: $ENVIRONMENT"
    log_info "  Project ID: $PROJECT_ID"
    log_info "  Cluster: $CLUSTER_NAME"
    log_info "  Namespace: $NAMESPACE"
    log_info "  Image: $IMAGE_NAME:$IMAGE_TAG"
}

# Confirm deployment
confirm_deployment() {
    log_warning "You are about to deploy to: $ENVIRONMENT"
    log_info "Image: $IMAGE_NAME:$IMAGE_TAG"

    read -p "Continue with deployment? (yes/no): " -r
    echo
    if [[ ! $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
        log_info "Deployment cancelled"
        exit 0
    fi
}

# Build Docker image
build_image() {
    log_info "Building Docker image..."

    cd "$SERVICE_DIR"

    docker build -t "${IMAGE_NAME}:${IMAGE_TAG}" .

    if [ "$ENVIRONMENT" = "production" ]; then
        docker tag "${IMAGE_NAME}:${IMAGE_TAG}" "${IMAGE_NAME}:latest"
    fi

    log_success "Docker image built successfully"
}

# Push Docker image to GCR
push_image() {
    log_info "Pushing image to GCR..."

    # Configure Docker for GCR
    gcloud auth configure-docker --quiet

    docker push "${IMAGE_NAME}:${IMAGE_TAG}"

    if [ "$ENVIRONMENT" = "production" ]; then
        docker push "${IMAGE_NAME}:latest"
    fi

    log_success "Image pushed to GCR successfully"
}

# Update kustomization with new image tag
update_kustomization() {
    log_info "Updating kustomization.yaml..."

    local overlay_dir="$SERVICE_DIR/k8s/overlays/$ENVIRONMENT"

    if [ ! -d "$overlay_dir" ]; then
        log_error "Overlay directory not found: $overlay_dir"
        exit 1
    fi

    # Update image tag in kustomization.yaml
    cd "$overlay_dir"

    # Backup current kustomization
    cp kustomization.yaml kustomization.yaml.bak

    # Update image tag using sed
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        sed -i '' "s|newTag:.*|newTag: ${IMAGE_TAG}|" kustomization.yaml
    else
        # Linux
        sed -i "s|newTag:.*|newTag: ${IMAGE_TAG}|" kustomization.yaml
    fi

    log_success "Kustomization updated"
}

# Apply Kubernetes manifests
deploy_to_k8s() {
    log_info "Deploying to Kubernetes..."

    # Set kubectl context
    gcloud container clusters get-credentials "$CLUSTER_NAME" \
        --region="$CLUSTER_REGION" \
        --project="$PROJECT_ID"

    # Create namespace if it doesn't exist
    kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -

    # Apply kustomization
    cd "$SERVICE_DIR"
    kubectl apply -k "k8s/overlays/$ENVIRONMENT/"

    log_success "Kubernetes manifests applied"
}

# Wait for rollout to complete
wait_for_rollout() {
    log_info "Waiting for deployment rollout..."

    local deployment_name
    if [ "$ENVIRONMENT" = "production" ]; then
        deployment_name="prod-collection-service"
    elif [ "$ENVIRONMENT" = "staging" ]; then
        deployment_name="staging-collection-service"
    else
        deployment_name="dev-collection-service"
    fi

    kubectl rollout status deployment/"$deployment_name" -n "$NAMESPACE" --timeout=5m

    log_success "Deployment rollout completed"
}

# Verify deployment health
verify_deployment() {
    log_info "Verifying deployment health..."

    # Check pod status
    log_info "Pod status:"
    kubectl get pods -n "$NAMESPACE" -l app=collection-service

    # Check all pods are running
    local ready_pods=$(kubectl get pods -n "$NAMESPACE" -l app=collection-service -o jsonpath='{.items[*].status.containerStatuses[*].ready}' | tr ' ' '\n' | grep -c true || true)
    local total_pods=$(kubectl get pods -n "$NAMESPACE" -l app=collection-service --no-headers | wc -l)

    log_info "Ready pods: $ready_pods/$total_pods"

    if [ "$ready_pods" -eq "$total_pods" ] && [ "$total_pods" -gt 0 ]; then
        log_success "All pods are ready"
    else
        log_error "Not all pods are ready"
        log_info "Checking pod logs..."
        kubectl logs -n "$NAMESPACE" -l app=collection-service --tail=50
        exit 1
    fi

    # Test health endpoint
    log_info "Testing health endpoint..."

    local pod_name=$(kubectl get pods -n "$NAMESPACE" -l app=collection-service -o jsonpath='{.items[0].metadata.name}')

    local health_response=$(kubectl exec -n "$NAMESPACE" "$pod_name" -- curl -s http://localhost:8080/health)

    if echo "$health_response" | grep -q "healthy"; then
        log_success "Health endpoint responding correctly"
    else
        log_error "Health endpoint not responding correctly"
        log_info "Response: $health_response"
        exit 1
    fi
}

# Display post-deployment information
post_deployment_info() {
    log_success "====================================="
    log_success "Deployment completed successfully!"
    log_success "====================================="
    echo
    log_info "Environment: $ENVIRONMENT"
    log_info "Namespace: $NAMESPACE"
    log_info "Image: $IMAGE_NAME:$IMAGE_TAG"
    echo
    log_info "Useful commands:"
    echo "  # View pods"
    echo "  kubectl get pods -n $NAMESPACE -l app=collection-service"
    echo
    echo "  # View logs"
    echo "  kubectl logs -n $NAMESPACE -l app=collection-service -f"
    echo
    echo "  # Check HPA"
    echo "  kubectl get hpa -n $NAMESPACE"
    echo
    echo "  # Port forward to test locally"
    echo "  kubectl port-forward -n $NAMESPACE svc/collection-service 8080:8080"
    echo
    log_info "Next steps:"
    echo "  1. Monitor logs for any errors"
    echo "  2. Verify data is being collected (check Pub/Sub topics)"
    echo "  3. Check Firestore watermarks"
    echo "  4. Query BigQuery tables for new data"
    echo
}

# Rollback function
rollback() {
    log_warning "Rolling back deployment..."

    local deployment_name
    if [ "$ENVIRONMENT" = "production" ]; then
        deployment_name="prod-collection-service"
    elif [ "$ENVIRONMENT" = "staging" ]; then
        deployment_name="staging-collection-service"
    else
        deployment_name="dev-collection-service"
    fi

    kubectl rollout undo deployment/"$deployment_name" -n "$NAMESPACE"

    log_info "Waiting for rollback to complete..."
    kubectl rollout status deployment/"$deployment_name" -n "$NAMESPACE"

    log_success "Rollback completed"
}

# Main deployment flow
main() {
    log_info "Starting deployment of Collection Service"
    log_info "Environment: $ENVIRONMENT"
    echo

    check_prerequisites
    get_config

    if [ "$ENVIRONMENT" = "production" ]; then
        confirm_deployment
    fi

    build_image
    push_image
    update_kustomization
    deploy_to_k8s
    wait_for_rollout
    verify_deployment
    post_deployment_info
}

# Handle script arguments
case "${2:-}" in
    rollback)
        log_info "Rollback requested"
        get_config
        rollback
        ;;
    *)
        main
        ;;
esac
