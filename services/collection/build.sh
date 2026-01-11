#!/bin/bash
# Build script for Collection Service Docker image
# This script must be run from the repository root

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}Building LADON Collection Service Docker Image${NC}"
echo "=============================================="

# Check if we're in the right directory
if [ ! -d "libs/python/ladon-common" ]; then
    echo -e "${RED}ERROR: This script must be run from the repository root!${NC}"
    echo ""
    echo "Current directory: $(pwd)"
    echo ""
    echo "Please run:"
    echo "  cd /Users/chemch/ladon"
    echo "  ./services/collection/build.sh"
    exit 1
fi

# Set image name and tag
IMAGE_NAME="${IMAGE_NAME:-collection-service}"
IMAGE_TAG="${IMAGE_TAG:-local}"
FULL_IMAGE="${IMAGE_NAME}:${IMAGE_TAG}"

echo ""
echo "Image: ${FULL_IMAGE}"
echo "Context: $(pwd)"
echo ""

# Build the image
echo -e "${YELLOW}Building Docker image...${NC}"
docker build \
    -f services/collection/Dockerfile \
    -t "${FULL_IMAGE}" \
    .

# Check if build succeeded
if [ $? -eq 0 ]; then
    echo ""
    echo -e "${GREEN}✅ Build successful!${NC}"
    echo ""
    echo "Image: ${FULL_IMAGE}"
    echo ""
    echo "Next steps:"
    echo "  1. Test locally:"
    echo "     docker run -p 8000:8000 ${FULL_IMAGE}"
    echo ""
    echo "  2. Deploy to local K8s:"
    echo "     cd services/collection"
    echo "     kubectl apply -f k8s-local/"
    echo ""
    echo "  3. Push to registry:"
    echo "     docker tag ${FULL_IMAGE} gcr.io/PROJECT_ID/collection-service:latest"
    echo "     docker push gcr.io/PROJECT_ID/collection-service:latest"
else
    echo ""
    echo -e "${RED}❌ Build failed!${NC}"
    exit 1
fi
