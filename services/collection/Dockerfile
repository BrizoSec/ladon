# Collection Service Dockerfile
# NOTE: Build this from the repository root, not from this directory
# Build command: docker build -f services/collection/Dockerfile -t collection-service:local .

FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    curl \
    netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

# Copy shared libraries
COPY libs/python/ladon-common /app/libs/ladon-common
COPY libs/python/ladon-models /app/libs/ladon-models

# Install shared libraries
RUN pip install --no-cache-dir -e /app/libs/ladon-common -e /app/libs/ladon-models

# Copy service files
COPY services/collection/requirements.txt .
COPY services/collection/src/ ./src/
COPY services/collection/config/ ./config/

# Install remaining dependencies (skip editable ones)
RUN grep -v "^-e" requirements.txt > requirements-no-editable.txt && \
    pip install --no-cache-dir -r requirements-no-editable.txt

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app
ENV COLLECTION_ENVIRONMENT=development

# Expose ports
EXPOSE 8000 9090

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Run the service
CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8000"]
