"""Collection Service - Main FastAPI application."""

import logging
import os
from contextlib import asynccontextmanager
from typing import Dict, List, Optional

from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel

from .clients.storage_client import MockStorageClient, StorageServiceClient
from .collection_service import CollectionService
from .config import CollectionConfig, PubSubConfig

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# Global service instance
collection_service: Optional[CollectionService] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager for startup and shutdown."""
    global collection_service

    # Startup
    logger.info("Starting Collection Service")

    # Load configuration
    config = load_config()

    # Initialize storage client if URL is provided
    storage_client = None
    if config.storage_service_url:
        logger.info(f"Connecting to Storage Service at {config.storage_service_url}")
        storage_client = StorageServiceClient(
            base_url=config.storage_service_url,
            timeout=30,
            verify_ssl=True,
            environment=config.environment,
            max_connections=100,
            max_connections_per_host=30,
        )

        # Verify connection (raises RuntimeError in production if unhealthy)
        try:
            is_healthy = await storage_client.health_check()
            if is_healthy:
                logger.info("Storage Service connection verified")
            else:
                logger.warning("Storage Service health check failed - watermarks will not persist")
        except RuntimeError as e:
            logger.error(f"Storage Service health check failed in production: {e}")
            raise
    else:
        # Development mode - use mock storage client
        logger.info("No storage service URL provided - using mock storage client")
        storage_client = MockStorageClient()

    # Create and initialize service
    collection_service = CollectionService(config, storage_client)
    await collection_service.initialize()

    # Start collection loops
    await collection_service.start()

    logger.info("Collection Service started successfully")

    yield

    # Shutdown
    logger.info("Shutting down Collection Service")
    if collection_service:
        await collection_service.stop()

    # Close storage client
    if storage_client:
        await storage_client.close()

    logger.info("Collection Service stopped")


# Create FastAPI app
app = FastAPI(
    title="Collection Service",
    description="Collects IOCs and activity logs from multiple data sources",
    version="1.0.0",
    lifespan=lifespan,
)


def load_config() -> CollectionConfig:
    """Load configuration from environment variables or config file.

    Returns:
        CollectionConfig instance
    """
    # For now, create a basic config with Pub/Sub settings
    # In production, this would load from environment variables or config files
    pubsub_config = PubSubConfig(
        project_id=os.getenv("PUBSUB_PROJECT_ID", "ladon-dev"),
        raw_ioc_events_topic=os.getenv(
            "PUBSUB_RAW_IOC_EVENTS_TOPIC", "raw-ioc-events"
        ),
        raw_activity_events_topic=os.getenv(
            "PUBSUB_RAW_ACTIVITY_EVENTS_TOPIC", "raw-activity-events"
        ),
    )

    config = CollectionConfig(
        environment=os.getenv("ENVIRONMENT", "development"),
        log_level=os.getenv("LOG_LEVEL", "INFO"),
        storage_service_url=os.getenv("STORAGE_SERVICE_URL"),
        pubsub=pubsub_config,
        data_sources=[],  # Would load from config file
    )

    return config


# Response models
class HealthResponse(BaseModel):
    """Health check response."""

    status: str
    collectors: Dict[str, bool]


class StatusResponse(BaseModel):
    """Service status response."""

    service: str
    collectors: Dict[str, Dict]
    total_collectors: int
    running_tasks: int


class CollectionResponse(BaseModel):
    """Collection result response."""

    source_id: str
    events_collected: int
    events_failed: int
    batches_processed: int
    duration_seconds: Optional[float]


# API Endpoints


@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint.

    Returns:
        Health status of all collectors
    """
    if not collection_service:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Service not initialized",
        )

    collector_health = await collection_service.health_check()

    # Overall status is healthy if at least one collector is healthy
    overall_status = "healthy" if any(collector_health.values()) else "unhealthy"

    return HealthResponse(status=overall_status, collectors=collector_health)


@app.get("/status", response_model=StatusResponse)
async def get_status():
    """Get detailed service status.

    Returns:
        Detailed status of all collectors
    """
    if not collection_service:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Service not initialized",
        )

    status_info = await collection_service.get_status()
    return StatusResponse(**status_info)


@app.post("/collect/{source_id}", response_model=CollectionResponse)
async def collect_source(source_id: str):
    """Trigger one-time collection for a specific source.

    Args:
        source_id: Data source identifier

    Returns:
        Collection metrics
    """
    if not collection_service:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Service not initialized",
        )

    try:
        metrics = await collection_service.collect_once(source_id)
        return CollectionResponse(source_id=source_id, **metrics)
    except KeyError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Collector '{source_id}' not found",
        )
    except Exception as e:
        logger.error(f"Collection failed for '{source_id}': {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Collection failed: {str(e)}",
        )


@app.post("/collect", response_model=List[CollectionResponse])
async def collect_all():
    """Trigger one-time collection for all sources.

    Returns:
        List of collection metrics for each source
    """
    if not collection_service:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Service not initialized",
        )

    try:
        results = await collection_service.collect_all_once()

        responses = []
        for source_id, metrics in results.items():
            if "error" in metrics:
                logger.error(f"Collection failed for '{source_id}': {metrics['error']}")
                # Skip failed collections in response
                continue

            responses.append(CollectionResponse(source_id=source_id, **metrics))

        return responses

    except Exception as e:
        logger.error(f"Bulk collection failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Bulk collection failed: {str(e)}",
        )


@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "service": "Collection Service",
        "version": "1.0.0",
        "description": "Collects IOCs and activity logs from multiple data sources",
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
