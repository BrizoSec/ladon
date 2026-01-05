"""Normalization Service - Main FastAPI application."""

import logging
import os
from contextlib import asynccontextmanager
from typing import Dict, Optional

from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel

from .config import NormalizationConfig, PubSubConfig
from .normalization_service import NormalizationService

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# Global service instance
normalization_service: Optional[NormalizationService] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager for startup and shutdown."""
    global normalization_service

    # Startup
    logger.info("Starting Normalization Service")

    # Load configuration
    config = load_config()

    # Create and start service
    normalization_service = NormalizationService(config)
    await normalization_service.start()

    logger.info("Normalization Service started successfully")

    yield

    # Shutdown
    logger.info("Shutting down Normalization Service")
    if normalization_service:
        await normalization_service.stop()
    logger.info("Normalization Service stopped")


# Create FastAPI app
app = FastAPI(
    title="Normalization Service",
    description="Normalizes raw IOCs and activity logs from Pub/Sub",
    version="1.0.0",
    lifespan=lifespan,
)


def load_config() -> NormalizationConfig:
    """Load configuration from environment variables.

    Returns:
        NormalizationConfig instance
    """
    pubsub_config = PubSubConfig(
        project_id=os.getenv("PUBSUB_PROJECT_ID", "ladon-dev"),
        raw_ioc_events_topic=os.getenv(
            "PUBSUB_RAW_IOC_EVENTS_TOPIC", "raw-ioc-events"
        ),
        raw_activity_events_topic=os.getenv(
            "PUBSUB_RAW_ACTIVITY_EVENTS_TOPIC", "raw-activity-events"
        ),
        raw_threat_events_topic=os.getenv(
            "PUBSUB_RAW_THREAT_EVENTS_TOPIC", "raw-threat-events"
        ),
        normalized_ioc_events_topic=os.getenv(
            "PUBSUB_NORMALIZED_IOC_EVENTS_TOPIC", "normalized-ioc-events"
        ),
        normalized_activity_events_topic=os.getenv(
            "PUBSUB_NORMALIZED_ACTIVITY_EVENTS_TOPIC", "normalized-activity-events"
        ),
        normalized_threat_events_topic=os.getenv(
            "PUBSUB_NORMALIZED_THREAT_EVENTS_TOPIC", "normalized-threat-events"
        ),
        ioc_subscription=os.getenv(
            "PUBSUB_IOC_SUBSCRIPTION", "normalization-ioc-sub"
        ),
        activity_subscription=os.getenv(
            "PUBSUB_ACTIVITY_SUBSCRIPTION", "normalization-activity-sub"
        ),
        threat_subscription=os.getenv(
            "PUBSUB_THREAT_SUBSCRIPTION", "normalization-threat-sub"
        ),
    )

    config = NormalizationConfig(
        environment=os.getenv("ENVIRONMENT", "development"),
        log_level=os.getenv("LOG_LEVEL", "INFO"),
        pubsub=pubsub_config,
        strict_validation=os.getenv("STRICT_VALIDATION", "true").lower() == "true",
        skip_invalid_iocs=os.getenv("SKIP_INVALID_IOCS", "true").lower() == "true",
    )

    return config


# Response models
class HealthResponse(BaseModel):
    """Health check response."""

    status: str
    running: bool


class StatusResponse(BaseModel):
    """Service status response."""

    service: str
    running: bool
    processing_tasks: int
    config: Dict


class ProcessingStatsResponse(BaseModel):
    """Processing statistics response."""

    total: int
    success: int
    failed: int


# API Endpoints


@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint.

    Returns:
        Health status
    """
    if not normalization_service:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Service not initialized",
        )

    return HealthResponse(
        status="healthy" if normalization_service.running else "unhealthy",
        running=normalization_service.running,
    )


@app.get("/status", response_model=StatusResponse)
async def get_status():
    """Get detailed service status.

    Returns:
        Detailed status
    """
    if not normalization_service:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Service not initialized",
        )

    status_info = await normalization_service.get_status()
    return StatusResponse(**status_info)


@app.post("/process/ioc", response_model=ProcessingStatsResponse)
async def process_ioc_batch():
    """Trigger one-time processing of IOC messages.

    Returns:
        Processing statistics
    """
    if not normalization_service:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Service not initialized",
        )

    try:
        stats = await normalization_service.process_ioc_batch()
        return ProcessingStatsResponse(**stats)
    except Exception as e:
        logger.error(f"IOC processing failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Processing failed: {str(e)}",
        )


@app.post("/process/activity", response_model=ProcessingStatsResponse)
async def process_activity_batch():
    """Trigger one-time processing of activity messages.

    Returns:
        Processing statistics
    """
    if not normalization_service:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Service not initialized",
        )

    try:
        stats = await normalization_service.process_activity_batch()
        return ProcessingStatsResponse(**stats)
    except Exception as e:
        logger.error(f"Activity processing failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Processing failed: {str(e)}",
        )


@app.post("/process/threat", response_model=ProcessingStatsResponse)
async def process_threat_batch():
    """Trigger one-time processing of threat messages.

    Returns:
        Processing statistics
    """
    if not normalization_service:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Service not initialized",
        )

    try:
        stats = await normalization_service.process_threat_batch()
        return ProcessingStatsResponse(**stats)
    except Exception as e:
        logger.error(f"Threat processing failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Processing failed: {str(e)}",
        )


@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "service": "Normalization Service",
        "version": "1.0.0",
        "description": "Normalizes raw IOCs and activity logs from Pub/Sub",
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8001)
