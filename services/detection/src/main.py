"""Detection Service - FastAPI application."""

import logging
from contextlib import asynccontextmanager
from typing import List

from fastapi import FastAPI, HTTPException
from ladon_models import Detection, NormalizedActivity
from prometheus_client import make_asgi_app
from redis import Redis

from .config import settings
from .detection_engine import DetectionEngine, IOCCache
from .metrics import (
    detection_correlations_total,
    detection_latency_seconds,
    detections_created_total,
    ioc_cache_hits_total,
    ioc_cache_misses_total,
)

# Configure logging
logging.basicConfig(
    level=settings.log_level,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Global instances
redis_client: Redis = None
detection_engine: DetectionEngine = None
ioc_cache: IOCCache = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    global redis_client, detection_engine, ioc_cache

    # Startup
    logger.info(f"Starting Detection Service in {settings.environment} environment")

    # Initialize Redis
    redis_client = Redis(
        host=settings.redis_host,
        port=settings.redis_port,
        db=settings.redis_db,
        password=settings.redis_password,
        ssl=settings.redis_ssl,
        decode_responses=False,  # We'll handle decoding
    )

    # Test Redis connection
    try:
        redis_client.ping()
        logger.info(f"Connected to Redis at {settings.redis_host}:{settings.redis_port}")
    except Exception as e:
        logger.error(f"Failed to connect to Redis: {e}")
        raise

    # Initialize detection engine and cache
    detection_engine = DetectionEngine(redis_client)
    ioc_cache = IOCCache(redis_client)

    logger.info("Detection Service started successfully")

    yield

    # Shutdown
    logger.info("Shutting down Detection Service")
    if redis_client:
        redis_client.close()


# Create FastAPI app
app = FastAPI(
    title="LADON Detection Service",
    description="Real-time IOC correlation and threat detection",
    version="1.0.0",
    lifespan=lifespan,
)

# Mount Prometheus metrics
metrics_app = make_asgi_app()
app.mount("/metrics", metrics_app)


@app.get("/health")
async def health():
    """Health check endpoint."""
    try:
        # Check Redis connection
        redis_client.ping()

        # Get cache stats
        stats = ioc_cache.cache_stats()

        return {
            "status": "healthy",
            "service": "detection",
            "environment": settings.environment,
            "redis_connected": True,
            "cache_stats": stats,
        }
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        raise HTTPException(status_code=503, detail=f"Service unhealthy: {e}")


@app.post("/v1/detect", response_model=List[Detection])
async def detect(events: List[NormalizedActivity]):
    """Correlate activity events against IOC cache.

    Args:
        events: List of normalized activity events

    Returns:
        List of detections
    """
    import time

    start_time = time.time()

    try:
        # Correlate events
        detections = await detection_engine.correlate_batch(events)

        # Record metrics
        detection_correlations_total.inc(len(events))
        detections_created_total.inc(len(detections))
        detection_latency_seconds.observe(time.time() - start_time)

        # Update cache hit/miss metrics
        if detections:
            ioc_cache_hits_total.inc(len(detections))
        else:
            ioc_cache_misses_total.inc(len(events))

        logger.info(
            f"Correlated {len(events)} events, created {len(detections)} detections "
            f"in {(time.time() - start_time) * 1000:.2f}ms"
        )

        return detections

    except Exception as e:
        logger.error(f"Detection failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Detection failed: {e}")


@app.post("/v1/cache/add")
async def add_to_cache(ioc: dict):
    """Add IOC to cache (for testing/manual operations).

    Args:
        ioc: IOC data

    Returns:
        Success status
    """
    try:
        from ladon_models import NormalizedIOC

        # Parse IOC
        ioc_obj = NormalizedIOC(**ioc)

        # Add to cache
        success = ioc_cache.add_ioc(ioc_obj)

        return {"success": success, "ioc_value": ioc_obj.ioc_value}

    except Exception as e:
        logger.error(f"Failed to add IOC to cache: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to add IOC: {e}")


@app.get("/v1/cache/stats")
async def cache_stats():
    """Get IOC cache statistics.

    Returns:
        Cache statistics
    """
    try:
        stats = ioc_cache.cache_stats()
        return stats
    except Exception as e:
        logger.error(f"Failed to get cache stats: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get stats: {e}")


@app.get("/v1/cache/get/{ioc_type}/{ioc_value}")
async def get_from_cache(ioc_type: str, ioc_value: str):
    """Get IOC from cache.

    Args:
        ioc_type: IOC type
        ioc_value: IOC value

    Returns:
        IOC data or 404
    """
    try:
        ioc = ioc_cache.get_ioc(ioc_value, ioc_type)

        if not ioc:
            raise HTTPException(status_code=404, detail="IOC not found in cache")

        return ioc.model_dump()

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get IOC from cache: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get IOC: {e}")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8003,
        reload=True,
        log_level=settings.log_level.lower(),
    )
