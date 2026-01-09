"""
Unified Storage Service - Main facade for all storage operations.

Provides a single interface to BigQuery, Redis, and Firestore,
implementing the Lambda architecture pattern with fast-path caching
and slow-path analytics.
"""

import logging
from datetime import datetime
from typing import Dict, List, Optional

from ladon_models import Detection, NormalizedActivity, NormalizedIOC, Threat, ThreatIOCAssociation

from .config import StorageConfig
from .repositories.bigquery_repository import (
    BigQueryActivityRepository,
    BigQueryDetectionRepository,
    BigQueryIOCRepository,
    BigQueryThreatRepository,
)
from .repositories.firestore_repository import FirestoreMetadataRepository
from .repositories.redis_repository import RedisIOCCache

logger = logging.getLogger(__name__)


class StorageService:
    """
    Unified storage service providing access to all storage backends.

    This class implements the Facade pattern, providing a simple interface
    to the complex underlying storage infrastructure.
    """

    def __init__(self, config: StorageConfig):
        """
        Initialize Storage Service with all repository implementations.

        Args:
            config: Storage service configuration
        """
        self.config = config

        # Initialize BigQuery repositories
        if config.enable_bigquery:
            self.ioc_repository = BigQueryIOCRepository(config.bigquery)
            self.activity_repository = BigQueryActivityRepository(config.bigquery)
            self.detection_repository = BigQueryDetectionRepository(config.bigquery)
            self.threat_repository = BigQueryThreatRepository(config.bigquery)
            logger.info("BigQuery repositories initialized")
        else:
            self.ioc_repository = None
            self.activity_repository = None
            self.detection_repository = None
            self.threat_repository = None
            logger.warning("BigQuery disabled")

        # Initialize Redis cache
        if config.enable_redis:
            self.ioc_cache = RedisIOCCache(config.redis)
            logger.info("Redis cache initialized")
        else:
            self.ioc_cache = None
            logger.warning("Redis cache disabled")

        # Initialize Firestore metadata repository
        if config.enable_firestore:
            self.metadata_repository = FirestoreMetadataRepository(config.firestore)
            logger.info("Firestore metadata repository initialized")
        else:
            self.metadata_repository = None
            logger.warning("Firestore disabled")

    async def initialize(self):
        """
        Initialize async connections (Redis).

        Call this before using the service.
        """
        if self.ioc_cache:
            await self.ioc_cache.connect()
            logger.info("Storage Service initialized")

    async def cleanup(self):
        """
        Clean up connections.

        Call this when shutting down the service.
        """
        if self.ioc_cache:
            await self.ioc_cache.disconnect()

        if self.metadata_repository:
            self.metadata_repository.close()

        logger.info("Storage Service cleanup complete")

    # ========================================================================
    # IOC Operations
    # ========================================================================

    async def store_ioc(
        self, ioc: NormalizedIOC, cache: bool = True
    ) -> bool:
        """
        Store an IOC in BigQuery and optionally cache in Redis.

        Args:
            ioc: Normalized IOC to store
            cache: Whether to also cache in Redis (default: True)

        Returns:
            True if successful
        """
        # Store in BigQuery
        if self.ioc_repository:
            success = await self.ioc_repository.store_ioc(ioc)

            # Cache in Redis if requested and IOC meets caching criteria
            if success and cache and self.ioc_cache:
                if self._should_cache_ioc(ioc):
                    await self.ioc_cache.cache_ioc(ioc)

            return success

        return False

    async def store_iocs_batch(
        self, iocs: List[NormalizedIOC], cache_hot: bool = True
    ) -> Dict[str, int]:
        """
        Store multiple IOCs in batch and cache hot ones.

        Args:
            iocs: List of normalized IOCs
            cache_hot: Whether to cache high-confidence recent IOCs

        Returns:
            Dictionary with success/failed counts
        """
        if not self.ioc_repository:
            return {"success": 0, "failed": len(iocs)}

        # Store in BigQuery
        result = await self.ioc_repository.store_iocs_batch(iocs)

        # Cache hot IOCs if enabled
        if cache_hot and self.ioc_cache and result["success"] > 0:
            cached_count = 0
            for ioc in iocs:
                if self._should_cache_ioc(ioc):
                    success = await self.ioc_cache.cache_ioc(ioc)
                    if success:
                        cached_count += 1

            logger.info(f"Cached {cached_count}/{result['success']} IOCs")

        return result

    async def get_ioc(
        self, ioc_value: str, ioc_type: str, use_cache: bool = True
    ) -> Optional[NormalizedIOC]:
        """
        Retrieve an IOC, checking cache first if enabled.

        Args:
            ioc_value: IOC value to lookup
            ioc_type: Type of IOC
            use_cache: Whether to check cache first (default: True)

        Returns:
            NormalizedIOC if found, None otherwise
        """
        # Try cache first for fast path
        if use_cache and self.ioc_cache:
            cached_ioc = await self.ioc_cache.get_cached_ioc(ioc_value, ioc_type)
            if cached_ioc:
                logger.debug(f"IOC cache hit: {ioc_value}")
                return cached_ioc

        # Fall back to BigQuery (slow path)
        if self.ioc_repository:
            ioc = await self.ioc_repository.get_ioc(ioc_value, ioc_type)

            # Cache the result if found and meets criteria
            if ioc and self.ioc_cache and self._should_cache_ioc(ioc):
                await self.ioc_cache.cache_ioc(ioc)

            return ioc

        return None

    async def search_iocs(self, **kwargs) -> List[NormalizedIOC]:
        """
        Search for IOCs in BigQuery.

        Args:
            **kwargs: Search criteria (ioc_type, threat_type, source, min_confidence, limit)

        Returns:
            List of matching IOCs
        """
        if self.ioc_repository:
            return await self.ioc_repository.search_iocs(**kwargs)
        return []

    def _should_cache_ioc(self, ioc: NormalizedIOC) -> bool:
        """
        Determine if an IOC should be cached based on recency and confidence.

        Args:
            ioc: IOC to evaluate

        Returns:
            True if should be cached
        """
        if not self.config.enable_redis:
            return False

        # Cache if recent and high confidence
        hours_old = (datetime.utcnow() - ioc.last_seen).total_seconds() / 3600
        is_recent = hours_old <= self.config.redis.hot_ioc_threshold_hours
        is_high_confidence = ioc.confidence >= self.config.redis.hot_ioc_min_confidence

        return is_recent and is_high_confidence

    # ========================================================================
    # Activity Operations
    # ========================================================================

    async def store_activity(self, activity: NormalizedActivity) -> bool:
        """Store a single activity event in BigQuery."""
        if self.activity_repository:
            return await self.activity_repository.store_activity(activity)
        return False

    async def store_activities_batch(
        self, activities: List[NormalizedActivity]
    ) -> Dict[str, int]:
        """Store multiple activity events in batch."""
        if self.activity_repository:
            return await self.activity_repository.store_activities_batch(activities)
        return {"success": 0, "failed": len(activities)}

    async def get_activity(self, event_id: str) -> Optional[NormalizedActivity]:
        """Retrieve a single activity event by ID."""
        if self.activity_repository:
            return await self.activity_repository.get_activity(event_id)
        return None

    async def search_activities(self, **kwargs) -> List[NormalizedActivity]:
        """Search for activity events."""
        if self.activity_repository:
            return await self.activity_repository.search_activities(**kwargs)
        return []

    # ========================================================================
    # Detection Operations
    # ========================================================================

    async def store_detection(self, detection: Detection) -> bool:
        """Store a single detection in BigQuery."""
        if self.detection_repository:
            return await self.detection_repository.store_detection(detection)
        return False

    async def store_detections_batch(
        self, detections: List[Detection]
    ) -> Dict[str, int]:
        """Store multiple detections in batch."""
        if self.detection_repository:
            return await self.detection_repository.store_detections_batch(detections)
        return {"success": 0, "failed": len(detections)}

    async def get_detection(self, detection_id: str) -> Optional[Detection]:
        """Retrieve a single detection by ID."""
        if self.detection_repository:
            return await self.detection_repository.get_detection(detection_id)
        return None

    async def search_detections(self, **kwargs) -> List[Detection]:
        """Search for detections."""
        if self.detection_repository:
            return await self.detection_repository.search_detections(**kwargs)
        return []

    async def update_detection_status(
        self, detection_id: str, status: str, case_id: Optional[str] = None
    ) -> bool:
        """Update detection status and optionally link to ServiceNow case."""
        if self.detection_repository:
            return await self.detection_repository.update_detection_status(
                detection_id, status, case_id
            )
        return False

    # ========================================================================
    # Threat Operations
    # ========================================================================

    async def store_threat(self, threat: Threat) -> bool:
        """Store a single threat in BigQuery.

        Args:
            threat: Threat to store

        Returns:
            True if successful
        """
        if self.threat_repository:
            return await self.threat_repository.store_threat(threat)
        return False

    async def store_threats_batch(
        self, threats: List[Threat]
    ) -> Dict[str, int]:
        """Store multiple threats in batch.

        Args:
            threats: List of threats to store

        Returns:
            Dictionary with success/failed counts
        """
        if self.threat_repository:
            return await self.threat_repository.store_threats_batch(threats)
        return {"success": 0, "failed": len(threats)}

    async def get_threat(self, threat_id: str) -> Optional[Threat]:
        """Retrieve a single threat by ID.

        Args:
            threat_id: Threat ID to lookup

        Returns:
            Threat if found, None otherwise
        """
        if self.threat_repository:
            return await self.threat_repository.get_threat(threat_id)
        return None

    async def get_threats_for_ioc(
        self, ioc_value: str, ioc_type: str
    ) -> List[Threat]:
        """Get all threats associated with an IOC.

        Args:
            ioc_value: IOC value
            ioc_type: IOC type

        Returns:
            List of associated threats
        """
        if self.threat_repository:
            return await self.threat_repository.get_threats_for_ioc(ioc_value, ioc_type)
        return []

    async def get_iocs_for_threat(
        self, threat_id: str, limit: int = 100
    ) -> List[Dict]:
        """Get all IOCs associated with a threat.

        Args:
            threat_id: Threat ID
            limit: Maximum number of IOCs to return

        Returns:
            List of associated IOCs
        """
        if self.threat_repository:
            return await self.threat_repository.get_iocs_for_threat(threat_id, limit)
        return []

    async def associate_ioc_with_threat(
        self, association: ThreatIOCAssociation
    ) -> bool:
        """Associate an IOC with a threat.

        Args:
            association: Threat-IOC association

        Returns:
            True if successful
        """
        if self.threat_repository:
            return await self.threat_repository.associate_ioc_with_threat(association)
        return False

    async def search_threats(self, **kwargs) -> List[Threat]:
        """Search for threats.

        Args:
            **kwargs: Search criteria (threat_category, threat_type, is_active, limit)

        Returns:
            List of matching threats
        """
        if self.threat_repository:
            return await self.threat_repository.search_threats(**kwargs)
        return []

    # ========================================================================
    # Cache Operations
    # ========================================================================

    async def invalidate_ioc_cache(self, ioc_value: str, ioc_type: str) -> bool:
        """Invalidate an IOC from the cache."""
        if self.ioc_cache:
            return await self.ioc_cache.invalidate_ioc(ioc_value, ioc_type)
        return False

    async def get_cache_stats(self) -> Dict:
        """Get Redis cache statistics."""
        if self.ioc_cache:
            return await self.ioc_cache.get_cache_stats()
        return {}

    async def warm_ioc_cache(
        self, min_confidence: float = 0.7, hours: int = 48
    ) -> int:
        """Warm the IOC cache with hot IOCs from BigQuery."""
        if not self.ioc_cache or not self.ioc_repository:
            return 0

        # Get hot IOCs from BigQuery
        iocs = await self.ioc_repository.search_iocs(
            min_confidence=min_confidence, limit=10000
        )

        # Filter by recency and cache
        cached_count = 0
        for ioc in iocs:
            hours_old = (datetime.utcnow() - ioc.last_seen).total_seconds() / 3600
            if hours_old <= hours:
                success = await self.ioc_cache.cache_ioc(ioc)
                if success:
                    cached_count += 1

        logger.info(f"Cache warming complete: {cached_count} IOCs cached")
        return cached_count

    # ========================================================================
    # Metadata Operations
    # ========================================================================

    async def get_watermark(self, source_id: str) -> Optional[Dict]:
        """Get collection watermark for a data source."""
        if self.metadata_repository:
            return await self.metadata_repository.get_watermark(source_id)
        return None

    async def update_watermark(
        self,
        source_id: str,
        timestamp: datetime,
        status: str = "success",
        error_message: Optional[str] = None,
    ) -> bool:
        """Update collection watermark for a data source."""
        if self.metadata_repository:
            return await self.metadata_repository.update_watermark(
                source_id, timestamp, status, error_message
            )
        return False

    async def get_config(self, key: str) -> Optional[Dict]:
        """Get a configuration value."""
        if self.metadata_repository:
            return await self.metadata_repository.get_config(key)
        return None

    async def set_config(self, key: str, value: Dict) -> bool:
        """Set a configuration value."""
        if self.metadata_repository:
            return await self.metadata_repository.set_config(key, value)
        return False

    # ========================================================================
    # Utility Methods
    # ========================================================================

    async def health_check(self) -> Dict[str, bool]:
        """
        Check health of all storage backends.

        Returns:
            Dictionary with health status for each backend
        """
        health = {}

        # Check BigQuery
        if self.ioc_repository:
            try:
                # Simple query to check connectivity
                await self.ioc_repository.search_iocs(limit=1)
                health["bigquery"] = True
            except Exception as e:
                logger.error(f"BigQuery health check failed: {e}")
                health["bigquery"] = False
        else:
            health["bigquery"] = None

        # Check Redis
        if self.ioc_cache:
            try:
                stats = await self.ioc_cache.get_cache_stats()
                health["redis"] = bool(stats)
            except Exception as e:
                logger.error(f"Redis health check failed: {e}")
                health["redis"] = False
        else:
            health["redis"] = None

        # Check Firestore
        if self.metadata_repository:
            try:
                await self.metadata_repository.get_config("_health_check")
                health["firestore"] = True
            except Exception as e:
                logger.error(f"Firestore health check failed: {e}")
                health["firestore"] = False
        else:
            health["firestore"] = None

        return health
