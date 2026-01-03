"""
Redis cache repository implementation for hot IOC caching.

Implements high-performance caching for frequently accessed IOCs
to enable fast-path detection with <5ms lookup latency.
"""

import json
import logging
from datetime import datetime, timedelta
from typing import Optional

import redis.asyncio as redis
from ladon_models import NormalizedIOC

from ..config import RedisConfig
from .base import CacheRepository

logger = logging.getLogger(__name__)


class RedisIOCCache(CacheRepository):
    """Redis-based cache for hot IOCs."""

    def __init__(self, config: RedisConfig):
        """
        Initialize Redis IOC cache.

        Args:
            config: Redis configuration
        """
        self.config = config
        self.client: Optional[redis.Redis] = None

    async def connect(self):
        """Establish connection to Redis."""
        if self.client is None:
            self.client = redis.Redis(
                host=self.config.host,
                port=self.config.port,
                password=self.config.password,
                db=self.config.db,
                decode_responses=True,
                socket_timeout=self.config.socket_timeout,
                socket_connect_timeout=self.config.socket_connect_timeout,
                max_connections=self.config.max_connections,
            )
            await self.client.ping()
            logger.info(f"Connected to Redis at {self.config.host}:{self.config.port}")

    async def disconnect(self):
        """Close Redis connection."""
        if self.client:
            await self.client.close()
            self.client = None
            logger.info("Disconnected from Redis")

    def _get_ioc_key(self, ioc_value: str, ioc_type: str) -> str:
        """
        Generate Redis key for an IOC.

        Format: ioc:{ioc_type}:{ioc_value}
        Example: ioc:domain:evil.com
        """
        return f"{self.config.ioc_key_prefix}:{ioc_type}:{ioc_value}"

    async def cache_ioc(self, ioc: NormalizedIOC, ttl: Optional[int] = None) -> bool:
        """
        Cache an IOC in Redis for fast lookup.

        Args:
            ioc: IOC to cache
            ttl: Time to live in seconds (defaults to config value)

        Returns:
            True if cached successfully, False otherwise
        """
        if not self.client:
            await self.connect()

        try:
            key = self._get_ioc_key(ioc.ioc_value, ioc.ioc_type.value if hasattr(ioc.ioc_type, "value") else ioc.ioc_type)
            ttl = ttl or self.config.ioc_cache_ttl

            # Serialize IOC to JSON
            ioc_data = {
                "ioc_value": ioc.ioc_value,
                "ioc_type": ioc.ioc_type.value if hasattr(ioc.ioc_type, "value") else ioc.ioc_type,
                "threat_type": ioc.threat_type.value if hasattr(ioc.threat_type, "value") else ioc.threat_type,
                "confidence": ioc.confidence,
                "source": ioc.source.value if hasattr(ioc.source, "value") else ioc.source,
                "first_seen": ioc.first_seen.isoformat(),
                "last_seen": ioc.last_seen.isoformat(),
                "tags": ioc.tags,
                "metadata": ioc.metadata.model_dump() if ioc.metadata else {},
            }

            # Store in Redis with TTL
            await self.client.setex(key, ttl, json.dumps(ioc_data))

            logger.debug(f"Cached IOC: {key} (TTL: {ttl}s)")
            return True

        except Exception as e:
            logger.error(f"Error caching IOC: {e}", exc_info=True)
            return False

    async def get_cached_ioc(
        self, ioc_value: str, ioc_type: str
    ) -> Optional[NormalizedIOC]:
        """
        Retrieve an IOC from cache.

        Args:
            ioc_value: IOC value to lookup
            ioc_type: Type of IOC

        Returns:
            NormalizedIOC if found in cache, None otherwise
        """
        if not self.client:
            await self.connect()

        try:
            key = self._get_ioc_key(ioc_value, ioc_type)
            data = await self.client.get(key)

            if not data:
                logger.debug(f"Cache miss: {key}")
                return None

            # Deserialize from JSON
            ioc_dict = json.loads(data)

            # Convert ISO strings back to datetime
            ioc_dict["first_seen"] = datetime.fromisoformat(ioc_dict["first_seen"])
            ioc_dict["last_seen"] = datetime.fromisoformat(ioc_dict["last_seen"])

            logger.debug(f"Cache hit: {key}")
            return NormalizedIOC(**ioc_dict)

        except Exception as e:
            logger.error(f"Error retrieving cached IOC: {e}", exc_info=True)
            return None

    async def invalidate_ioc(self, ioc_value: str, ioc_type: str) -> bool:
        """
        Remove an IOC from cache.

        Args:
            ioc_value: IOC value to invalidate
            ioc_type: Type of IOC

        Returns:
            True if invalidated, False if not found
        """
        if not self.client:
            await self.connect()

        try:
            key = self._get_ioc_key(ioc_value, ioc_type)
            result = await self.client.delete(key)

            if result > 0:
                logger.info(f"Invalidated cache: {key}")
                return True
            else:
                logger.debug(f"Cache key not found: {key}")
                return False

        except Exception as e:
            logger.error(f"Error invalidating IOC: {e}", exc_info=True)
            return False

    async def warm_cache(
        self, min_confidence: float = 0.7, hours: int = 48
    ) -> int:
        """
        Warm the cache with hot IOCs from BigQuery.

        This method should be called by a separate service/job that
        queries BigQuery for recent high-confidence IOCs and caches them.

        Args:
            min_confidence: Minimum confidence threshold
            hours: How many hours back to fetch IOCs

        Returns:
            Number of IOCs cached

        Note:
            This is a placeholder. The actual implementation would require
            access to the BigQuery repository to fetch IOCs.
        """
        logger.info(
            f"Cache warming requested: min_confidence={min_confidence}, hours={hours}"
        )
        # Actual implementation would:
        # 1. Query BigQuery for IOCs with last_seen > (now - hours) AND confidence >= min_confidence
        # 2. Cache each IOC using cache_ioc()
        # 3. Return count of cached IOCs
        return 0

    async def get_cache_stats(self) -> dict:
        """
        Get cache statistics.

        Returns:
            Dictionary with cache statistics
        """
        if not self.client:
            await self.connect()

        try:
            info = await self.client.info("stats")
            keyspace = await self.client.info("keyspace")

            # Count IOC keys
            cursor = 0
            ioc_count = 0
            while True:
                cursor, keys = await self.client.scan(
                    cursor, match=f"{self.config.ioc_key_prefix}:*", count=100
                )
                ioc_count += len(keys)
                if cursor == 0:
                    break

            return {
                "total_keys": info.get("db0", {}).get("keys", 0),
                "ioc_keys": ioc_count,
                "hits": info.get("keyspace_hits", 0),
                "misses": info.get("keyspace_misses", 0),
                "hit_rate": self._calculate_hit_rate(
                    info.get("keyspace_hits", 0), info.get("keyspace_misses", 0)
                ),
                "used_memory": info.get("used_memory_human", "0"),
                "connected_clients": info.get("connected_clients", 0),
            }

        except Exception as e:
            logger.error(f"Error getting cache stats: {e}", exc_info=True)
            return {}

    def _calculate_hit_rate(self, hits: int, misses: int) -> float:
        """Calculate cache hit rate percentage."""
        total = hits + misses
        if total == 0:
            return 0.0
        return (hits / total) * 100

    async def flush_cache(self) -> bool:
        """
        Flush all IOC keys from cache.

        WARNING: This will clear all IOC cache entries!

        Returns:
            True if successful
        """
        if not self.client:
            await self.connect()

        try:
            # Delete all keys matching the IOC prefix
            cursor = 0
            deleted_count = 0

            while True:
                cursor, keys = await self.client.scan(
                    cursor, match=f"{self.config.ioc_key_prefix}:*", count=100
                )
                if keys:
                    deleted_count += await self.client.delete(*keys)

                if cursor == 0:
                    break

            logger.warning(f"Flushed {deleted_count} IOC keys from cache")
            return True

        except Exception as e:
            logger.error(f"Error flushing cache: {e}", exc_info=True)
            return False

    async def set_expiry(self, ioc_value: str, ioc_type: str, ttl: int) -> bool:
        """
        Update the TTL for a cached IOC.

        Args:
            ioc_value: IOC value
            ioc_type: Type of IOC
            ttl: New time to live in seconds

        Returns:
            True if updated, False if key not found
        """
        if not self.client:
            await self.connect()

        try:
            key = self._get_ioc_key(ioc_value, ioc_type)
            result = await self.client.expire(key, ttl)

            if result:
                logger.debug(f"Updated TTL for {key} to {ttl}s")
                return True
            else:
                logger.debug(f"Key not found: {key}")
                return False

        except Exception as e:
            logger.error(f"Error setting expiry: {e}", exc_info=True)
            return False

    async def get_ttl(self, ioc_value: str, ioc_type: str) -> Optional[int]:
        """
        Get the remaining TTL for a cached IOC.

        Args:
            ioc_value: IOC value
            ioc_type: Type of IOC

        Returns:
            Remaining TTL in seconds, None if key doesn't exist or no TTL
        """
        if not self.client:
            await self.connect()

        try:
            key = self._get_ioc_key(ioc_value, ioc_type)
            ttl = await self.client.ttl(key)

            if ttl == -2:  # Key doesn't exist
                return None
            elif ttl == -1:  # Key exists but has no TTL
                return None
            else:
                return ttl

        except Exception as e:
            logger.error(f"Error getting TTL: {e}", exc_info=True)
            return None
