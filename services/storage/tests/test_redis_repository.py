"""Tests for Redis cache repository."""

import json
from datetime import datetime
from unittest.mock import AsyncMock, patch

import pytest

from storage_service.repositories.redis_repository import RedisIOCCache


class TestRedisIOCCache:
    """Tests for Redis IOC cache."""

    @pytest.fixture
    def cache(self, redis_config):
        """Create Redis cache instance."""
        return RedisIOCCache(redis_config)

    @pytest.mark.asyncio
    async def test_connect(self, cache, mock_redis_client):
        """Test connecting to Redis."""
        with patch("storage_service.repositories.redis_repository.redis.Redis") as mock_redis_class:
            mock_redis_class.return_value = mock_redis_client

            await cache.connect()

            assert cache.client is not None
            mock_redis_client.ping.assert_called_once()

    @pytest.mark.asyncio
    async def test_disconnect(self, cache, mock_redis_client):
        """Test disconnecting from Redis."""
        cache.client = mock_redis_client

        await cache.disconnect()

        mock_redis_client.close.assert_called_once()
        assert cache.client is None

    def test_get_ioc_key(self, cache):
        """Test IOC key generation."""
        key = cache._get_ioc_key("evil.com", "domain")

        assert key == "ioc:domain:evil.com"
        assert key.startswith(cache.config.ioc_key_prefix)

    @pytest.mark.asyncio
    async def test_cache_ioc_success(self, cache, sample_ioc, mock_redis_client):
        """Test successfully caching an IOC."""
        cache.client = mock_redis_client
        mock_redis_client.setex.return_value = True

        result = await cache.cache_ioc(sample_ioc)

        assert result is True
        mock_redis_client.setex.assert_called_once()

        # Verify key format
        call_args = mock_redis_client.setex.call_args
        key = call_args[0][0]
        ttl = call_args[0][1]
        data = call_args[0][2]

        assert key == "ioc:domain:evil.com"
        assert ttl == cache.config.ioc_cache_ttl
        assert sample_ioc.ioc_value in data

    @pytest.mark.asyncio
    async def test_cache_ioc_custom_ttl(self, cache, sample_ioc, mock_redis_client):
        """Test caching with custom TTL."""
        cache.client = mock_redis_client

        await cache.cache_ioc(sample_ioc, ttl=7200)

        call_args = mock_redis_client.setex.call_args
        ttl = call_args[0][1]
        assert ttl == 7200

    @pytest.mark.asyncio
    async def test_get_cached_ioc_hit(self, cache, sample_ioc, mock_redis_client):
        """Test cache hit when retrieving IOC."""
        cache.client = mock_redis_client

        # Mock Redis to return cached data
        cached_data = {
            "ioc_value": sample_ioc.ioc_value,
            "ioc_type": sample_ioc.ioc_type.value,
            "threat_type": sample_ioc.threat_type.value,
            "confidence": sample_ioc.confidence,
            "source": sample_ioc.source.value,
            "first_seen": sample_ioc.first_seen.isoformat(),
            "last_seen": sample_ioc.last_seen.isoformat(),
            "tags": sample_ioc.tags,
            "metadata": {},
        }
        mock_redis_client.get.return_value = json.dumps(cached_data)

        result = await cache.get_cached_ioc(sample_ioc.ioc_value, sample_ioc.ioc_type.value)

        assert result is not None
        assert result.ioc_value == sample_ioc.ioc_value
        assert result.confidence == sample_ioc.confidence
        mock_redis_client.get.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_cached_ioc_miss(self, cache, mock_redis_client):
        """Test cache miss when retrieving IOC."""
        cache.client = mock_redis_client
        mock_redis_client.get.return_value = None

        result = await cache.get_cached_ioc("nonexistent.com", "domain")

        assert result is None
        mock_redis_client.get.assert_called_once()

    @pytest.mark.asyncio
    async def test_invalidate_ioc_success(self, cache, mock_redis_client):
        """Test successfully invalidating cached IOC."""
        cache.client = mock_redis_client
        mock_redis_client.delete.return_value = 1

        result = await cache.invalidate_ioc("evil.com", "domain")

        assert result is True
        mock_redis_client.delete.assert_called_once()

    @pytest.mark.asyncio
    async def test_invalidate_ioc_not_found(self, cache, mock_redis_client):
        """Test invalidating non-existent IOC."""
        cache.client = mock_redis_client
        mock_redis_client.delete.return_value = 0

        result = await cache.invalidate_ioc("nonexistent.com", "domain")

        assert result is False

    @pytest.mark.asyncio
    async def test_get_cache_stats(self, cache, mock_redis_client):
        """Test retrieving cache statistics."""
        cache.client = mock_redis_client

        # Mock info responses
        mock_redis_client.info.side_effect = [
            {
                "keyspace_hits": 1000,
                "keyspace_misses": 50,
                "used_memory_human": "2.5M",
                "connected_clients": 10,
            },
            {"db0": {"keys": 150}},
        ]

        # Mock scan for counting IOC keys
        mock_redis_client.scan.return_value = (0, ["ioc:domain:evil1.com", "ioc:domain:evil2.com"])

        stats = await cache.get_cache_stats()

        assert stats["hits"] == 1000
        assert stats["misses"] == 50
        assert stats["hit_rate"] > 90
        assert stats["ioc_keys"] == 2

    @pytest.mark.asyncio
    async def test_flush_cache(self, cache, mock_redis_client):
        """Test flushing all IOC keys."""
        cache.client = mock_redis_client

        # Mock scan to return some IOC keys
        mock_redis_client.scan.return_value = (
            0,
            ["ioc:domain:evil1.com", "ioc:domain:evil2.com", "ioc:ip:192.0.2.1"],
        )
        mock_redis_client.delete.return_value = 3

        result = await cache.flush_cache()

        assert result is True
        mock_redis_client.delete.assert_called()

    @pytest.mark.asyncio
    async def test_set_expiry(self, cache, mock_redis_client):
        """Test updating TTL for cached IOC."""
        cache.client = mock_redis_client
        mock_redis_client.expire.return_value = True

        result = await cache.set_expiry("evil.com", "domain", ttl=3600)

        assert result is True
        mock_redis_client.expire.assert_called_once()
        call_args = mock_redis_client.expire.call_args
        assert call_args[0][1] == 3600

    @pytest.mark.asyncio
    async def test_get_ttl_exists(self, cache, mock_redis_client):
        """Test getting TTL for existing key."""
        cache.client = mock_redis_client
        mock_redis_client.ttl.return_value = 1800

        ttl = await cache.get_ttl("evil.com", "domain")

        assert ttl == 1800

    @pytest.mark.asyncio
    async def test_get_ttl_not_exists(self, cache, mock_redis_client):
        """Test getting TTL for non-existent key."""
        cache.client = mock_redis_client
        mock_redis_client.ttl.return_value = -2  # Key doesn't exist

        ttl = await cache.get_ttl("nonexistent.com", "domain")

        assert ttl is None

    @pytest.mark.asyncio
    async def test_get_ttl_no_expiry(self, cache, mock_redis_client):
        """Test getting TTL for key with no expiration."""
        cache.client = mock_redis_client
        mock_redis_client.ttl.return_value = -1  # Key exists but no TTL

        ttl = await cache.get_ttl("evil.com", "domain")

        assert ttl is None

    def test_calculate_hit_rate(self, cache):
        """Test cache hit rate calculation."""
        rate = cache._calculate_hit_rate(950, 50)
        assert rate == 95.0

        rate = cache._calculate_hit_rate(0, 0)
        assert rate == 0.0

        rate = cache._calculate_hit_rate(100, 0)
        assert rate == 100.0
