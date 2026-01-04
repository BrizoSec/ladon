"""Detection engine for correlating IOCs against activity events."""

import ipaddress
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set
from urllib.parse import urlparse

import tldextract
from ladon_models import Detection, NormalizedActivity, NormalizedIOC
from redis import Redis

try:
    from .config import settings
except ImportError:
    from config import settings

logger = logging.getLogger(__name__)


class DetectionEngine:
    """Engine for correlating activity events against IOC cache."""

    def __init__(self, redis_client: Redis):
        """Initialize detection engine.

        Args:
            redis_client: Redis client for IOC cache access
        """
        self.redis = redis_client
        self.enable_subdomain_matching = settings.enable_subdomain_matching
        self.enable_cidr_matching = settings.enable_cidr_matching
        self.enable_url_domain_extraction = settings.enable_url_domain_extraction

    async def correlate_event(self, event: NormalizedActivity) -> List[Detection]:
        """Correlate a single activity event against IOC cache.

        Args:
            event: Normalized activity event

        Returns:
            List of detections (may be empty if no matches)
        """
        detections = []

        # Extract IOC values from event
        ioc_candidates = self._extract_ioc_candidates(event)

        # Check each candidate against cache
        for ioc_value, ioc_type in ioc_candidates:
            matched_iocs = self._check_ioc_cache(ioc_value, ioc_type, event)
            for matched_ioc in matched_iocs:
                detection = self._create_detection(event, matched_ioc)
                detections.append(detection)

        return detections

    async def correlate_batch(self, events: List[NormalizedActivity]) -> List[Detection]:
        """Correlate a batch of activity events.

        Args:
            events: List of normalized activity events

        Returns:
            List of detections
        """
        all_detections = []

        for event in events:
            detections = await self.correlate_event(event)
            all_detections.extend(detections)

        logger.info(
            f"Correlated {len(events)} events, found {len(all_detections)} detections"
        )

        return all_detections

    def _extract_ioc_candidates(
        self, event: NormalizedActivity
    ) -> List[tuple[str, str]]:
        """Extract potential IOC values from activity event.

        Args:
            event: Activity event

        Returns:
            List of (ioc_value, ioc_type) tuples
        """
        candidates = []

        # IP addresses
        if event.src_ip:
            candidates.append((event.src_ip, "ipv4"))
        if event.dst_ip:
            candidates.append((event.dst_ip, "ipv4"))

        # Domains
        if event.domain:
            candidates.append((event.domain, "domain"))

            # Add parent domains for subdomain matching
            if self.enable_subdomain_matching:
                parent_domains = self._get_parent_domains(event.domain)
                for parent in parent_domains:
                    candidates.append((parent, "domain"))

        # URLs
        if event.url:
            candidates.append((event.url, "url"))

            # Extract domain from URL
            if self.enable_url_domain_extraction:
                domain = self._extract_domain_from_url(event.url)
                if domain:
                    candidates.append((domain, "domain"))

        # File hashes
        if event.file_hash:
            # Detect hash type based on length
            hash_type = self._detect_hash_type(event.file_hash)
            if hash_type:
                candidates.append((event.file_hash.lower(), hash_type))

        return candidates

    def _check_ioc_cache(
        self, ioc_value: str, ioc_type: str, event: NormalizedActivity
    ) -> List[NormalizedIOC]:
        """Check if IOC exists in Redis cache.

        Args:
            ioc_value: IOC value to check
            ioc_type: IOC type
            event: Activity event (for CIDR matching)

        Returns:
            List of matched IOCs
        """
        matched_iocs = []

        # Exact match
        # Convert enum to string value if needed
        ioc_type_str = ioc_type.value if hasattr(ioc_type, 'value') else str(ioc_type)
        cache_key = f"{settings.ioc_cache_key_prefix}:{ioc_type_str}:{ioc_value}"
        ioc_data = self.redis.get(cache_key)

        if ioc_data:
            # Parse IOC from cache
            import json
            ioc_dict = json.loads(ioc_data)
            matched_iocs.append(self._dict_to_ioc(ioc_dict))

        # CIDR matching for IPs
        if ioc_type == "ipv4" and self.enable_cidr_matching:
            cidr_matches = self._check_cidr_ranges(ioc_value)
            matched_iocs.extend(cidr_matches)

        return matched_iocs

    def _check_cidr_ranges(self, ip_address: str) -> List[NormalizedIOC]:
        """Check if IP matches any CIDR ranges in cache.

        Args:
            ip_address: IP address to check

        Returns:
            List of matched IOCs from CIDR ranges
        """
        matched_iocs = []

        try:
            ip = ipaddress.ip_address(ip_address)

            # Get all CIDR IOCs from cache
            # Note: In production, you'd want a more efficient data structure
            # like an interval tree or redis geospatial index
            cidr_pattern = f"{settings.ioc_cache_key_prefix}:cidr:*"
            cidr_keys = self.redis.keys(cidr_pattern)

            for key in cidr_keys:
                # Extract CIDR from key
                cidr_str = key.decode().split(":", 2)[2]

                try:
                    network = ipaddress.ip_network(cidr_str)
                    if ip in network:
                        ioc_data = self.redis.get(key)
                        if ioc_data:
                            import json
                            ioc_dict = json.loads(ioc_data)
                            matched_iocs.append(self._dict_to_ioc(ioc_dict))
                except ValueError:
                    logger.warning(f"Invalid CIDR in cache: {cidr_str}")

        except ValueError:
            logger.warning(f"Invalid IP address: {ip_address}")

        return matched_iocs

    def _get_parent_domains(self, domain: str) -> List[str]:
        """Get parent domains for subdomain matching.

        Args:
            domain: Full domain name (e.g., sub.evil.com)

        Returns:
            List of parent domains (e.g., ['evil.com'])
        """
        parent_domains = []

        # Use tldextract to properly parse domain
        extracted = tldextract.extract(domain)

        # Get registered domain (e.g., evil.com)
        registered_domain = f"{extracted.domain}.{extracted.suffix}"
        if registered_domain != domain and extracted.domain:
            parent_domains.append(registered_domain)

        return parent_domains

    def _extract_domain_from_url(self, url: str) -> Optional[str]:
        """Extract domain from URL.

        Args:
            url: Full URL

        Returns:
            Domain or None
        """
        try:
            parsed = urlparse(url)
            return parsed.netloc or None
        except Exception as e:
            logger.warning(f"Failed to parse URL {url}: {e}")
            return None

    def _detect_hash_type(self, hash_value: str) -> Optional[str]:
        """Detect hash type based on length.

        Args:
            hash_value: Hash string

        Returns:
            Hash type (hash_md5, hash_sha1, hash_sha256, hash_sha512) or None
        """
        hash_len = len(hash_value)

        hash_type_map = {
            32: "hash_md5",
            40: "hash_sha1",
            64: "hash_sha256",
            128: "hash_sha512",
        }

        return hash_type_map.get(hash_len)

    def _create_detection(
        self, event: NormalizedActivity, ioc: NormalizedIOC
    ) -> Detection:
        """Create a detection record.

        Args:
            event: Activity event
            ioc: Matched IOC

        Returns:
            Detection record
        """
        detection_id = self._generate_detection_id(event, ioc)

        # Map IOC confidence to initial severity (will be refined by Scoring Service)
        severity = self._map_confidence_to_severity(ioc.confidence)

        detection = Detection(
            detection_id=detection_id,
            timestamp=datetime.now(timezone.utc),
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
            severity=severity,
            confidence=ioc.confidence,
            status="New",  # Use proper enum value
            ioc_value=ioc.ioc_value,
            ioc_type=ioc.ioc_type,
            ioc_source=ioc.source,
            ioc_threat_type=ioc.threat_type,
            ioc_confidence=ioc.confidence,
            activity_event_id=event.event_id,
            activity_source=event.source,
            activity_timestamp=event.timestamp,
            # Activity context
            src_ip=event.src_ip,
            dst_ip=event.dst_ip,
            domain=event.domain,
            url=event.url,
            hostname=event.hostname,
            user=event.user,
            process_name=event.process_name,
            file_hash=event.file_hash,
            # Enrichment placeholder
            enrichment={},
        )

        return detection

    def _map_confidence_to_severity(self, confidence: float) -> str:
        """Map IOC confidence to initial severity level.

        This is a preliminary severity. The Scoring Service will
        calculate the final severity based on additional factors.

        Args:
            confidence: IOC confidence (0.0-1.0)

        Returns:
            Severity level
        """
        if confidence >= 0.9:
            return "CRITICAL"
        elif confidence >= 0.75:
            return "HIGH"
        elif confidence >= 0.5:
            return "MEDIUM"
        else:
            return "LOW"

    def _generate_detection_id(
        self, event: NormalizedActivity, ioc: NormalizedIOC
    ) -> str:
        """Generate unique detection ID.

        Args:
            event: Activity event
            ioc: Matched IOC

        Returns:
            Detection ID
        """
        import hashlib

        # Create deterministic ID from event + IOC
        id_str = f"{event.event_id}:{ioc.ioc_value}:{ioc.source}"
        hash_obj = hashlib.sha256(id_str.encode())
        return f"det_{hash_obj.hexdigest()[:16]}"

    def _dict_to_ioc(self, ioc_dict: dict) -> NormalizedIOC:
        """Convert dict to NormalizedIOC.

        Args:
            ioc_dict: IOC dictionary from cache

        Returns:
            NormalizedIOC instance
        """
        # Parse timestamps
        first_seen = ioc_dict.get("first_seen")
        if first_seen and isinstance(first_seen, str):
            first_seen = datetime.fromisoformat(first_seen)

        last_seen = ioc_dict.get("last_seen")
        if last_seen and isinstance(last_seen, str):
            last_seen = datetime.fromisoformat(last_seen)

        return NormalizedIOC(
            ioc_value=ioc_dict["ioc_value"],
            ioc_type=ioc_dict["ioc_type"],
            threat_type=ioc_dict["threat_type"],
            confidence=ioc_dict["confidence"],
            source=ioc_dict["source"],
            first_seen=first_seen,
            last_seen=last_seen,
            tags=ioc_dict.get("tags", []),
            metadata=ioc_dict.get("metadata", {}),
        )


class IOCCache:
    """Helper class for managing IOC cache operations."""

    def __init__(self, redis_client: Redis):
        """Initialize IOC cache.

        Args:
            redis_client: Redis client
        """
        self.redis = redis_client

    def add_ioc(self, ioc: NormalizedIOC, ttl: int = None) -> bool:
        """Add IOC to cache.

        Args:
            ioc: Normalized IOC
            ttl: Time-to-live in seconds (default: from settings)

        Returns:
            True if added successfully
        """
        if ttl is None:
            ttl = settings.ioc_cache_ttl

        # Create cache key
        # Convert enum to string value if needed
        ioc_type_str = ioc.ioc_type.value if hasattr(ioc.ioc_type, 'value') else str(ioc.ioc_type)
        cache_key = f"{settings.ioc_cache_key_prefix}:{ioc_type_str}:{ioc.ioc_value}"

        # Serialize IOC
        import json

        # Convert metadata to dict if it's a pydantic model
        metadata_dict = ioc.metadata
        if hasattr(ioc.metadata, 'model_dump'):
            metadata_dict = ioc.metadata.model_dump()
        elif hasattr(ioc.metadata, '__dict__'):
            metadata_dict = vars(ioc.metadata)

        # Convert enum values to strings for JSON serialization
        ioc_type_value = ioc.ioc_type.value if hasattr(ioc.ioc_type, 'value') else str(ioc.ioc_type)
        threat_type_value = ioc.threat_type.value if hasattr(ioc.threat_type, 'value') else str(ioc.threat_type)
        source_value = ioc.source.value if hasattr(ioc.source, 'value') else str(ioc.source)

        ioc_data = json.dumps({
            "ioc_value": ioc.ioc_value,
            "ioc_type": ioc_type_value,
            "threat_type": threat_type_value,
            "confidence": ioc.confidence,
            "source": source_value,
            "first_seen": ioc.first_seen.isoformat() if ioc.first_seen else None,
            "last_seen": ioc.last_seen.isoformat() if ioc.last_seen else None,
            "tags": ioc.tags,
            "metadata": metadata_dict,
        })

        # Store in Redis with TTL
        self.redis.setex(cache_key, ttl, ioc_data)

        logger.debug(f"Added IOC to cache: {cache_key}")
        return True

    def get_ioc(self, ioc_value: str, ioc_type: str) -> Optional[NormalizedIOC]:
        """Get IOC from cache.

        Args:
            ioc_value: IOC value
            ioc_type: IOC type

        Returns:
            NormalizedIOC or None
        """
        # Convert enum to string value if needed
        ioc_type_str = ioc_type.value if hasattr(ioc_type, 'value') else str(ioc_type)
        cache_key = f"{settings.ioc_cache_key_prefix}:{ioc_type_str}:{ioc_value}"
        ioc_data = self.redis.get(cache_key)

        if not ioc_data:
            return None

        import json
        ioc_dict = json.loads(ioc_data)

        # Parse timestamps
        first_seen = ioc_dict.get("first_seen")
        if first_seen:
            first_seen = datetime.fromisoformat(first_seen)

        last_seen = ioc_dict.get("last_seen")
        if last_seen:
            last_seen = datetime.fromisoformat(last_seen)

        return NormalizedIOC(
            ioc_value=ioc_dict["ioc_value"],
            ioc_type=ioc_dict["ioc_type"],
            threat_type=ioc_dict["threat_type"],
            confidence=ioc_dict["confidence"],
            source=ioc_dict["source"],
            first_seen=first_seen,
            last_seen=last_seen,
            tags=ioc_dict.get("tags", []),
            metadata=ioc_dict.get("metadata", {}),
        )

    def cache_stats(self) -> Dict[str, int]:
        """Get cache statistics.

        Returns:
            Dict with cache stats
        """
        total_keys = 0
        by_type = {}

        # Get all IOC keys
        pattern = f"{settings.ioc_cache_key_prefix}:*"
        keys = self.redis.keys(pattern)
        total_keys = len(keys)

        # Count by type
        for key in keys:
            parts = key.decode().split(":", 2)
            if len(parts) >= 2:
                ioc_type = parts[1]
                by_type[ioc_type] = by_type.get(ioc_type, 0) + 1

        return {
            "total_iocs": total_keys,
            "by_type": by_type,
        }
