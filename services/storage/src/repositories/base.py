"""
Abstract base repository interfaces for storage backends.

Defines the contracts that each storage implementation must follow.
"""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Dict, List, Optional

from ladon_models import Detection, NormalizedActivity, NormalizedIOC, Threat, ThreatIOCAssociation


class IOCRepository(ABC):
    """Abstract repository for IOC storage and retrieval."""

    @abstractmethod
    async def store_ioc(self, ioc: NormalizedIOC) -> bool:
        """
        Store a single IOC.

        Args:
            ioc: Normalized IOC to store

        Returns:
            True if successful, False otherwise
        """
        pass

    @abstractmethod
    async def store_iocs_batch(self, iocs: List[NormalizedIOC]) -> Dict[str, int]:
        """
        Store multiple IOCs in a batch operation.

        Args:
            iocs: List of normalized IOCs to store

        Returns:
            Dictionary with counts: {"success": N, "failed": M}
        """
        pass

    @abstractmethod
    async def get_ioc(
        self, ioc_value: str, ioc_type: str
    ) -> Optional[NormalizedIOC]:
        """
        Retrieve a single IOC by value and type.

        Args:
            ioc_value: The IOC value to search for
            ioc_type: The type of IOC

        Returns:
            NormalizedIOC if found, None otherwise
        """
        pass

    @abstractmethod
    async def search_iocs(
        self,
        ioc_type: Optional[str] = None,
        threat_type: Optional[str] = None,
        source: Optional[str] = None,
        min_confidence: Optional[float] = None,
        limit: int = 100,
    ) -> List[NormalizedIOC]:
        """
        Search for IOCs matching criteria.

        Args:
            ioc_type: Filter by IOC type
            threat_type: Filter by threat type
            source: Filter by source
            min_confidence: Minimum confidence score
            limit: Maximum number of results

        Returns:
            List of matching IOCs
        """
        pass

    @abstractmethod
    async def delete_ioc(self, ioc_value: str, ioc_type: str) -> bool:
        """
        Delete an IOC (soft delete by marking inactive).

        Args:
            ioc_value: The IOC value to delete
            ioc_type: The type of IOC

        Returns:
            True if deleted, False if not found
        """
        pass


class ActivityRepository(ABC):
    """Abstract repository for activity log storage and retrieval."""

    @abstractmethod
    async def store_activity(self, activity: NormalizedActivity) -> bool:
        """
        Store a single activity event.

        Args:
            activity: Normalized activity event to store

        Returns:
            True if successful, False otherwise
        """
        pass

    @abstractmethod
    async def store_activities_batch(
        self, activities: List[NormalizedActivity]
    ) -> Dict[str, int]:
        """
        Store multiple activity events in a batch operation.

        Args:
            activities: List of normalized activities to store

        Returns:
            Dictionary with counts: {"success": N, "failed": M}
        """
        pass

    @abstractmethod
    async def get_activity(self, event_id: str) -> Optional[NormalizedActivity]:
        """
        Retrieve a single activity event by ID.

        Args:
            event_id: The event ID to search for

        Returns:
            NormalizedActivity if found, None otherwise
        """
        pass

    @abstractmethod
    async def search_activities(
        self,
        source: Optional[str] = None,
        event_type: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100,
    ) -> List[NormalizedActivity]:
        """
        Search for activity events matching criteria.

        Args:
            source: Filter by source system
            event_type: Filter by event type
            start_time: Start of time range
            end_time: End of time range
            limit: Maximum number of results

        Returns:
            List of matching activities
        """
        pass


class DetectionRepository(ABC):
    """Abstract repository for detection storage and retrieval."""

    @abstractmethod
    async def store_detection(self, detection: Detection) -> bool:
        """
        Store a single detection.

        Args:
            detection: Detection to store

        Returns:
            True if successful, False otherwise
        """
        pass

    @abstractmethod
    async def store_detections_batch(
        self, detections: List[Detection]
    ) -> Dict[str, int]:
        """
        Store multiple detections in a batch operation.

        Args:
            detections: List of detections to store

        Returns:
            Dictionary with counts: {"success": N, "failed": M}
        """
        pass

    @abstractmethod
    async def get_detection(self, detection_id: str) -> Optional[Detection]:
        """
        Retrieve a single detection by ID.

        Args:
            detection_id: The detection ID to search for

        Returns:
            Detection if found, None otherwise
        """
        pass

    @abstractmethod
    async def search_detections(
        self,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100,
    ) -> List[Detection]:
        """
        Search for detections matching criteria.

        Args:
            severity: Filter by severity level
            status: Filter by detection status
            start_time: Start of time range
            end_time: End of time range
            limit: Maximum number of results

        Returns:
            List of matching detections
        """
        pass

    @abstractmethod
    async def update_detection_status(
        self, detection_id: str, status: str, case_id: Optional[str] = None
    ) -> bool:
        """
        Update the status of a detection.

        Args:
            detection_id: The detection ID to update
            status: New status value
            case_id: Optional ServiceNow case ID

        Returns:
            True if updated, False if not found
        """
        pass


class CacheRepository(ABC):
    """Abstract repository for caching hot IOCs."""

    @abstractmethod
    async def cache_ioc(self, ioc: NormalizedIOC, ttl: Optional[int] = None) -> bool:
        """
        Cache an IOC for fast lookup.

        Args:
            ioc: IOC to cache
            ttl: Time to live in seconds (optional)

        Returns:
            True if cached successfully
        """
        pass

    @abstractmethod
    async def get_cached_ioc(
        self, ioc_value: str, ioc_type: str
    ) -> Optional[NormalizedIOC]:
        """
        Retrieve an IOC from cache.

        Args:
            ioc_value: The IOC value to search for
            ioc_type: The type of IOC

        Returns:
            NormalizedIOC if found in cache, None otherwise
        """
        pass

    @abstractmethod
    async def invalidate_ioc(self, ioc_value: str, ioc_type: str) -> bool:
        """
        Remove an IOC from cache.

        Args:
            ioc_value: The IOC value to invalidate
            ioc_type: The type of IOC

        Returns:
            True if invalidated, False if not found
        """
        pass

    @abstractmethod
    async def warm_cache(
        self, min_confidence: float = 0.7, hours: int = 48
    ) -> int:
        """
        Warm the cache with hot IOCs from the database.

        Args:
            min_confidence: Minimum confidence threshold
            hours: How many hours back to fetch IOCs

        Returns:
            Number of IOCs cached
        """
        pass


class MetadataRepository(ABC):
    """Abstract repository for metadata and configuration storage."""

    @abstractmethod
    async def get_watermark(self, source_id: str) -> Optional[Dict]:
        """
        Get the last successful watermark for a data source.

        Args:
            source_id: Identifier for the data source

        Returns:
            Watermark data if found, None otherwise
        """
        pass

    @abstractmethod
    async def update_watermark(
        self, source_id: str, timestamp: datetime, status: str = "success"
    ) -> bool:
        """
        Update the watermark for a data source.

        Args:
            source_id: Identifier for the data source
            timestamp: New watermark timestamp
            status: Status of the collection run

        Returns:
            True if updated successfully
        """
        pass

    @abstractmethod
    async def get_config(self, key: str) -> Optional[Dict]:
        """
        Retrieve a configuration value.

        Args:
            key: Configuration key

        Returns:
            Configuration value if found, None otherwise
        """
        pass

    @abstractmethod
    async def set_config(self, key: str, value: Dict) -> bool:
        """
        Store a configuration value.

        Args:
            key: Configuration key
            value: Configuration value

        Returns:
            True if stored successfully
        """
        pass


class ThreatRepository(ABC):
    """Abstract repository for threat actor/campaign storage and retrieval."""

    @abstractmethod
    async def store_threat(self, threat: Threat) -> bool:
        """
        Store a single threat.

        Args:
            threat: Threat to store

        Returns:
            True if successful, False otherwise
        """
        pass

    @abstractmethod
    async def store_threats_batch(self, threats: List[Threat]) -> Dict[str, int]:
        """
        Store multiple threats in a batch operation.

        Args:
            threats: List of threats to store

        Returns:
            Dictionary with counts: {"success": N, "failed": M}
        """
        pass

    @abstractmethod
    async def get_threat(self, threat_id: str) -> Optional[Threat]:
        """
        Retrieve a single threat by ID.

        Args:
            threat_id: The threat ID to search for

        Returns:
            Threat if found, None otherwise
        """
        pass

    @abstractmethod
    async def search_threats(
        self,
        category: Optional[str] = None,
        threat_type: Optional[str] = None,
        is_active: Optional[bool] = None,
        min_confidence: Optional[float] = None,
        limit: int = 100,
    ) -> List[Threat]:
        """
        Search for threats matching criteria.

        Args:
            category: Filter by category (actor, campaign, malware_family)
            threat_type: Filter by threat type
            is_active: Filter by active status
            min_confidence: Minimum confidence score
            limit: Maximum number of results

        Returns:
            List of matching threats
        """
        pass

    @abstractmethod
    async def associate_ioc_with_threat(
        self, association: ThreatIOCAssociation
    ) -> bool:
        """
        Associate an IOC with a threat.

        Args:
            association: ThreatIOCAssociation model

        Returns:
            True if successful, False otherwise
        """
        pass

    @abstractmethod
    async def get_threats_for_ioc(
        self, ioc_value: str, ioc_type: str
    ) -> List[Threat]:
        """
        Get all threats associated with an IOC.

        Args:
            ioc_value: The IOC value
            ioc_type: The IOC type

        Returns:
            List of associated threats
        """
        pass

    @abstractmethod
    async def get_iocs_for_threat(
        self, threat_id: str, limit: int = 100
    ) -> List[Dict]:
        """
        Get all IOCs associated with a threat.

        Args:
            threat_id: The threat ID
            limit: Maximum number of IOCs to return

        Returns:
            List of IOC associations
        """
        pass

    @abstractmethod
    async def update_threat(self, threat_id: str, updates: Dict) -> bool:
        """
        Update a threat's fields.

        Args:
            threat_id: The threat ID to update
            updates: Dictionary of fields to update

        Returns:
            True if updated, False if not found
        """
        pass
