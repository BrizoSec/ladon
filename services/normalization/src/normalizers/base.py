"""Base normalizer interface for data transformation."""

import logging
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Dict, List, Optional

from ladon_models import NormalizedActivity, NormalizedIOC

logger = logging.getLogger(__name__)


class NormalizationMetrics:
    """Tracks normalization metrics for observability."""

    def __init__(self):
        self.events_normalized = 0
        self.events_failed = 0
        self.validation_errors: List[str] = []
        self.start_time: Optional[datetime] = None
        self.end_time: Optional[datetime] = None

    def start(self):
        """Mark normalization start."""
        self.start_time = datetime.utcnow()

    def end(self):
        """Mark normalization end."""
        self.end_time = datetime.utcnow()

    def add_success(self, count: int = 1):
        """Increment successful event count."""
        self.events_normalized += count

    def add_failure(self, count: int = 1, error: Optional[str] = None):
        """Increment failed event count."""
        self.events_failed += count
        if error:
            self.validation_errors.append(error)

    def get_duration_seconds(self) -> Optional[float]:
        """Get normalization duration in seconds."""
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return None

    def to_dict(self) -> Dict[str, Any]:
        """Convert metrics to dictionary."""
        return {
            "events_normalized": self.events_normalized,
            "events_failed": self.events_failed,
            "validation_errors": self.validation_errors[:10],  # Limit to first 10
            "duration_seconds": self.get_duration_seconds(),
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
        }


class BaseNormalizer(ABC):
    """Abstract base class for all normalizers.

    Normalizers transform raw data from various sources into standardized
    formats defined in ladon-models.
    """

    def __init__(self, source_name: str, skip_invalid: bool = True):
        """Initialize normalizer.

        Args:
            source_name: Name of the data source (e.g., "alienvault_otx", "dns")
            skip_invalid: Skip invalid records instead of failing entire batch
        """
        self.source_name = source_name
        self.skip_invalid = skip_invalid
        self.metrics = NormalizationMetrics()

    @abstractmethod
    def normalize(self, raw_data: Dict[str, Any]) -> Optional[Any]:
        """Normalize a single raw event.

        Args:
            raw_data: Raw event data

        Returns:
            Normalized event or None if validation fails
        """
        pass

    def normalize_batch(
        self, raw_events: List[Dict[str, Any]]
    ) -> List[Any]:
        """Normalize a batch of raw events.

        Args:
            raw_events: List of raw event dictionaries

        Returns:
            List of normalized events (excludes invalid ones if skip_invalid=True)
        """
        self.metrics.start()
        normalized = []

        for raw_event in raw_events:
            try:
                normalized_event = self.normalize(raw_event)

                if normalized_event:
                    normalized.append(normalized_event)
                    self.metrics.add_success()
                else:
                    self.metrics.add_failure(
                        error=f"Normalization returned None for event: {raw_event.get('event_id', 'unknown')}"
                    )

            except Exception as e:
                error_msg = f"Failed to normalize event: {e}"
                logger.error(error_msg)
                self.metrics.add_failure(error=error_msg)

                if not self.skip_invalid:
                    raise

        self.metrics.end()
        return normalized

    def _extract_field(
        self,
        raw_data: Dict[str, Any],
        field_name: str,
        default: Any = None,
        required: bool = False,
    ) -> Any:
        """Extract a field from raw data with optional default.

        Args:
            raw_data: Raw data dictionary
            field_name: Field name to extract
            default: Default value if field not found
            required: Raise exception if field is required but missing

        Returns:
            Field value or default

        Raises:
            ValueError: If required field is missing
        """
        value = raw_data.get(field_name, default)

        if required and value is None:
            raise ValueError(f"Required field '{field_name}' is missing")

        return value

    def _parse_timestamp(
        self, timestamp_value: Any, default: Optional[datetime] = None
    ) -> datetime:
        """Parse timestamp from various formats.

        Args:
            timestamp_value: Timestamp as string, int, or datetime
            default: Default value if parsing fails

        Returns:
            Parsed datetime
        """
        if isinstance(timestamp_value, datetime):
            return timestamp_value

        if isinstance(timestamp_value, str):
            # Try ISO format
            try:
                return datetime.fromisoformat(timestamp_value.replace("Z", "+00:00"))
            except ValueError:
                pass

            # Try common formats
            formats = [
                "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%d",
            ]
            for fmt in formats:
                try:
                    return datetime.strptime(timestamp_value, fmt)
                except ValueError:
                    continue

        if isinstance(timestamp_value, (int, float)):
            # Assume Unix timestamp
            return datetime.fromtimestamp(timestamp_value)

        if default:
            return default

        # Fall back to current time
        logger.warning(f"Could not parse timestamp: {timestamp_value}, using current time")
        return datetime.utcnow()


class IOCNormalizer(BaseNormalizer):
    """Base class for IOC normalizers."""

    def normalize(self, raw_data: Dict[str, Any]) -> Optional[NormalizedIOC]:
        """Normalize raw IOC data.

        Args:
            raw_data: Raw IOC dictionary

        Returns:
            NormalizedIOC or None if validation fails
        """
        try:
            # Extract required fields
            ioc_value = self._extract_field(raw_data, "ioc_value", required=True)
            ioc_type = self._extract_field(raw_data, "ioc_type", required=True)
            threat_type = self._extract_field(raw_data, "threat_type", required=True)
            confidence = self._extract_field(raw_data, "confidence", required=True)
            source = self._extract_field(raw_data, "source", required=True)

            # Extract optional fields
            first_seen = self._parse_timestamp(
                self._extract_field(raw_data, "first_seen", default=datetime.utcnow())
            )
            last_seen = self._parse_timestamp(
                self._extract_field(raw_data, "last_seen", default=datetime.utcnow())
            )
            tags = self._extract_field(raw_data, "tags", default=[])
            metadata = self._extract_field(raw_data, "metadata", default={})

            # Create NormalizedIOC
            normalized_ioc = NormalizedIOC(
                ioc_value=ioc_value,
                ioc_type=ioc_type,
                threat_type=threat_type,
                confidence=float(confidence),
                source=source,
                first_seen=first_seen,
                last_seen=last_seen,
                tags=tags,
                metadata=metadata,
            )

            return normalized_ioc

        except Exception as e:
            logger.error(f"Failed to normalize IOC: {e}")
            if not self.skip_invalid:
                raise
            return None


class ActivityNormalizer(BaseNormalizer):
    """Base class for activity log normalizers."""

    def normalize(self, raw_data: Dict[str, Any]) -> Optional[NormalizedActivity]:
        """Normalize raw activity data.

        Args:
            raw_data: Raw activity event dictionary

        Returns:
            NormalizedActivity or None if validation fails
        """
        try:
            # Extract required fields
            event_id = self._extract_field(raw_data, "event_id", required=True)
            timestamp = self._parse_timestamp(
                self._extract_field(raw_data, "timestamp", required=True)
            )
            source = self._extract_field(raw_data, "source", required=True)
            event_type = self._extract_field(raw_data, "event_type", required=True)

            # Extract optional network fields
            src_ip = self._extract_field(raw_data, "src_ip")
            dst_ip = self._extract_field(raw_data, "dst_ip")
            domain = self._extract_field(raw_data, "domain")
            url = self._extract_field(raw_data, "url")

            # Extract optional host fields
            hostname = self._extract_field(raw_data, "hostname")
            user = self._extract_field(raw_data, "user")
            process_name = self._extract_field(raw_data, "process_name")
            file_hash = self._extract_field(raw_data, "file_hash")

            # Store original event
            raw_event = raw_data.copy()

            # Create NormalizedActivity
            normalized_activity = NormalizedActivity(
                event_id=event_id,
                timestamp=timestamp,
                source=source,
                event_type=event_type,
                src_ip=src_ip,
                dst_ip=dst_ip,
                domain=domain,
                url=url,
                hostname=hostname,
                user=user,
                process_name=process_name,
                file_hash=file_hash,
                raw_event=raw_event,
            )

            return normalized_activity

        except Exception as e:
            logger.error(f"Failed to normalize activity event: {e}")
            if not self.skip_invalid:
                raise
            return None
