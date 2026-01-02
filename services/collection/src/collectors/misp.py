"""MISP threat intelligence platform collector."""

import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

import aiohttp

from ..config import MISPConfig
from .base import BaseCollector, WatermarkManager

logger = logging.getLogger(__name__)


class MISPCollector(BaseCollector):
    """Collector for MISP (Malware Information Sharing Platform).

    Collects threat intelligence from a MISP instance, including:
    - IOCs from published events
    - Attributes marked for IDS detection
    - Optional tag-based filtering
    """

    def __init__(
        self,
        config: MISPConfig,
        watermark_manager: WatermarkManager,
        publisher: Any,
    ):
        """Initialize MISP collector.

        Args:
            config: MISP configuration
            watermark_manager: Watermark manager instance
            publisher: Pub/Sub publisher instance
        """
        super().__init__(config, watermark_manager, publisher)
        self.session: Optional[aiohttp.ClientSession] = None

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create HTTP session.

        Returns:
            aiohttp ClientSession
        """
        if self.session is None:
            headers = {
                "Authorization": self.config.api_key,
                "Accept": "application/json",
                "Content-Type": "application/json",
            }
            timeout = aiohttp.ClientTimeout(total=self.config.timeout_seconds)

            connector = None
            if not self.config.verify_ssl:
                connector = aiohttp.TCPConnector(ssl=False)

            self.session = aiohttp.ClientSession(
                headers=headers, timeout=timeout, connector=connector
            )

        return self.session

    async def validate_connection(self) -> bool:
        """Validate connection to MISP instance.

        Returns:
            True if connection is valid
        """
        try:
            session = await self._get_session()
            url = f"{self.config.url}/servers/getVersion"

            async with session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    logger.info(
                        f"MISP connection validated successfully (version: {data.get('version', 'unknown')})"
                    )
                    return True
                else:
                    logger.error(f"MISP connection failed: {response.status}")
                    return False

        except Exception as e:
            logger.error(f"MISP connection validation error: {e}")
            return False

    async def collect(self) -> Dict[str, Any]:
        """Collect IOCs from MISP.

        Returns:
            Collection metrics dictionary
        """
        self.metrics.start()

        try:
            # Get watermark to determine starting point
            watermark = await self.watermark_manager.get_watermark(self.config.id)

            # Calculate timestamp filter
            if watermark and watermark.get("last_successful_timestamp"):
                timestamp_filter = watermark["last_successful_timestamp"]
            else:
                # Default to last 30 days for initial collection
                timestamp_filter = datetime.utcnow() - timedelta(days=30)

            logger.info(
                f"Collecting MISP events published/modified since {timestamp_filter}"
            )

            # Fetch events
            events = await self._fetch_events(timestamp_filter)
            logger.info(f"Fetched {len(events)} events from MISP")

            if not events:
                await self.watermark_manager.update_watermark(
                    source_id=self.config.id,
                    timestamp=datetime.utcnow(),
                    status="success",
                    records_collected=0,
                )
                self.metrics.end()
                return self.metrics.to_dict()

            # Extract IOCs from events
            all_iocs = []
            latest_timestamp = timestamp_filter

            for event in events:
                iocs = self._extract_iocs_from_event(event)
                all_iocs.extend(iocs)

                # Track latest event timestamp
                event_timestamp = datetime.fromtimestamp(int(event.get("timestamp", 0)))
                if event_timestamp > latest_timestamp:
                    latest_timestamp = event_timestamp

            logger.info(f"Extracted {len(all_iocs)} IOCs from MISP events")

            # Publish IOCs in batches
            batches = self._batch_events(all_iocs, self.config.batch_size)

            for batch in batches:
                success = await self._publish_batch(batch, self.config.pubsub_topic)
                if not success:
                    logger.error(f"Failed to publish batch of {len(batch)} IOCs")

            # Update watermark on success
            await self.watermark_manager.update_watermark(
                source_id=self.config.id,
                timestamp=latest_timestamp,
                status="success",
                records_collected=len(all_iocs),
            )

        except Exception as e:
            logger.error(f"MISP collection error: {e}")
            await self.watermark_manager.update_watermark(
                source_id=self.config.id,
                timestamp=datetime.utcnow(),
                status="failed",
                error_message=str(e),
            )
            raise

        finally:
            self.metrics.end()
            if self.session:
                await self.session.close()
                self.session = None

        return self.metrics.to_dict()

    async def _fetch_events(self, timestamp_filter: datetime) -> List[Dict[str, Any]]:
        """Fetch events from MISP.

        Args:
            timestamp_filter: Only fetch events after this timestamp

        Returns:
            List of MISP event dictionaries
        """
        session = await self._get_session()
        url = f"{self.config.url}/events/restSearch"

        # Build search parameters
        search_params = {
            "returnFormat": "json",
            "published": self.config.published,
            "to_ids": self.config.to_ids,
            "timestamp": int(timestamp_filter.timestamp()),
        }

        # Add tag filter if configured
        if self.config.tags:
            search_params["tags"] = self.config.tags

        try:
            async with session.post(url, json=search_params) as response:
                response.raise_for_status()
                data = await response.json()

                # MISP returns events in a response wrapper
                events = data.get("response", [])
                return [event.get("Event", event) for event in events]

        except aiohttp.ClientError as e:
            logger.error(f"Failed to fetch MISP events: {e}")
            raise

    def _extract_iocs_from_event(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract IOCs from a MISP event.

        Args:
            event: MISP event dictionary

        Returns:
            List of IOC dictionaries
        """
        iocs = []
        event_id = event.get("id")
        event_info = event.get("info")
        event_tags = self._extract_tags(event.get("Tag", []))
        event_threat_level = event.get("threat_level_id", "3")  # 1=High, 2=Medium, 3=Low, 4=Undefined
        event_timestamp = datetime.fromtimestamp(int(event.get("timestamp", 0)))

        # Map MISP attribute types to our IOC types
        type_mapping = {
            "ip-src": "ip",
            "ip-dst": "ip",
            "domain": "domain",
            "hostname": "domain",
            "url": "url",
            "md5": "hash_md5",
            "sha1": "hash_sha1",
            "sha256": "hash_sha256",
            "email-src": "email",
            "email-dst": "email",
            "mutex": "mutex",
            "filename": "file_path",
            "regkey": "registry_key",
        }

        # Extract attributes
        for attribute in event.get("Attribute", []):
            # Skip if not marked for IDS and we require to_ids
            if self.config.to_ids and not attribute.get("to_ids"):
                continue

            attr_type = attribute.get("type")
            attr_value = attribute.get("value")

            # Map to our IOC type
            ioc_type = type_mapping.get(attr_type)
            if not ioc_type:
                continue

            # Get attribute tags
            attr_tags = self._extract_tags(attribute.get("Tag", []))
            all_tags = list(set(event_tags + attr_tags))

            # Determine threat type
            threat_type = self._infer_threat_type(all_tags, event_info)

            # Calculate confidence based on threat level and tags
            confidence = self._calculate_confidence(event_threat_level, all_tags)

            ioc = {
                "ioc_value": attr_value,
                "ioc_type": ioc_type,
                "threat_type": threat_type,
                "confidence": confidence,
                "source": "misp",
                "first_seen": event_timestamp.isoformat(),
                "last_seen": event_timestamp.isoformat(),
                "tags": all_tags,
                "metadata": {
                    "event_id": event_id,
                    "event_info": event_info,
                    "attribute_id": attribute.get("id"),
                    "attribute_category": attribute.get("category"),
                    "attribute_comment": attribute.get("comment"),
                    "threat_level_id": event_threat_level,
                },
            }

            iocs.append(ioc)

        return iocs

    def _extract_tags(self, tags: List[Dict[str, Any]]) -> List[str]:
        """Extract tag names from MISP tag objects.

        Args:
            tags: List of MISP tag dictionaries

        Returns:
            List of tag names
        """
        return [tag.get("name", "") for tag in tags if tag.get("name")]

    def _infer_threat_type(self, tags: List[str], event_info: str) -> str:
        """Infer threat type from tags and event info.

        Args:
            tags: Tag list
            event_info: Event information

        Returns:
            Threat type
        """
        text = " ".join(tags + [event_info]).lower()

        if any(keyword in text for keyword in ["ransomware", "crypto-locker"]):
            return "ransomware"
        elif any(keyword in text for keyword in ["c2", "c&c", "command-and-control"]):
            return "c2"
        elif any(keyword in text for keyword in ["phish", "credential"]):
            return "phishing"
        elif any(keyword in text for keyword in ["apt", "espionage", "targeted"]):
            return "apt"
        elif any(keyword in text for keyword in ["exploit", "cve", "vulnerability"]):
            return "exploit"
        elif any(keyword in text for keyword in ["malware", "trojan", "backdoor"]):
            return "malware"
        else:
            return "malware"

    def _calculate_confidence(
        self, threat_level_id: str, tags: List[str]
    ) -> float:
        """Calculate IOC confidence based on MISP metadata.

        Args:
            threat_level_id: MISP threat level (1=High, 2=Medium, 3=Low, 4=Undefined)
            tags: Tag list

        Returns:
            Confidence score (0.0-1.0)
        """
        # Base confidence from threat level
        threat_level_map = {
            "1": 0.9,  # High
            "2": 0.7,  # Medium
            "3": 0.5,  # Low
            "4": 0.3,  # Undefined
        }
        base_confidence = threat_level_map.get(str(threat_level_id), 0.5)

        # Adjust based on tags
        high_confidence_tags = ["apt", "targeted", "confirmed"]
        low_confidence_tags = ["false-positive", "test"]

        if any(tag.lower() in " ".join(tags).lower() for tag in high_confidence_tags):
            base_confidence = min(base_confidence + 0.2, 1.0)

        if any(tag.lower() in " ".join(tags).lower() for tag in low_confidence_tags):
            base_confidence = max(base_confidence - 0.3, 0.1)

        return round(base_confidence, 2)
