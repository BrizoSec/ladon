"""abuse.ch threat intelligence feed collector."""

import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

import aiohttp

from ..config import AbuseCHConfig
from .base import BaseCollector, WatermarkManager

logger = logging.getLogger(__name__)


class AbuseCHCollector(BaseCollector):
    """Collector for abuse.ch threat intelligence feeds.

    Collects threat intelligence from multiple abuse.ch feeds:
    - ThreatFox: Malware IOCs
    - URLhaus: Malicious URLs
    - MalwareBazaar: Malware samples and hashes
    """

    def __init__(
        self,
        config: AbuseCHConfig,
        watermark_manager: WatermarkManager,
        publisher: Any,
    ):
        """Initialize abuse.ch collector.

        Args:
            config: abuse.ch configuration
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
            headers = {"Accept": "application/json"}
            if self.config.api_key:
                headers["API-KEY"] = self.config.api_key

            timeout = aiohttp.ClientTimeout(total=self.config.timeout_seconds)
            self.session = aiohttp.ClientSession(headers=headers, timeout=timeout)

        return self.session

    async def validate_connection(self) -> bool:
        """Validate connection to abuse.ch APIs.

        Returns:
            True if connection is valid
        """
        try:
            # Test ThreatFox API
            session = await self._get_session()
            payload = {"query": "get_iocs", "days": 1}

            async with session.post(
                self.config.threatfox_url, json=payload
            ) as response:
                if response.status == 200:
                    logger.info("abuse.ch connection validated successfully")
                    return True
                else:
                    logger.error(f"abuse.ch connection failed: {response.status}")
                    return False

        except Exception as e:
            logger.error(f"abuse.ch connection validation error: {e}")
            return False

    async def collect(self) -> Dict[str, Any]:
        """Collect IOCs from abuse.ch feeds.

        Returns:
            Collection metrics dictionary
        """
        self.metrics.start()

        try:
            # Get watermark to determine starting point
            watermark = await self.watermark_manager.get_watermark(self.config.id)

            # Calculate days to look back
            if watermark and watermark.get("last_successful_timestamp"):
                time_since_last = datetime.utcnow() - watermark["last_successful_timestamp"]
                days = max(1, int(time_since_last.total_seconds() / 86400))
            else:
                days = 7  # Default to last 7 days

            logger.info(f"Collecting abuse.ch IOCs from last {days} days")

            all_iocs = []

            # Collect from ThreatFox
            threatfox_iocs = await self._collect_threatfox(days)
            all_iocs.extend(threatfox_iocs)
            logger.info(f"Collected {len(threatfox_iocs)} IOCs from ThreatFox")

            # Collect from URLhaus
            urlhaus_iocs = await self._collect_urlhaus(days)
            all_iocs.extend(urlhaus_iocs)
            logger.info(f"Collected {len(urlhaus_iocs)} IOCs from URLhaus")

            # Collect from MalwareBazaar
            malware_bazaar_iocs = await self._collect_malware_bazaar(days)
            all_iocs.extend(malware_bazaar_iocs)
            logger.info(f"Collected {len(malware_bazaar_iocs)} IOCs from MalwareBazaar")

            logger.info(f"Total IOCs collected from abuse.ch: {len(all_iocs)}")

            if not all_iocs:
                await self.watermark_manager.update_watermark(
                    source_id=self.config.id,
                    timestamp=datetime.utcnow(),
                    status="success",
                    records_collected=0,
                )
                self.metrics.end()
                return self.metrics.to_dict()

            # Publish IOCs in batches
            batches = self._batch_events(all_iocs, self.config.batch_size)

            for batch in batches:
                success = await self._publish_batch(batch, self.config.pubsub_topic)
                if not success:
                    logger.error(f"Failed to publish batch of {len(batch)} IOCs")

            # Update watermark on success
            await self.watermark_manager.update_watermark(
                source_id=self.config.id,
                timestamp=datetime.utcnow(),
                status="success",
                records_collected=len(all_iocs),
            )

        except Exception as e:
            logger.error(f"abuse.ch collection error: {e}")
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

    async def _collect_threatfox(self, days: int) -> List[Dict[str, Any]]:
        """Collect IOCs from ThreatFox.

        Args:
            days: Number of days to look back

        Returns:
            List of IOC dictionaries
        """
        session = await self._get_session()
        payload = {"query": "get_iocs", "days": days}

        try:
            async with session.post(
                self.config.threatfox_url, json=payload
            ) as response:
                response.raise_for_status()
                data = await response.json()

                if data.get("query_status") != "ok":
                    logger.warning(f"ThreatFox query failed: {data}")
                    return []

                iocs = []
                for entry in data.get("data", []):
                    ioc = self._parse_threatfox_entry(entry)
                    if ioc:
                        iocs.append(ioc)

                return iocs

        except aiohttp.ClientError as e:
            logger.error(f"Failed to fetch ThreatFox IOCs: {e}")
            return []

    def _parse_threatfox_entry(self, entry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Parse ThreatFox entry into IOC format.

        Args:
            entry: ThreatFox entry dictionary

        Returns:
            IOC dictionary or None
        """
        ioc_type_mapping = {
            "ip:port": "ip",
            "domain": "domain",
            "url": "url",
            "md5_hash": "hash_md5",
            "sha256_hash": "hash_sha256",
        }

        ioc_type = ioc_type_mapping.get(entry.get("ioc_type"))
        if not ioc_type:
            return None

        # Map malware to threat type
        malware = entry.get("malware", "").lower()
        threat_type = "malware"
        if "ransomware" in malware or "crypt" in malware:
            threat_type = "ransomware"
        elif "c2" in malware or "c&c" in malware:
            threat_type = "c2"

        return {
            "ioc_value": entry.get("ioc"),
            "ioc_type": ioc_type,
            "threat_type": threat_type,
            "confidence": entry.get("confidence_level", 50) / 100.0,
            "source": "abuse_ch_threatfox",
            "first_seen": entry.get("first_seen_utc"),
            "last_seen": entry.get("last_seen_utc", entry.get("first_seen_utc")),
            "tags": entry.get("tags", []),
            "metadata": {
                "malware": entry.get("malware"),
                "malware_alias": entry.get("malware_alias"),
                "threat_type_desc": entry.get("threat_type"),
                "reporter": entry.get("reporter"),
                "reference": entry.get("reference"),
            },
        }

    async def _collect_urlhaus(self, days: int) -> List[Dict[str, Any]]:
        """Collect IOCs from URLhaus.

        Args:
            days: Number of days to look back

        Returns:
            List of IOC dictionaries
        """
        session = await self._get_session()
        payload = {"query": "get_recent"}

        try:
            async with session.post(
                self.config.urlhaus_url + "urls/recent/", json=payload
            ) as response:
                response.raise_for_status()
                data = await response.json()

                if data.get("query_status") != "ok":
                    logger.warning(f"URLhaus query failed: {data}")
                    return []

                iocs = []
                cutoff_date = datetime.utcnow() - timedelta(days=days)

                for entry in data.get("urls", []):
                    # Check if within time window
                    date_added = datetime.fromisoformat(
                        entry.get("date_added").replace("Z", "+00:00")
                    )
                    if date_added < cutoff_date:
                        continue

                    ioc = self._parse_urlhaus_entry(entry)
                    if ioc:
                        iocs.append(ioc)

                return iocs

        except aiohttp.ClientError as e:
            logger.error(f"Failed to fetch URLhaus IOCs: {e}")
            return []

    def _parse_urlhaus_entry(self, entry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Parse URLhaus entry into IOC format.

        Args:
            entry: URLhaus entry dictionary

        Returns:
            IOC dictionary or None
        """
        url = entry.get("url")
        if not url:
            return None

        # Determine threat type from tags
        tags = entry.get("tags", [])
        threat_type = "malware"
        if any(tag in tags for tag in ["ransomware", "crypto"]):
            threat_type = "ransomware"
        elif any(tag in tags for tag in ["phishing"]):
            threat_type = "phishing"

        return {
            "ioc_value": url,
            "ioc_type": "url",
            "threat_type": threat_type,
            "confidence": 0.85,  # URLhaus has high quality
            "source": "abuse_ch_urlhaus",
            "first_seen": entry.get("date_added"),
            "last_seen": entry.get("date_added"),
            "tags": tags,
            "metadata": {
                "url_status": entry.get("url_status"),
                "threat": entry.get("threat"),
                "reporter": entry.get("reporter"),
                "larted": entry.get("larted"),
            },
        }

    async def _collect_malware_bazaar(self, days: int) -> List[Dict[str, Any]]:
        """Collect IOCs from MalwareBazaar.

        Args:
            days: Number of days to look back

        Returns:
            List of IOC dictionaries
        """
        session = await self._get_session()
        payload = {"query": "get_recent"}

        try:
            async with session.post(
                self.config.malware_bazaar_url, json=payload
            ) as response:
                response.raise_for_status()
                data = await response.json()

                if data.get("query_status") != "ok":
                    logger.warning(f"MalwareBazaar query failed: {data}")
                    return []

                iocs = []
                cutoff_date = datetime.utcnow() - timedelta(days=days)

                for entry in data.get("data", []):
                    # Check if within time window
                    date_added = datetime.fromisoformat(
                        entry.get("first_seen").replace("Z", "+00:00")
                    )
                    if date_added < cutoff_date:
                        continue

                    ioc_list = self._parse_malware_bazaar_entry(entry)
                    iocs.extend(ioc_list)

                return iocs

        except aiohttp.ClientError as e:
            logger.error(f"Failed to fetch MalwareBazaar IOCs: {e}")
            return []

    def _parse_malware_bazaar_entry(
        self, entry: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Parse MalwareBazaar entry into IOC format.

        Args:
            entry: MalwareBazaar entry dictionary

        Returns:
            List of IOC dictionaries (one per hash type)
        """
        iocs = []

        # Determine threat type
        signature = entry.get("signature", "").lower()
        threat_type = "malware"
        if "ransomware" in signature:
            threat_type = "ransomware"

        # Extract all available hashes
        hash_mapping = {
            "md5_hash": "hash_md5",
            "sha1_hash": "hash_sha1",
            "sha256_hash": "hash_sha256",
        }

        for hash_field, ioc_type in hash_mapping.items():
            hash_value = entry.get(hash_field)
            if hash_value:
                iocs.append(
                    {
                        "ioc_value": hash_value,
                        "ioc_type": ioc_type,
                        "threat_type": threat_type,
                        "confidence": 0.9,  # MalwareBazaar has very high quality
                        "source": "abuse_ch_malware_bazaar",
                        "first_seen": entry.get("first_seen"),
                        "last_seen": entry.get("first_seen"),
                        "tags": entry.get("tags", []),
                        "metadata": {
                            "signature": entry.get("signature"),
                            "file_name": entry.get("file_name"),
                            "file_type": entry.get("file_type"),
                            "reporter": entry.get("reporter"),
                            "intelligence": entry.get("intelligence", {}),
                        },
                    }
                )

        return iocs
