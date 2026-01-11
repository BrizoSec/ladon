"""AlienVault OTX threat intelligence feed collector."""

import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

import aiohttp

from ..config import AlienVaultOTXConfig
from .base import BaseCollector, WatermarkManager

logger = logging.getLogger(__name__)


class AlienVaultOTXCollector(BaseCollector):
    """Collector for AlienVault Open Threat Exchange (OTX) feed.

    Collects threat intelligence pulses from AlienVault OTX, including:
    - Malware hashes
    - C2 domains and IPs
    - Phishing URLs
    - Exploit indicators
    """

    def __init__(
        self,
        config: AlienVaultOTXConfig,
        watermark_manager: WatermarkManager,
        publisher: Any,
    ):
        """Initialize AlienVault OTX collector.

        Args:
            config: AlienVault OTX configuration
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
                "X-OTX-API-KEY": self.config.api_key,
                "Accept": "application/json",
            }
            timeout = aiohttp.ClientTimeout(total=self.config.timeout_seconds)
            self.session = aiohttp.ClientSession(headers=headers, timeout=timeout)

        return self.session

    async def validate_connection(self) -> bool:
        """Validate connection to AlienVault OTX API.

        Returns:
            True if connection is valid
        """
        max_retries = 2
        for attempt in range(max_retries):
            try:
                session = await self._get_session()
                url = f"{self.config.api_endpoint}/pulses/subscribed"

                async with session.get(url, params={"limit": 1}) as response:
                    if response.status == 200:
                        logger.info("AlienVault OTX connection validated successfully")
                        return True
                    else:
                        logger.error(
                            f"AlienVault OTX connection failed: {response.status}"
                        )
                        return False

            except aiohttp.ServerDisconnectedError as e:
                logger.warning(f"AlienVault OTX connection disconnected, recreating session (attempt {attempt + 1}/{max_retries})")
                # Force session recreation on next call
                if self.session and not self.session.closed:
                    await self.session.close()
                self.session = None
                if attempt == max_retries - 1:
                    logger.error(f"AlienVault OTX connection validation failed after {max_retries} attempts")
                    return False
            except Exception as e:
                logger.error(f"AlienVault OTX connection validation error: {e}")
                return False

        return False

    async def collect(self) -> Dict[str, Any]:
        """Collect IOCs from AlienVault OTX.

        Returns:
            Collection metrics dictionary
        """
        self.metrics.start()

        try:
            # Get watermark to determine starting point
            watermark = await self.watermark_manager.get_watermark(self.config.id)

            # Calculate modified_since timestamp
            if watermark and watermark.get("last_successful_timestamp"):
                modified_since = watermark["last_successful_timestamp"]
            else:
                # Default to last 7 days for initial collection
                modified_since = datetime.utcnow() - timedelta(days=7)

            logger.info(
                f"Collecting AlienVault OTX pulses modified since {modified_since}"
            )

            # Fetch pulses
            pulses = await self._fetch_pulses(modified_since)
            logger.info(f"Fetched {len(pulses)} pulses from AlienVault OTX")

            if not pulses:
                await self.watermark_manager.update_watermark(
                    source_id=self.config.id,
                    timestamp=datetime.utcnow(),
                    status="success",
                    records_collected=0,
                )
                self.metrics.end()
                return self.metrics.to_dict()

            # Extract IOCs from pulses
            all_iocs = []
            latest_timestamp = modified_since

            for pulse in pulses:
                iocs = self._extract_iocs_from_pulse(pulse)
                all_iocs.extend(iocs)

                # Track latest pulse timestamp
                pulse_modified = datetime.fromisoformat(
                    pulse["modified"].replace("Z", "+00:00")
                )
                if pulse_modified > latest_timestamp:
                    latest_timestamp = pulse_modified

            logger.info(f"Extracted {len(all_iocs)} IOCs from pulses")

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
            logger.error(f"AlienVault OTX collection error: {e}")
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

    async def _fetch_pulses(
        self, modified_since: datetime
    ) -> List[Dict[str, Any]]:
        """Fetch pulses from AlienVault OTX API.

        Args:
            modified_since: Only fetch pulses modified after this timestamp

        Returns:
            List of pulse dictionaries
        """
        session = await self._get_session()
        url = f"{self.config.api_endpoint}/pulses/subscribed"

        pulses = []
        params = {
            "modified_since": modified_since.isoformat(),
            "limit": self.config.pulses_limit,
        }

        try:
            async with session.get(url, params=params) as response:
                response.raise_for_status()
                data = await response.json()
                pulses = data.get("results", [])

        except aiohttp.ClientError as e:
            logger.error(f"Failed to fetch OTX pulses: {e}")
            raise

        return pulses

    def _extract_iocs_from_pulse(self, pulse: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract IOCs from an OTX pulse.

        Args:
            pulse: OTX pulse dictionary

        Returns:
            List of IOC dictionaries
        """
        iocs = []
        pulse_id = pulse.get("id")
        pulse_name = pulse.get("name")
        pulse_tags = pulse.get("tags", [])
        pulse_created = pulse.get("created")
        pulse_modified = pulse.get("modified")

        # Map OTX indicator types to our IOC types
        type_mapping = {
            "IPv4": "ip",
            "IPv6": "ip",
            "domain": "domain",
            "hostname": "domain",
            "URL": "url",
            "FileHash-MD5": "hash_md5",
            "FileHash-SHA1": "hash_sha1",
            "FileHash-SHA256": "hash_sha256",
            "email": "email",
            "CIDR": "cidr",
            "FilePath": "file_path",
            "Mutex": "mutex",
            "CVE": "cve",
        }

        # Extract indicators
        for indicator in pulse.get("indicators", []):
            indicator_type = indicator.get("type")
            indicator_value = indicator.get("indicator")

            # Map to our IOC type
            ioc_type = type_mapping.get(indicator_type)
            if not ioc_type:
                logger.debug(f"Skipping unknown indicator type: {indicator_type}")
                continue

            # Determine threat type from tags
            threat_type = self._infer_threat_type(pulse_tags, pulse_name)

            ioc = {
                "ioc_value": indicator_value,
                "ioc_type": ioc_type,
                "threat_type": threat_type,
                "confidence": 0.8,  # OTX has good quality
                "source": "alienvault_otx",
                "first_seen": pulse_created,
                "last_seen": pulse_modified,
                "tags": pulse_tags,
                "metadata": {
                    "pulse_id": pulse_id,
                    "pulse_name": pulse_name,
                    "indicator_description": indicator.get("description"),
                    "indicator_role": indicator.get("role"),
                },
            }

            iocs.append(ioc)

        return iocs

    def _infer_threat_type(
        self, tags: List[str], pulse_name: str
    ) -> str:
        """Infer threat type from pulse tags and name.

        Args:
            tags: Pulse tags
            pulse_name: Pulse name

        Returns:
            Threat type
        """
        # Combine tags and pulse name for analysis
        text = " ".join(tags + [pulse_name]).lower()

        # Priority order: ransomware > c2 > phishing > malware > exploit
        if any(
            keyword in text
            for keyword in ["ransomware", "crypto", "locker", "crypt"]
        ):
            return "ransomware"
        elif any(keyword in text for keyword in ["c2", "c&c", "command"]):
            return "c2"
        elif any(keyword in text for keyword in ["phish", "credential"]):
            return "phishing"
        elif any(
            keyword in text for keyword in ["malware", "trojan", "backdoor", "rat"]
        ):
            return "malware"
        elif any(keyword in text for keyword in ["exploit", "cve", "vulnerability"]):
            return "exploit"
        else:
            return "malware"  # Default
