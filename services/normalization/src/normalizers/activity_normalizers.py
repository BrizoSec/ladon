"""Activity normalizers for different log sources."""

import logging
from typing import Any, Dict, Optional

from ladon_models import ActivityEventType, ActivitySource, NormalizedActivity

from .base import ActivityNormalizer

logger = logging.getLogger(__name__)


class DNSNormalizer(ActivityNormalizer):
    """Normalizer for DNS query logs."""

    def __init__(self, skip_invalid: bool = True):
        super().__init__(source_name="dns", skip_invalid=skip_invalid)

    def normalize(self, raw_data: Dict[str, Any]) -> Optional[NormalizedActivity]:
        """Normalize DNS log entry.

        DNS logs typically have: query_name (domain), client_ip, server_ip
        """
        try:
            # Map DNS-specific fields to standard fields
            dns_normalized = {
                "event_id": self._extract_field(raw_data, "event_id", required=True),
                "timestamp": raw_data.get("timestamp"),
                "source": ActivitySource.DNS.value,
                "event_type": ActivityEventType.DNS_QUERY.value,
                "domain": self._extract_field(
                    raw_data, "query_name", raw_data.get("domain")
                ),
                "src_ip": self._extract_field(
                    raw_data, "client_ip", raw_data.get("src_ip")
                ),
                "dst_ip": self._extract_field(
                    raw_data, "server_ip", raw_data.get("dst_ip", "8.8.8.8")
                ),
            }

            # Use parent class normalization
            return super().normalize(dns_normalized)

        except Exception as e:
            logger.error(f"Failed to normalize DNS event: {e}")
            if not self.skip_invalid:
                raise
            return None


class ProxyNormalizer(ActivityNormalizer):
    """Normalizer for proxy/HTTP logs."""

    def __init__(self, skip_invalid: bool = True):
        super().__init__(source_name="proxy", skip_invalid=skip_invalid)

    def normalize(self, raw_data: Dict[str, Any]) -> Optional[NormalizedActivity]:
        """Normalize proxy log entry.

        Proxy logs typically have: url, client_ip, server_ip, user_agent
        """
        try:
            # Extract URL and parse domain
            url = self._extract_field(raw_data, "url", raw_data.get("request_url"))
            domain = None

            if url:
                # Extract domain from URL
                from urllib.parse import urlparse

                try:
                    parsed = urlparse(url)
                    domain = parsed.netloc
                except Exception:
                    logger.warning(f"Failed to parse URL: {url}")

            proxy_normalized = {
                "event_id": self._extract_field(raw_data, "event_id", required=True),
                "timestamp": raw_data.get("timestamp"),
                "source": ActivitySource.PROXY.value,
                "event_type": ActivityEventType.HTTP_REQUEST.value,
                "url": url,
                "domain": domain,
                "src_ip": self._extract_field(
                    raw_data, "client_ip", raw_data.get("src_ip")
                ),
                "dst_ip": self._extract_field(
                    raw_data, "server_ip", raw_data.get("dst_ip")
                ),
                "user": self._extract_field(
                    raw_data, "username", raw_data.get("user")
                ),
            }

            return super().normalize(proxy_normalized)

        except Exception as e:
            logger.error(f"Failed to normalize proxy event: {e}")
            if not self.skip_invalid:
                raise
            return None


class MDENormalizer(ActivityNormalizer):
    """Normalizer for Microsoft Defender for Endpoint logs."""

    def __init__(self, skip_invalid: bool = True):
        super().__init__(source_name="mde", skip_invalid=skip_invalid)

    def normalize(self, raw_data: Dict[str, Any]) -> Optional[NormalizedActivity]:
        """Normalize MDE event.

        MDE events can be process creation, network connection, file activity, etc.
        """
        try:
            # Determine event type from action
            action = raw_data.get("action_type", "").lower()
            event_type_map = {
                "processcreated": ActivityEventType.PROCESS_CREATE,
                "connectionrequest": ActivityEventType.NETWORK_CONNECTION,
                "fileCreated": ActivityEventType.FILE_CREATE,
                "registryvalueSet": ActivityEventType.REGISTRY_SET,
            }

            event_type = event_type_map.get(
                action, ActivityEventType.PROCESS_CREATE
            ).value

            mde_normalized = {
                "event_id": self._extract_field(raw_data, "event_id", required=True),
                "timestamp": raw_data.get("timestamp"),
                "source": ActivitySource.MDE.value,
                "event_type": event_type,
                "hostname": self._extract_field(
                    raw_data, "device_name", raw_data.get("hostname")
                ),
                "user": self._extract_field(
                    raw_data, "account_name", raw_data.get("user")
                ),
                "process_name": self._extract_field(
                    raw_data, "process_command_line", raw_data.get("process_name")
                ),
                "file_hash": self._extract_field(
                    raw_data, "sha256", raw_data.get("file_hash")
                ),
                "src_ip": raw_data.get("local_ip"),
                "dst_ip": raw_data.get("remote_ip"),
                "domain": raw_data.get("remote_url"),
            }

            return super().normalize(mde_normalized)

        except Exception as e:
            logger.error(f"Failed to normalize MDE event: {e}")
            if not self.skip_invalid:
                raise
            return None


class CrowdStrikeNormalizer(ActivityNormalizer):
    """Normalizer for CrowdStrike Falcon logs."""

    def __init__(self, skip_invalid: bool = True):
        super().__init__(source_name="crowdstrike", skip_invalid=skip_invalid)

    def normalize(self, raw_data: Dict[str, Any]) -> Optional[NormalizedActivity]:
        """Normalize CrowdStrike event."""
        try:
            # Map event types
            event_name = raw_data.get("event_name", "").lower()
            event_type_map = {
                "processrollup2": ActivityEventType.PROCESS_CREATE,
                "dnsrequest": ActivityEventType.DNS_QUERY,
                "networkconnectip4": ActivityEventType.NETWORK_CONNECTION,
            }

            event_type = event_type_map.get(
                event_name, ActivityEventType.PROCESS_CREATE
            ).value

            crowdstrike_normalized = {
                "event_id": self._extract_field(raw_data, "event_id", required=True),
                "timestamp": raw_data.get("timestamp"),
                "source": ActivitySource.CROWDSTRIKE.value,
                "event_type": event_type,
                "hostname": self._extract_field(
                    raw_data, "computer_name", raw_data.get("hostname")
                ),
                "user": self._extract_field(
                    raw_data, "user_name", raw_data.get("user")
                ),
                "process_name": self._extract_field(
                    raw_data, "image_file_name", raw_data.get("process_name")
                ),
                "file_hash": self._extract_field(
                    raw_data, "sha256_hash", raw_data.get("file_hash")
                ),
                "src_ip": raw_data.get("local_address_ip4"),
                "dst_ip": raw_data.get("remote_address_ip4"),
                "domain": raw_data.get("domain_name"),
            }

            return super().normalize(crowdstrike_normalized)

        except Exception as e:
            logger.error(f"Failed to normalize CrowdStrike event: {e}")
            if not self.skip_invalid:
                raise
            return None


class SinkholeNormalizer(ActivityNormalizer):
    """Normalizer for sinkhole logs."""

    def __init__(self, skip_invalid: bool = True):
        super().__init__(source_name="sinkhole", skip_invalid=skip_invalid)

    def normalize(self, raw_data: Dict[str, Any]) -> Optional[NormalizedActivity]:
        """Normalize sinkhole event."""
        try:
            sinkhole_normalized = {
                "event_id": self._extract_field(raw_data, "event_id", required=True),
                "timestamp": raw_data.get("timestamp"),
                "source": ActivitySource.SINKHOLE.value,
                "event_type": ActivityEventType.NETWORK_CONNECTION.value,
                "src_ip": self._extract_field(raw_data, "src_ip", required=True),
                "dst_ip": self._extract_field(
                    raw_data, "sinkhole_ip", raw_data.get("dst_ip")
                ),
                "domain": raw_data.get("queried_domain"),
            }

            return super().normalize(sinkhole_normalized)

        except Exception as e:
            logger.error(f"Failed to normalize sinkhole event: {e}")
            if not self.skip_invalid:
                raise
            return None


class GenericActivityNormalizer(ActivityNormalizer):
    """Generic activity normalizer for custom sources."""

    def __init__(self, source_name: str, skip_invalid: bool = True):
        super().__init__(source_name=source_name, skip_invalid=skip_invalid)


def get_activity_normalizer(
    source: str, skip_invalid: bool = True
) -> ActivityNormalizer:
    """Factory function to get appropriate activity normalizer.

    Args:
        source: Source name
        skip_invalid: Skip invalid events

    Returns:
        Activity normalizer instance
    """
    normalizer_map = {
        "dns": DNSNormalizer,
        "proxy": ProxyNormalizer,
        "mde": MDENormalizer,
        "crowdstrike": CrowdStrikeNormalizer,
        "sinkhole": SinkholeNormalizer,
    }

    normalizer_class = normalizer_map.get(source, GenericActivityNormalizer)

    if normalizer_class == GenericActivityNormalizer:
        return normalizer_class(source_name=source, skip_invalid=skip_invalid)
    else:
        return normalizer_class(skip_invalid=skip_invalid)
