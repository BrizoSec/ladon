"""IOC normalizers for different threat intelligence sources."""

import logging
from typing import Any, Dict, Optional

from ladon_models import NormalizedIOC

from .base import IOCNormalizer

logger = logging.getLogger(__name__)


class AlienVaultOTXNormalizer(IOCNormalizer):
    """Normalizer for AlienVault OTX IOCs.

    Maps AlienVault OTX IOC types to LADON standard types.
    """

    # AlienVault OTX type mapping to LADON types
    TYPE_MAPPING = {
        "IPv4": "ipv4",
        "IPv6": "ipv6",
        "domain": "domain",
        "hostname": "domain",
        "URL": "url",
        "URI": "url",
        "FileHash-MD5": "hash_md5",
        "FileHash-SHA1": "hash_sha1",
        "FileHash-SHA256": "hash_sha256",
        "FileHash-SHA512": "hash_sha512",
        "email": "email",
        "FilePath": "file_path",
        "FileName": "file_name",
        "Mutex": "mutex",
        "CVE": "cve",
        "CIDR": "cidr",
        "FileHash-IMPHASH": "imphash",
        "FileHash-SSDEEP": "ssdeep",
        "SSLCertFingerprint": "ssl_cert_fingerprint",
        "JA3": "ja3_fingerprint",
    }

    def __init__(self, skip_invalid: bool = True):
        super().__init__(source_name="alienvault_otx", skip_invalid=skip_invalid)

    def normalize(self, raw_data: Dict[str, Any]) -> Optional[NormalizedIOC]:
        """Normalize AlienVault OTX IOC with type mapping.

        Args:
            raw_data: Raw IOC data from AlienVault OTX

        Returns:
            Normalized IOC or None if invalid
        """
        # Map AlienVault type to LADON type
        alienvault_type = raw_data.get("ioc_type", "")
        mapped_type = self.TYPE_MAPPING.get(alienvault_type)

        if not mapped_type:
            if not self.skip_invalid:
                logger.warning(f"Unknown AlienVault IOC type: {alienvault_type}")
            return None

        # Create a copy with mapped type
        normalized_data = raw_data.copy()
        normalized_data["ioc_type"] = mapped_type

        # Call parent normalize with mapped type
        return super().normalize(normalized_data)


class AbuseCHNormalizer(IOCNormalizer):
    """Normalizer for abuse.ch IOCs (ThreatFox, URLhaus, MalwareBazaar)."""

    def __init__(self, skip_invalid: bool = True):
        super().__init__(source_name="abuse_ch", skip_invalid=skip_invalid)


class MISPNormalizer(IOCNormalizer):
    """Normalizer for MISP IOCs."""

    def __init__(self, skip_invalid: bool = True):
        super().__init__(source_name="misp", skip_invalid=skip_invalid)


class GenericIOCNormalizer(IOCNormalizer):
    """Generic IOC normalizer for custom sources."""

    def __init__(self, source_name: str, skip_invalid: bool = True):
        super().__init__(source_name=source_name, skip_invalid=skip_invalid)


def get_ioc_normalizer(source: str, skip_invalid: bool = True) -> IOCNormalizer:
    """Factory function to get appropriate IOC normalizer.

    Args:
        source: Source name
        skip_invalid: Skip invalid IOCs

    Returns:
        IOC normalizer instance
    """
    normalizer_map = {
        "alienvault_otx": AlienVaultOTXNormalizer,
        "abuse_ch": AbuseCHNormalizer,
        "abuse_ch_threatfox": AbuseCHNormalizer,
        "abuse_ch_urlhaus": AbuseCHNormalizer,
        "abuse_ch_malware_bazaar": AbuseCHNormalizer,
        "misp": MISPNormalizer,
    }

    normalizer_class = normalizer_map.get(source, GenericIOCNormalizer)

    if normalizer_class == GenericIOCNormalizer:
        return normalizer_class(source_name=source, skip_invalid=skip_invalid)
    else:
        return normalizer_class(skip_invalid=skip_invalid)
