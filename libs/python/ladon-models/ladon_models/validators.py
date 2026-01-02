"""
Validation utilities for IOCs and activity events.

This module provides validators for different types of IOCs including
IP addresses, domains, URLs, hashes, etc.
"""

import hashlib
import ipaddress
import re
from typing import Optional
from urllib.parse import urlparse


class IOCValidator:
    """Validators for different IOC types."""

    @staticmethod
    def is_valid_ipv4(ip: str) -> bool:
        """Validate IPv4 address."""
        try:
            ipaddress.IPv4Address(ip)
            return True
        except (ipaddress.AddressValueError, ValueError):
            return False

    @staticmethod
    def is_valid_ipv6(ip: str) -> bool:
        """Validate IPv6 address."""
        try:
            ipaddress.IPv6Address(ip)
            return True
        except (ipaddress.AddressValueError, ValueError):
            return False

    @staticmethod
    def is_valid_ip(ip: str) -> bool:
        """Validate IP address (v4 or v6)."""
        try:
            ipaddress.ip_address(ip)
            return True
        except (ipaddress.AddressValueError, ValueError):
            return False

    @staticmethod
    def is_valid_cidr(cidr: str) -> bool:
        """Validate CIDR notation."""
        try:
            ipaddress.ip_network(cidr, strict=False)
            return True
        except (ipaddress.AddressValueError, ValueError):
            return False

    @staticmethod
    def is_valid_domain(domain: str) -> bool:
        """
        Validate domain name.

        Basic validation for domain format. Does not verify DNS resolution.
        """
        if not domain or len(domain) > 253:
            return False

        # Remove trailing dot if present (valid for FQDN)
        if domain.endswith("."):
            domain = domain[:-1]

        # Domain regex pattern
        pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
        return bool(re.match(pattern, domain))

    @staticmethod
    def is_valid_url(url: str) -> bool:
        """Validate URL format."""
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except Exception:
            return False

    @staticmethod
    def is_valid_email(email: str) -> bool:
        """Validate email address format."""
        pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        return bool(re.match(pattern, email))

    @staticmethod
    def is_valid_md5(hash_str: str) -> bool:
        """Validate MD5 hash format."""
        return bool(re.match(r"^[a-fA-F0-9]{32}$", hash_str))

    @staticmethod
    def is_valid_sha1(hash_str: str) -> bool:
        """Validate SHA1 hash format."""
        return bool(re.match(r"^[a-fA-F0-9]{40}$", hash_str))

    @staticmethod
    def is_valid_sha256(hash_str: str) -> bool:
        """Validate SHA256 hash format."""
        return bool(re.match(r"^[a-fA-F0-9]{64}$", hash_str))

    @staticmethod
    def is_valid_sha512(hash_str: str) -> bool:
        """Validate SHA512 hash format."""
        return bool(re.match(r"^[a-fA-F0-9]{128}$", hash_str))

    @staticmethod
    def detect_hash_type(hash_str: str) -> Optional[str]:
        """
        Detect hash type based on length and format.

        Returns: 'md5', 'sha1', 'sha256', 'sha512', or None
        """
        hash_str = hash_str.strip().lower()

        if IOCValidator.is_valid_md5(hash_str):
            return "hash_md5"
        elif IOCValidator.is_valid_sha1(hash_str):
            return "hash_sha1"
        elif IOCValidator.is_valid_sha256(hash_str):
            return "hash_sha256"
        elif IOCValidator.is_valid_sha512(hash_str):
            return "hash_sha512"
        return None

    @staticmethod
    def is_valid_cve(cve: str) -> bool:
        """Validate CVE identifier format."""
        pattern = r"^CVE-\d{4}-\d{4,}$"
        return bool(re.match(pattern, cve, re.IGNORECASE))

    @staticmethod
    def is_valid_mac_address(mac: str) -> bool:
        """Validate MAC address format."""
        pattern = r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$"
        return bool(re.match(pattern, mac))

    @staticmethod
    def normalize_mac_address(mac: str) -> str:
        """Normalize MAC address to lowercase with colons."""
        mac = mac.replace("-", ":").lower()
        return mac


class DomainMatcher:
    """Utilities for matching domains and subdomains."""

    @staticmethod
    def is_subdomain(subdomain: str, parent_domain: str) -> bool:
        """
        Check if subdomain is a subdomain of parent_domain.

        Examples:
            is_subdomain('sub.example.com', 'example.com') -> True
            is_subdomain('example.com', 'example.com') -> True
            is_subdomain('notexample.com', 'example.com') -> False
        """
        subdomain = subdomain.lower().strip(".")
        parent_domain = parent_domain.lower().strip(".")

        if subdomain == parent_domain:
            return True

        return subdomain.endswith(f".{parent_domain}")

    @staticmethod
    def extract_domain_from_url(url: str) -> Optional[str]:
        """Extract domain from URL."""
        try:
            parsed = urlparse(url)
            return parsed.netloc.lower() if parsed.netloc else None
        except Exception:
            return None

    @staticmethod
    def extract_base_domain(domain: str) -> str:
        """
        Extract base domain from subdomain.

        Examples:
            extract_base_domain('sub.example.com') -> 'example.com'
            extract_base_domain('example.com') -> 'example.com'
        """
        domain = domain.lower().strip(".")
        parts = domain.split(".")

        # Handle special cases like .co.uk
        if len(parts) >= 3 and parts[-2] in ("co", "ac", "gov", "org", "com"):
            return ".".join(parts[-3:])

        # Default: return last two parts
        if len(parts) >= 2:
            return ".".join(parts[-2:])

        return domain


class IPMatcher:
    """Utilities for matching IP addresses against CIDR ranges."""

    @staticmethod
    def ip_in_cidr(ip: str, cidr: str) -> bool:
        """Check if IP address is within CIDR range."""
        try:
            ip_obj = ipaddress.ip_address(ip)
            network = ipaddress.ip_network(cidr, strict=False)
            return ip_obj in network
        except (ipaddress.AddressValueError, ValueError):
            return False

    @staticmethod
    def is_private_ip(ip: str) -> bool:
        """Check if IP address is in private range."""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except (ipaddress.AddressValueError, ValueError):
            return False

    @staticmethod
    def is_reserved_ip(ip: str) -> bool:
        """Check if IP address is reserved/special use."""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return (
                ip_obj.is_private
                or ip_obj.is_loopback
                or ip_obj.is_multicast
                or ip_obj.is_reserved
                or ip_obj.is_link_local
            )
        except (ipaddress.AddressValueError, ValueError):
            return False


class HashCalculator:
    """Utilities for calculating file hashes."""

    @staticmethod
    def calculate_md5(data: bytes) -> str:
        """Calculate MD5 hash of data."""
        return hashlib.md5(data).hexdigest()

    @staticmethod
    def calculate_sha1(data: bytes) -> str:
        """Calculate SHA1 hash of data."""
        return hashlib.sha1(data).hexdigest()

    @staticmethod
    def calculate_sha256(data: bytes) -> str:
        """Calculate SHA256 hash of data."""
        return hashlib.sha256(data).hexdigest()

    @staticmethod
    def calculate_sha512(data: bytes) -> str:
        """Calculate SHA512 hash of data."""
        return hashlib.sha512(data).hexdigest()

    @staticmethod
    def calculate_all_hashes(data: bytes) -> dict:
        """Calculate all common hashes for data."""
        return {
            "md5": HashCalculator.calculate_md5(data),
            "sha1": HashCalculator.calculate_sha1(data),
            "sha256": HashCalculator.calculate_sha256(data),
            "sha512": HashCalculator.calculate_sha512(data),
        }
