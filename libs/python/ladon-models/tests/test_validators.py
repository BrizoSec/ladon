"""Tests for IOC validators."""

import pytest

from ladon_models.validators import (
    DomainMatcher,
    HashCalculator,
    IOCValidator,
    IPMatcher,
)


class TestIOCValidator:
    """Tests for IOCValidator class."""

    def test_valid_ipv4(self):
        assert IOCValidator.is_valid_ipv4("192.0.2.1")
        assert IOCValidator.is_valid_ipv4("10.0.0.1")
        assert IOCValidator.is_valid_ipv4("255.255.255.255")

    def test_invalid_ipv4(self):
        assert not IOCValidator.is_valid_ipv4("256.1.1.1")
        assert not IOCValidator.is_valid_ipv4("192.0.2")
        assert not IOCValidator.is_valid_ipv4("not-an-ip")

    def test_valid_ipv6(self):
        assert IOCValidator.is_valid_ipv6("2001:0db8::1")
        assert IOCValidator.is_valid_ipv6("::1")
        assert IOCValidator.is_valid_ipv6("fe80::1")

    def test_valid_domain(self):
        assert IOCValidator.is_valid_domain("example.com")
        assert IOCValidator.is_valid_domain("sub.example.com")
        assert IOCValidator.is_valid_domain("example.co.uk")

    def test_invalid_domain(self):
        assert not IOCValidator.is_valid_domain("")
        assert not IOCValidator.is_valid_domain("invalid domain with spaces")
        assert not IOCValidator.is_valid_domain(".example.com")

    def test_valid_url(self):
        assert IOCValidator.is_valid_url("https://example.com")
        assert IOCValidator.is_valid_url("http://example.com/path")
        assert IOCValidator.is_valid_url("ftp://example.com")

    def test_invalid_url(self):
        assert not IOCValidator.is_valid_url("not a url")
        assert not IOCValidator.is_valid_url("example.com")  # Missing scheme

    def test_valid_email(self):
        assert IOCValidator.is_valid_email("user@example.com")
        assert IOCValidator.is_valid_email("test.user@example.co.uk")

    def test_invalid_email(self):
        assert not IOCValidator.is_valid_email("not-an-email")
        assert not IOCValidator.is_valid_email("@example.com")
        assert not IOCValidator.is_valid_email("user@")

    def test_valid_hashes(self):
        assert IOCValidator.is_valid_md5("d41d8cd98f00b204e9800998ecf8427e")
        assert IOCValidator.is_valid_sha1("da39a3ee5e6b4b0d3255bfef95601890afd80709")
        assert IOCValidator.is_valid_sha256(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )

    def test_invalid_hashes(self):
        assert not IOCValidator.is_valid_md5("too-short")
        assert not IOCValidator.is_valid_md5("z" * 32)  # Invalid hex
        assert not IOCValidator.is_valid_sha256("a" * 63)  # Too short

    def test_detect_hash_type(self):
        assert IOCValidator.detect_hash_type("d41d8cd98f00b204e9800998ecf8427e") == "hash_md5"
        assert (
            IOCValidator.detect_hash_type("da39a3ee5e6b4b0d3255bfef95601890afd80709")
            == "hash_sha1"
        )
        assert (
            IOCValidator.detect_hash_type(
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            )
            == "hash_sha256"
        )
        assert IOCValidator.detect_hash_type("not-a-hash") is None

    def test_valid_cve(self):
        assert IOCValidator.is_valid_cve("CVE-2021-1234")
        assert IOCValidator.is_valid_cve("CVE-2021-12345")

    def test_invalid_cve(self):
        assert not IOCValidator.is_valid_cve("CVE-123")
        assert not IOCValidator.is_valid_cve("not-a-cve")

    def test_valid_mac_address(self):
        assert IOCValidator.is_valid_mac_address("00:11:22:33:44:55")
        assert IOCValidator.is_valid_mac_address("00-11-22-33-44-55")

    def test_normalize_mac_address(self):
        assert IOCValidator.normalize_mac_address("00-11-22-33-44-55") == "00:11:22:33:44:55"
        assert IOCValidator.normalize_mac_address("AA:BB:CC:DD:EE:FF") == "aa:bb:cc:dd:ee:ff"


class TestDomainMatcher:
    """Tests for DomainMatcher class."""

    def test_is_subdomain(self):
        assert DomainMatcher.is_subdomain("sub.example.com", "example.com")
        assert DomainMatcher.is_subdomain("example.com", "example.com")
        assert DomainMatcher.is_subdomain("deep.sub.example.com", "example.com")

    def test_is_not_subdomain(self):
        assert not DomainMatcher.is_subdomain("notexample.com", "example.com")
        assert not DomainMatcher.is_subdomain("example.org", "example.com")

    def test_extract_domain_from_url(self):
        assert DomainMatcher.extract_domain_from_url("https://example.com/path") == "example.com"
        assert DomainMatcher.extract_domain_from_url("http://sub.example.com") == "sub.example.com"

    def test_extract_base_domain(self):
        assert DomainMatcher.extract_base_domain("sub.example.com") == "example.com"
        assert DomainMatcher.extract_base_domain("example.com") == "example.com"
        assert DomainMatcher.extract_base_domain("deep.sub.example.com") == "example.com"


class TestIPMatcher:
    """Tests for IPMatcher class."""

    def test_ip_in_cidr(self):
        assert IPMatcher.ip_in_cidr("192.0.2.50", "192.0.2.0/24")
        assert IPMatcher.ip_in_cidr("192.0.2.1", "192.0.2.0/24")
        assert IPMatcher.ip_in_cidr("192.0.2.254", "192.0.2.0/24")

    def test_ip_not_in_cidr(self):
        assert not IPMatcher.ip_in_cidr("192.0.3.1", "192.0.2.0/24")
        assert not IPMatcher.ip_in_cidr("10.0.0.1", "192.0.2.0/24")

    def test_is_private_ip(self):
        assert IPMatcher.is_private_ip("10.0.0.1")
        assert IPMatcher.is_private_ip("172.16.0.1")
        assert IPMatcher.is_private_ip("192.168.1.1")
        assert not IPMatcher.is_private_ip("8.8.8.8")

    def test_is_reserved_ip(self):
        assert IPMatcher.is_reserved_ip("127.0.0.1")  # Loopback
        assert IPMatcher.is_reserved_ip("10.0.0.1")  # Private
        assert IPMatcher.is_reserved_ip("224.0.0.1")  # Multicast
        assert not IPMatcher.is_reserved_ip("8.8.8.8")


class TestHashCalculator:
    """Tests for HashCalculator class."""

    def test_calculate_hashes(self):
        data = b"test data"

        md5 = HashCalculator.calculate_md5(data)
        assert len(md5) == 32
        assert IOCValidator.is_valid_md5(md5)

        sha1 = HashCalculator.calculate_sha1(data)
        assert len(sha1) == 40
        assert IOCValidator.is_valid_sha1(sha1)

        sha256 = HashCalculator.calculate_sha256(data)
        assert len(sha256) == 64
        assert IOCValidator.is_valid_sha256(sha256)

    def test_calculate_all_hashes(self):
        data = b"test data"
        hashes = HashCalculator.calculate_all_hashes(data)

        assert "md5" in hashes
        assert "sha1" in hashes
        assert "sha256" in hashes
        assert "sha512" in hashes

        assert IOCValidator.is_valid_md5(hashes["md5"])
        assert IOCValidator.is_valid_sha256(hashes["sha256"])
