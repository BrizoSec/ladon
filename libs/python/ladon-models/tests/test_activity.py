"""Tests for Activity models."""

from datetime import datetime

import pytest

from ladon_models import (
    ActivityEventType,
    ActivitySource,
    DNSFields,
    EmailFields,
    FileFields,
    HostFields,
    HTTPFields,
    NetworkFields,
    NormalizedActivity,
    ProcessFields,
    RawActivity,
    UserFields,
)


class TestNetworkFields:
    """Tests for NetworkFields model."""

    def test_create_network_fields(self):
        network = NetworkFields(
            src_ip="10.0.1.100",
            src_port=54321,
            dst_ip="192.0.2.1",
            dst_port=443,
            domain="evil.com",
            protocol="HTTPS",
        )
        assert network.src_ip == "10.0.1.100"
        assert network.dst_port == 443
        assert network.domain == "evil.com"

    def test_normalize_domain(self):
        network = NetworkFields(domain="EVIL.COM")
        assert network.domain == "evil.com"


class TestHostFields:
    """Tests for HostFields model."""

    def test_create_host_fields(self):
        host = HostFields(
            hostname="workstation-01",
            fqdn="workstation-01.corp.local",
            ip_address="10.0.1.100",
            os="Windows 10",
        )
        assert host.hostname == "workstation-01"
        assert host.os == "Windows 10"


class TestUserFields:
    """Tests for UserFields model."""

    def test_create_user_fields(self):
        user = UserFields(
            username="jdoe", domain="CORP", email="jdoe@corp.local", uid=1001
        )
        assert user.username == "jdoe"
        assert user.domain == "CORP"
        assert user.uid == 1001


class TestProcessFields:
    """Tests for ProcessFields model."""

    def test_create_process_fields(self):
        process = ProcessFields(
            process_name="powershell.exe",
            process_path="C:\\Windows\\System32\\powershell.exe",
            process_id=1234,
            parent_process_id=5678,
            command_line="powershell.exe -ExecutionPolicy Bypass",
        )
        assert process.process_name == "powershell.exe"
        assert process.process_id == 1234


class TestFileFields:
    """Tests for FileFields model."""

    def test_create_file_fields(self):
        file_fields = FileFields(
            file_name="malware.exe",
            file_path="C:\\Temp\\malware.exe",
            file_hash_sha256="a" * 64,
            file_size=1024000,
        )
        assert file_fields.file_name == "malware.exe"
        assert file_fields.file_size == 1024000


class TestEmailFields:
    """Tests for EmailFields model."""

    def test_create_email_fields(self):
        email = EmailFields(
            sender="attacker@evil.com",
            recipient="victim@company.com",
            recipients=["victim@company.com", "other@company.com"],
            subject="Urgent: Please review",
            attachment_names=["invoice.pdf"],
        )
        assert email.sender == "attacker@evil.com"
        assert len(email.recipients) == 2


class TestDNSFields:
    """Tests for DNSFields model."""

    def test_create_dns_fields(self):
        dns = DNSFields(
            query="evil.com",
            query_type="A",
            response_code=0,
            answers=["192.0.2.1", "192.0.2.2"],
        )
        assert dns.query == "evil.com"
        assert len(dns.answers) == 2

    def test_normalize_query(self):
        dns = DNSFields(query="EVIL.COM", query_type="A")
        assert dns.query == "evil.com"


class TestHTTPFields:
    """Tests for HTTPFields model."""

    def test_create_http_fields(self):
        http = HTTPFields(
            method="GET",
            status_code=200,
            user_agent="Mozilla/5.0",
            content_type="text/html",
        )
        assert http.method == "GET"
        assert http.status_code == 200


class TestRawActivity:
    """Tests for RawActivity model."""

    def test_create_raw_activity(self):
        raw = RawActivity(
            source=ActivitySource.DNS,
            raw_event={"query": "evil.com", "type": "A"},
            event_id="evt_123",
        )
        assert raw.source == ActivitySource.DNS
        assert raw.raw_event["query"] == "evil.com"


class TestNormalizedActivity:
    """Tests for NormalizedActivity model."""

    def test_create_dns_activity(self):
        activity = NormalizedActivity(
            event_id="evt_12345",
            timestamp=datetime.utcnow(),
            source=ActivitySource.DNS,
            event_type=ActivityEventType.DNS_QUERY,
            network=NetworkFields(src_ip="10.0.1.100", domain="evil.com"),
            dns=DNSFields(query="evil.com", query_type="A", answers=["192.0.2.1"]),
        )
        assert activity.event_id == "evt_12345"
        assert activity.source == ActivitySource.DNS
        assert activity.dns.query == "evil.com"

    def test_create_http_activity(self):
        activity = NormalizedActivity(
            event_id="evt_12345",
            timestamp=datetime.utcnow(),
            source=ActivitySource.PROXY,
            event_type=ActivityEventType.HTTP_REQUEST,
            network=NetworkFields(
                src_ip="10.0.1.100",
                dst_ip="192.0.2.1",
                dst_port=80,
                url="http://evil.com/malware",
            ),
            http=HTTPFields(method="GET", user_agent="curl/7.68.0"),
        )
        assert activity.source == ActivitySource.PROXY
        assert activity.http.method == "GET"

    def test_create_edr_activity(self):
        activity = NormalizedActivity(
            event_id="evt_12345",
            timestamp=datetime.utcnow(),
            source=ActivitySource.MDE,
            event_type=ActivityEventType.PROCESS_CREATE,
            host=HostFields(hostname="workstation-01", os="Windows 10"),
            process=ProcessFields(
                process_name="powershell.exe",
                process_id=1234,
                command_line="powershell.exe -enc ...",
            ),
            file=FileFields(
                file_path="C:\\Windows\\System32\\powershell.exe",
                file_hash_sha256="a" * 64,
            ),
        )
        assert activity.source == ActivitySource.MDE
        assert activity.process.process_name == "powershell.exe"

    def test_populate_quick_access_fields(self):
        activity = NormalizedActivity(
            event_id="evt_12345",
            timestamp=datetime.utcnow(),
            source=ActivitySource.DNS,
            event_type=ActivityEventType.DNS_QUERY,
            network=NetworkFields(src_ip="10.0.1.100", domain="evil.com"),
            host=HostFields(hostname="workstation-01"),
            user=UserFields(username="jdoe"),
            process=ProcessFields(process_name="chrome.exe"),
            file=FileFields(file_hash_sha256="a" * 64),
        )

        # Quick-access fields should be populated from structured fields
        assert activity.src_ip == "10.0.1.100"
        assert activity.domain == "evil.com"
        assert activity.hostname == "workstation-01"
        assert activity.user_name == "jdoe"
        assert activity.process_name == "chrome.exe"
        assert activity.file_hash == "a" * 64

    def test_extract_ioc_values(self):
        activity = NormalizedActivity(
            event_id="evt_12345",
            timestamp=datetime.utcnow(),
            source=ActivitySource.DNS,
            event_type=ActivityEventType.DNS_QUERY,
            network=NetworkFields(
                src_ip="10.0.1.100", dst_ip="8.8.8.8", domain="evil.com"
            ),
            dns=DNSFields(query="evil.com", query_type="A", answers=["192.0.2.1"]),
            file=FileFields(
                file_hash_md5="d41d8cd98f00b204e9800998ecf8427e",
                file_hash_sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            email=EmailFields(
                sender="attacker@evil.com",
                recipients=["victim1@company.com", "victim2@company.com"],
            ),
        )

        ioc_values = activity.extract_ioc_values()

        # Check IPs
        assert "10.0.1.100" in ioc_values["ip"]
        assert "8.8.8.8" in ioc_values["ip"]

        # Check domains
        assert "evil.com" in ioc_values["domain"]
        assert "192.0.2.1" in ioc_values["domain"]  # DNS answer

        # Check hashes
        assert "d41d8cd98f00b204e9800998ecf8427e" in ioc_values["hash"]
        assert (
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            in ioc_values["hash"]
        )

        # Check emails
        assert "attacker@evil.com" in ioc_values["email"]
        assert "victim1@company.com" in ioc_values["email"]

    def test_extract_ioc_values_deduplication(self):
        activity = NormalizedActivity(
            event_id="evt_12345",
            timestamp=datetime.utcnow(),
            source=ActivitySource.DNS,
            event_type=ActivityEventType.DNS_QUERY,
            network=NetworkFields(domain="evil.com"),
            dns=DNSFields(query="evil.com", query_type="A"),
        )

        ioc_values = activity.extract_ioc_values()

        # Domain appears in both network and dns fields, should be deduplicated
        assert ioc_values["domain"].count("evil.com") == 1
