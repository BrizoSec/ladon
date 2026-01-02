"""
Enumerations for LADON data models.

This module defines all enumeration types used across the LADON platform,
including IOC types, threat types, severity levels, and detection statuses.
"""

from enum import Enum


class IOCType(str, Enum):
    """Types of Indicators of Compromise supported by the platform."""

    # Network indicators
    IP = "ip"
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"

    # File indicators
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"
    HASH_SHA512 = "hash_sha512"
    FILE_PATH = "file_path"
    FILE_NAME = "file_name"

    # User/Account indicators
    USERNAME = "username"
    ACCOUNT_NUMBER = "account_number"
    USER_AGENT = "user_agent"

    # Certificate indicators
    SSL_CERT_FINGERPRINT = "ssl_cert_fingerprint"
    JA3_FINGERPRINT = "ja3_fingerprint"

    # Registry indicators (Windows)
    REGISTRY_KEY = "registry_key"

    # Process indicators
    PROCESS_NAME = "process_name"
    MUTEX = "mutex"

    # Other
    CVE = "cve"
    ASN = "asn"
    CIDR = "cidr"
    MAC_ADDRESS = "mac_address"
    IMPHASH = "imphash"
    SSDEEP = "ssdeep"


class ThreatType(str, Enum):
    """Categories of threats associated with IOCs."""

    MALWARE = "malware"
    RANSOMWARE = "ransomware"
    TROJAN = "trojan"
    BACKDOOR = "backdoor"
    SPYWARE = "spyware"
    ADWARE = "adware"
    ROOTKIT = "rootkit"

    C2 = "c2"  # Command and Control
    BOTNET = "botnet"

    PHISHING = "phishing"
    SPAM = "spam"

    EXPLOIT = "exploit"
    VULNERABILITY = "vulnerability"

    APT = "apt"  # Advanced Persistent Threat
    TARGETED_ATTACK = "targeted_attack"

    DATA_EXFILTRATION = "data_exfiltration"
    LATERAL_MOVEMENT = "lateral_movement"

    CRYPTOMINING = "cryptomining"
    DDoS = "ddos"

    SUSPICIOUS = "suspicious"
    ANOMALOUS = "anomalous"
    UNKNOWN = "unknown"


class Severity(str, Enum):
    """Severity levels for detections and alerts."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class DetectionStatus(str, Enum):
    """Status of a detection throughout its lifecycle."""

    NEW = "New"
    INVESTIGATING = "Investigating"
    FALSE_POSITIVE = "False Positive"
    CONFIRMED = "Confirmed"
    RESOLVED = "Resolved"
    CLOSED = "Closed"
    ESCALATED = "Escalated"


class ActivitySource(str, Enum):
    """Sources of activity log data."""

    PROXY = "proxy"
    DNS = "dns"
    SINKHOLE = "sinkhole"
    MDE = "mde"  # Microsoft Defender for Endpoint
    CROWDSTRIKE = "crowdstrike"
    FIREWALL = "firewall"
    VPN = "vpn"
    EMAIL_GATEWAY = "email_gateway"
    WEB_GATEWAY = "web_gateway"
    EDR = "edr"  # Generic Endpoint Detection and Response
    SIEM = "siem"
    NETFLOW = "netflow"
    PCAP = "pcap"
    AUTH_LOGS = "auth_logs"
    CLOUD_TRAIL = "cloud_trail"
    AZURE_AD = "azure_ad"
    OKTA = "okta"
    OTHER = "other"


class ActivityEventType(str, Enum):
    """Types of activity events."""

    DNS_QUERY = "dns_query"
    DNS_RESPONSE = "dns_response"

    HTTP_REQUEST = "http_request"
    HTTP_RESPONSE = "http_response"
    HTTPS_REQUEST = "https_request"

    NETWORK_CONNECTION = "network_connection"
    NETWORK_FLOW = "network_flow"

    PROCESS_CREATE = "process_create"
    PROCESS_TERMINATE = "process_terminate"
    PROCESS_INJECTION = "process_injection"

    FILE_CREATE = "file_create"
    FILE_DELETE = "file_delete"
    FILE_MODIFY = "file_modify"
    FILE_RENAME = "file_rename"

    REGISTRY_CREATE = "registry_create"
    REGISTRY_MODIFY = "registry_modify"
    REGISTRY_DELETE = "registry_delete"

    USER_LOGIN = "user_login"
    USER_LOGOUT = "user_logout"
    USER_FAILED_LOGIN = "user_failed_login"

    EMAIL_SEND = "email_send"
    EMAIL_RECEIVE = "email_receive"

    OTHER = "other"


class IOCSource(str, Enum):
    """Sources of threat intelligence IOCs."""

    ALIENVAULT_OTX = "alienvault"
    ABUSE_CH = "abuse.ch"
    MISP = "misp"
    THREAT_FOX = "threatfox"
    URL_HAUS = "urlhaus"
    MALWARE_BAZAAR = "malwarebazaar"
    FEODO_TRACKER = "feodotracker"

    VIRUSTOTAL = "virustotal"
    HYBRID_ANALYSIS = "hybrid_analysis"
    ANY_RUN = "anyrun"

    EMERGING_THREATS = "emerging_threats"
    PROOFPOINT = "proofpoint"
    RECORDED_FUTURE = "recorded_future"
    CROWDSTRIKE_INTEL = "crowdstrike_intel"

    INTERNAL = "internal"
    CUSTOM = "custom"
    MANUAL = "manual"
    OTHER = "other"


class EnrichmentProvider(str, Enum):
    """External enrichment API providers."""

    VIRUSTOTAL = "virustotal"
    PASSIVETOTAL = "passivetotal"
    SHODAN = "shodan"
    CENSYS = "censys"
    GREYNOISE = "greynoise"
    ABUSEIPDB = "abuseipdb"
    IPQUALITYSCORE = "ipqualityscore"
    MAXMIND = "maxmind"
    WHOIS = "whois"
    URLSCAN = "urlscan"
    HYBRID_ANALYSIS = "hybrid_analysis"
    JOE_SANDBOX = "joe_sandbox"
    INTERNAL = "internal"
    OTHER = "other"
