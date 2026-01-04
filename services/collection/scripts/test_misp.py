#!/usr/bin/env python3
"""Test script for MISP collection.

MISP (Malware Information Sharing Platform) is an open-source threat intelligence
platform for sharing, storing, and correlating IOCs.

This script:
1. Fetches events and attributes from a MISP instance
2. Extracts IOCs from MISP attributes
3. Tests normalization
4. Compares with other sources

Usage:
    # Option 1: Use .env file (recommended)
    cp .env.example .env
    # Edit .env and add your MISP URL and API key
    python scripts/test_misp.py

    # Option 2: Export environment variables
    export MISP_URL="https://your-misp-instance.com"
    export MISP_API_KEY="your_api_key_here"
    python scripts/test_misp.py

MISP Setup:
    1. You need access to a MISP instance (cloud or self-hosted)
    2. Get your API key from: MISP → Global Actions → My Profile → Auth Keys
    3. Public MISP instances: https://www.misp-project.org/communities/
"""

import asyncio
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import aiohttp
from dotenv import load_dotenv

# Load .env file if it exists
env_path = Path(__file__).parent.parent / ".env"
if env_path.exists():
    load_dotenv(env_path)
    print(f"✅ Loaded environment from: {env_path}")
else:
    print(f"ℹ️  No .env file found at: {env_path}")
    print("   Using system environment variables")

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


class MISPCollector:
    """Collector for MISP threat intelligence platform."""

    def __init__(self, misp_url: str, api_key: str, verify_ssl: bool = True):
        """Initialize MISP collector.

        Args:
            misp_url: MISP instance URL (e.g., https://misp.example.com)
            api_key: MISP API key (get from My Profile → Auth Keys)
            verify_ssl: Verify SSL certificates (set False for self-signed certs)
        """
        self.misp_url = misp_url.rstrip("/")
        self.api_key = api_key
        self.verify_ssl = verify_ssl
        self.session = None

    async def __aenter__(self):
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit - ensures proper cleanup."""
        await self.close()

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create HTTP session."""
        if self.session is None or self.session.closed:
            headers = {
                "Authorization": self.api_key,
                "Accept": "application/json",
                "Content-Type": "application/json",
            }

            # SSL context
            connector = None
            if not self.verify_ssl:
                import ssl
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE
                connector = aiohttp.TCPConnector(ssl=ssl_context)

            self.session = aiohttp.ClientSession(headers=headers, connector=connector)
        return self.session

    async def close(self):
        """Close HTTP session."""
        if self.session and not self.session.closed:
            await self.session.close()

    async def get_recent_events(self, days: int = 1, limit: int = 10):
        """Get recent events from MISP.

        Args:
            days: Number of days to look back
            limit: Maximum number of events to retrieve

        Returns:
            List of MISP events
        """
        session = await self._get_session()

        print(f"\n🔍 Fetching events from MISP...")
        print(f"   URL: {self.misp_url}")
        print(f"   Looking back: {days} days")
        print(f"   API Key: {self.api_key[:8]}...{self.api_key[-4:]} (length: {len(self.api_key)})")

        # MISP REST API: Search events
        # Reference: https://www.misp-project.org/openapi/
        url = f"{self.misp_url}/events/restSearch"

        # Calculate timestamp for "last N days"
        since = datetime.now(timezone.utc) - timedelta(days=days)

        payload = {
            "timestamp": since.timestamp(),
            "limit": limit,
            "published": True,  # Only published events
            "enforceWarninglist": False,
        }

        try:
            async with session.post(url, json=payload) as response:
                if response.status == 200:
                    data = await response.json()

                    # MISP returns: {"response": [{"Event": {...}}, ...]}
                    events = []
                    if isinstance(data, dict) and "response" in data:
                        for item in data["response"]:
                            if "Event" in item:
                                events.append(item["Event"])

                    print(f"✅ Retrieved {len(events)} events from MISP")
                    return events
                else:
                    error_text = await response.text()
                    print(f"❌ Error {response.status}: {error_text[:200]}")
                    return []
        except Exception as e:
            print(f"❌ Exception: {e}")
            return []

    async def get_attributes(self, event_id: str = None, days: int = 1, limit: int = 100):
        """Get attributes (IOCs) from MISP.

        Args:
            event_id: Specific event ID to get attributes from
            days: Number of days to look back (if no event_id)
            limit: Maximum number of attributes to retrieve

        Returns:
            List of MISP attributes
        """
        session = await self._get_session()

        print(f"\n🔍 Fetching attributes from MISP...")

        url = f"{self.misp_url}/attributes/restSearch"

        payload = {
            "limit": limit,
            "enforceWarninglist": False,
            "to_ids": True,  # Only IOC attributes
        }

        if event_id:
            payload["eventid"] = event_id
            print(f"   Event ID: {event_id}")
        else:
            since = datetime.now(timezone.utc) - timedelta(days=days)
            payload["timestamp"] = since.timestamp()
            print(f"   Looking back: {days} days")

        try:
            async with session.post(url, json=payload) as response:
                if response.status == 200:
                    data = await response.json()

                    # MISP returns: {"response": {"Attribute": [...]}}
                    attributes = []
                    if isinstance(data, dict) and "response" in data:
                        if "Attribute" in data["response"]:
                            attributes = data["response"]["Attribute"]

                    print(f"✅ Retrieved {len(attributes)} attributes from MISP")
                    return attributes
                else:
                    error_text = await response.text()
                    print(f"❌ Error {response.status}: {error_text[:200]}")
                    return []
        except Exception as e:
            print(f"❌ Exception: {e}")
            return []

    def extract_iocs_from_attributes(self, attributes: list):
        """Extract and normalize IOCs from MISP attributes.

        Args:
            attributes: Raw attribute list from MISP

        Returns:
            List of formatted IOC events
        """
        iocs = []
        for attr in attributes:
            ioc = {
                "source": "misp",
                "event_id": attr.get("event_id"),
                "attribute_id": attr.get("id"),
                "ioc_value": attr.get("value"),
                "ioc_type": self._map_misp_type(attr.get("type")),
                "category": attr.get("category"),
                "comment": attr.get("comment"),
                "to_ids": attr.get("to_ids"),
                "timestamp": attr.get("timestamp"),
                "first_seen": self._parse_timestamp(attr.get("first_seen")),
                "last_seen": self._parse_timestamp(attr.get("last_seen")),
                "threat_type": self._map_threat_type(attr.get("category")),
                "confidence": self._calculate_confidence(attr),
                "tags": [tag.get("name") for tag in attr.get("Tag", [])],
                "distribution": attr.get("distribution"),
                "sharing_group_id": attr.get("sharing_group_id"),
            }
            iocs.append(ioc)

        return iocs

    def _map_misp_type(self, misp_type: str) -> str:
        """Map MISP attribute type to LADON standard type."""
        type_mapping = {
            "ip-src": "ipv4",
            "ip-dst": "ipv4",
            "ip-src|port": "ipv4",
            "ip-dst|port": "ipv4",
            "domain": "domain",
            "hostname": "domain",
            "url": "url",
            "uri": "url",
            "md5": "hash_md5",
            "sha1": "hash_sha1",
            "sha256": "hash_sha256",
            "sha512": "hash_sha512",
            "ssdeep": "ssdeep",
            "imphash": "imphash",
            "email": "email",
            "email-src": "email",
            "email-dst": "email",
            "filename": "file_name",
            "filepath": "file_path",
            "mutex": "mutex",
            "vulnerability": "cve",
            "ja3-fingerprint-md5": "ja3_fingerprint",
        }
        return type_mapping.get(misp_type, misp_type)

    def _map_threat_type(self, category: str) -> str:
        """Map MISP category to threat type."""
        category_lower = (category or "").lower()

        if "payload" in category_lower or "artifacts" in category_lower:
            return "malware"
        elif "network" in category_lower:
            return "c2"
        elif "phish" in category_lower:
            return "phishing"
        elif "exploit" in category_lower or "vulnerability" in category_lower:
            return "exploit"
        else:
            return "unknown"

    def _calculate_confidence(self, attr: dict) -> float:
        """Calculate confidence score based on attribute metadata."""
        base_confidence = 0.6

        # Increase confidence if marked as IOC
        if attr.get("to_ids"):
            base_confidence += 0.2

        # Increase confidence based on distribution level
        # 0=Your org only, 1=This community, 2=Connected communities, 3=All communities
        distribution = attr.get("distribution", 0)
        if distribution >= 2:
            base_confidence += 0.1

        # Check if attribute has been seen recently
        if attr.get("first_seen") and attr.get("last_seen"):
            base_confidence += 0.1

        return min(base_confidence, 1.0)

    def _parse_timestamp(self, timestamp) -> str:
        """Parse MISP timestamp to ISO format."""
        if not timestamp:
            return None

        try:
            # MISP timestamps can be Unix epoch or ISO strings
            if isinstance(timestamp, (int, float)):
                dt = datetime.fromtimestamp(timestamp, tz=timezone.utc)
            else:
                dt = datetime.fromisoformat(str(timestamp).replace("Z", "+00:00"))
            return dt.isoformat()
        except (ValueError, OverflowError, TypeError) as e:
            # Log the specific error for debugging
            print(f"⚠️  Failed to parse timestamp {timestamp}: {e}")
            return None


async def main():
    """Test MISP collection."""
    # Get MISP credentials
    misp_url = os.getenv("MISP_URL")
    misp_api_key = os.getenv("MISP_API_KEY")
    verify_ssl = os.getenv("MISP_VERIFY_SSL", "true").lower() == "true"

    if not misp_url or not misp_api_key:
        print("❌ Error: MISP_URL and MISP_API_KEY environment variables not set")
        print("\nTo configure MISP:")
        print("1. Get access to a MISP instance (cloud or self-hosted)")
        print("2. Log in and go to: Global Actions → My Profile → Auth Keys")
        print("3. Copy your API key")
        print("4. Set environment variables:")
        print("   export MISP_URL='https://your-misp-instance.com'")
        print("   export MISP_API_KEY='your_api_key_here'")
        print("\nOr add to .env file:")
        print("   MISP_URL=https://your-misp-instance.com")
        print("   MISP_API_KEY=your_api_key_here")
        print("\nPublic MISP instances: https://www.misp-project.org/communities/")
        return

    print("=" * 80)
    print("MISP Collection Test")
    print("=" * 80)

    # Create collector with async context manager for proper cleanup
    async with MISPCollector(misp_url, misp_api_key, verify_ssl) as collector:
        # Get recent events
        events = await collector.get_recent_events(days=7, limit=5)

        if events:
            print(f"\n📊 Processing {len(events)} MISP events...")

            # Show event details
            print(f"\n--- Sample MISP Events ---")
            for i, event in enumerate(events[:3], 1):
                print(f"\n   Event #{i}:")
                print(f"      ID:            {event.get('id')}")
                print(f"      Info:          {event.get('info')[:60]}")
                print(f"      Date:          {event.get('date')}")
                print(f"      Threat Level:  {event.get('threat_level_id')}")
                print(f"      Attributes:    {len(event.get('Attribute', []))}")
                print(f"      Tags:          {', '.join([t.get('name', '') for t in event.get('Tag', [])])[:60]}")

        # Get recent attributes (IOCs)
        attributes = await collector.get_attributes(days=7, limit=20)

        if attributes:
            print(f"\n📊 Processing {len(attributes)} MISP attributes...")
            misp_iocs = collector.extract_iocs_from_attributes(attributes)

            # Show first 3 IOCs
            print(f"\n--- Sample MISP IOCs ---")
            for i, ioc in enumerate(misp_iocs[:3], 1):
                print(f"\n   IOC #{i}:")
                print(f"      Type:          {ioc['ioc_type']}")
                print(f"      Value:         {ioc['ioc_value'][:60]}")
                print(f"      Category:      {ioc['category']}")
                print(f"      Threat Type:   {ioc['threat_type']}")
                print(f"      Confidence:    {ioc['confidence']:.2f}")
                print(f"      To IDS:        {ioc['to_ids']}")
                print(f"      Tags:          {', '.join(ioc['tags'][:3])}")

        # Summary
        print(f"\n" + "=" * 80)
        print(f"✅ Collection Complete!")

        total_events = len(events) if events else 0
        total_iocs = len(misp_iocs) if attributes else 0

        print(f"   MISP Events:    {total_events}")
        print(f"   MISP IOCs:      {total_iocs}")
        print("=" * 80)

        # Save sample output
        if events or attributes:
            output_file = Path(__file__).parent / "sample_misp_output.json"
            with open(output_file, "w") as f:
                sample_data = {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "events_count": total_events,
                    "iocs_count": total_iocs,
                    "sample_events": events[:2] if events else [],
                    "sample_iocs": misp_iocs[:10] if attributes else [],
                }
                json.dump(sample_data, f, indent=2)
            print(f"\n💾 Sample data saved to: {output_file}")

        # Comparison with other sources
        print(f"\n🔍 Comparison with Other Sources:")
        print(f"   AlienVault OTX:      Community pulses, broad coverage")
        print(f"   abuse.ch ThreatFox:  C2 and malware IOCs, high confidence")
        print(f"   abuse.ch URLhaus:    Malicious URLs, online/offline status")
        print(f"   MISP:                Community sharing, structured events")
        print(f"\n   All sources provide complementary threat intelligence! 🎯")


if __name__ == "__main__":
    asyncio.run(main())
