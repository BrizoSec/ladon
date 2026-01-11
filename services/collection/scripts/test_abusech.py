#!/usr/bin/env python3
"""Test script for abuse.ch collection.

abuse.ch provides multiple free threat intelligence feeds:
- ThreatFox: IOCs for malware families (C2, malware distribution)
- URLhaus: Malicious URLs used for malware distribution
- MalwareBazaar: Malware samples (file hashes)

This script:
1. Fetches IOCs from abuse.ch APIs (requires free Auth-Key)
2. Tests normalization
3. Compares with AlienVault results

Usage:
    # Option 1: Use .env file (recommended)
    cp .env.example .env
    # Edit .env and add your Auth-Key
    python scripts/test_abusech.py

    # Option 2: Export environment variable
    export ABUSECH_API_KEY="your_auth_key_here"
    python scripts/test_abusech.py

To get a free Auth-Key:
    1. Go to https://auth.abuse.ch/
    2. Sign up using X, LinkedIn, Google, or GitHub
    3. Connect at least one additional authentication provider
    4. Create an Auth-Key in the "Optional" section
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

from threat_extractors.abusech_threat_extractor import AbuseCHThreatExtractor


class AbuseCHCollector:
    """Collector for abuse.ch threat intelligence feeds."""

    def __init__(self, auth_key: str):
        """Initialize abuse.ch collector.

        Args:
            auth_key: abuse.ch Auth-Key (get free key from https://auth.abuse.ch/)
        """
        self.auth_key = auth_key
        self.threatfox_url = "https://threatfox-api.abuse.ch/api/v1/"
        self.urlhaus_url = "https://urlhaus-api.abuse.ch/v1/"
        self.malwarebazaar_url = "https://mb-api.abuse.ch/api/v1/"
        self.session = None
        self.threat_extractor = AbuseCHThreatExtractor()

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create HTTP session."""
        if self.session is None or self.session.closed:
            import ssl
            # Headers with Auth-Key
            headers = {"Auth-Key": self.auth_key}
            # SSL context for abuse.ch
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

    async def get_threatfox_iocs(self, days: int = 1, limit: int = 10):
        """Get recent IOCs from ThreatFox.

        Args:
            days: Number of days to look back
            limit: Maximum number of IOCs to retrieve

        Returns:
            List of IOCs
        """
        session = await self._get_session()

        print(f"\n🔍 Fetching IOCs from ThreatFox (abuse.ch)...")
        print(f"   URL: {self.threatfox_url}")
        print(f"   Looking back: {days} days")
        print(f"   Auth-Key: {self.auth_key[:8]}...{self.auth_key[-4:]} (length: {len(self.auth_key)})")

        # ThreatFox API: Get recent IOCs
        payload = {
            "query": "get_iocs",
            "days": days
        }

        try:
            async with session.post(self.threatfox_url, json=payload) as response:
                if response.status == 200:
                    data = await response.json()

                    if data.get("query_status") == "ok":
                        iocs = data.get("data", [])[:limit]  # Limit results
                        print(f"✅ Retrieved {len(iocs)} IOCs from ThreatFox")
                        return iocs
                    else:
                        print(f"⚠️  Query status: {data.get('query_status')}")
                        return []
                else:
                    error_text = await response.text()
                    print(f"❌ Error {response.status}: {error_text}")
                    return []
        except Exception as e:
            print(f"❌ Exception: {e}")
            return []

    async def get_urlhaus_urls(self, limit: int = 10):
        """Get recent malicious URLs from URLhaus.

        Args:
            limit: Maximum number of URLs to retrieve

        Returns:
            List of URLs
        """
        session = await self._get_session()

        print(f"\n🔍 Fetching URLs from URLhaus (abuse.ch)...")
        print(f"   URL: {self.urlhaus_url}urls/recent/limit/{limit}/")

        try:
            url = f"{self.urlhaus_url}urls/recent/limit/{limit}/"
            async with session.get(url) as response:
                if response.status == 200:
                    data = await response.json()

                    if data.get("query_status") == "ok":
                        urls = data.get("urls", [])
                        print(f"✅ Retrieved {len(urls)} URLs from URLhaus")
                        return urls
                    else:
                        print(f"⚠️  Query status: {data.get('query_status')}")
                        return []
                else:
                    error_text = await response.text()
                    print(f"❌ Error {response.status}: {error_text}")
                    return []
        except Exception as e:
            print(f"❌ Exception: {e}")
            return []

    def extract_iocs_from_threatfox(self, raw_iocs: list):
        """Extract and normalize IOCs from ThreatFox format.

        Args:
            raw_iocs: Raw IOC list from ThreatFox

        Returns:
            List of formatted IOC events
        """
        iocs = []
        for item in raw_iocs:
            ioc = {
                "source": "abuse_ch_threatfox",
                "ioc_value": item.get("ioc"),
                "ioc_type": self._map_threatfox_type(item.get("ioc_type")),
                "threat_type": item.get("threat_type", "malware"),
                "malware_family": item.get("malware"),
                "malware_alias": item.get("malware_alias"),
                "malware_printable": item.get("malware_printable"),
                "confidence": self._map_confidence_level(item.get("confidence_level", 50)),
                "first_seen": item.get("first_seen_utc"),
                "last_seen": item.get("last_seen_utc"),
                "tags": item.get("tags", []),
                "reporter": item.get("reporter"),
                "reference": item.get("reference"),
            }
            iocs.append(ioc)

        return iocs

    def extract_iocs_from_urlhaus(self, raw_urls: list):
        """Extract and normalize IOCs from URLhaus format.

        Args:
            raw_urls: Raw URL list from URLhaus

        Returns:
            List of formatted IOC events
        """
        iocs = []
        for item in raw_urls:
            ioc = {
                "source": "abuse_ch_urlhaus",
                "ioc_value": item.get("url"),
                "ioc_type": "url",
                "threat_type": self._map_urlhaus_threat(item.get("threat")),
                "url_status": item.get("url_status"),
                "confidence": 0.8 if item.get("url_status") == "online" else 0.6,
                "first_seen": item.get("dateadded"),
                "tags": item.get("tags", []),
                "reporter": item.get("reporter"),
                "larted": item.get("larted"),
                "takedown_time_seconds": item.get("takedown_time_seconds"),
            }
            iocs.append(ioc)

        return iocs

    def extract_threats(self, threatfox_iocs: list, urlhaus_iocs: list):
        """Extract threat intelligence from abuse.ch IOC data.

        Args:
            threatfox_iocs: List of ThreatFox IOCs
            urlhaus_iocs: List of URLhaus IOCs

        Returns:
            List of threat dictionaries
        """
        # Combine data for threat extraction
        raw_data = {
            "threatfox_iocs": threatfox_iocs,
            "urlhaus_iocs": urlhaus_iocs,
        }
        threats = self.threat_extractor.extract_threats(raw_data)
        return threats

    def extract_threat_ioc_associations(self, threatfox_iocs: list, urlhaus_iocs: list, threat_id: str):
        """Extract threat-IOC associations from abuse.ch data.

        Args:
            threatfox_iocs: List of ThreatFox IOCs
            urlhaus_iocs: List of URLhaus IOCs
            threat_id: ID of the threat

        Returns:
            List of threat-IOC association dictionaries
        """
        raw_data = {
            "threatfox_iocs": threatfox_iocs,
            "urlhaus_iocs": urlhaus_iocs,
        }
        associations = self.threat_extractor.extract_threat_ioc_associations(raw_data, threat_id)
        return associations

    def _map_threatfox_type(self, ioc_type: str) -> str:
        """Map ThreatFox IOC type to standard type."""
        type_mapping = {
            "ip:port": "ipv4",  # Extract IP, ignore port
            "domain": "domain",
            "url": "url",
            "md5_hash": "hash_md5",
            "sha256_hash": "hash_sha256",
        }
        return type_mapping.get(ioc_type, ioc_type)

    def _map_confidence_level(self, level: int) -> float:
        """Map ThreatFox confidence level (0-100) to float (0.0-1.0)."""
        return min(level / 100.0, 1.0)

    def _map_urlhaus_threat(self, threat: str) -> str:
        """Map URLhaus threat type."""
        if not threat:
            return "malware"

        threat_lower = threat.lower()
        if "malware" in threat_lower:
            return "malware"
        elif "phish" in threat_lower:
            return "phishing"
        else:
            return "malware"


async def main():
    """Test abuse.ch collection."""
    # Get Auth-Key
    auth_key = os.getenv("ABUSECH_API_KEY")
    if not auth_key:
        print("❌ Error: ABUSECH_API_KEY environment variable not set")
        print("\nTo get a free Auth-Key:")
        print("1. Go to https://auth.abuse.ch/")
        print("2. Sign up using X, LinkedIn, Google, or GitHub")
        print("3. Connect at least one additional authentication provider")
        print("4. Create an Auth-Key in the 'Optional' section")
        print("5. Set environment variable: export ABUSECH_API_KEY='your_key'")
        print("\nOr add to .env file:")
        print("   ABUSECH_API_KEY=your_key_here")
        return

    print("=" * 80)
    print("abuse.ch Collection Test")
    print("=" * 80)

    # Create collector
    collector = AbuseCHCollector(auth_key)

    try:
        # Get ThreatFox IOCs
        threatfox_raw = await collector.get_threatfox_iocs(days=1, limit=10)
        threatfox_iocs = []

        if threatfox_raw:
            print(f"\n📊 Processing {len(threatfox_raw)} ThreatFox IOCs...")
            threatfox_iocs = collector.extract_iocs_from_threatfox(threatfox_raw)

            # Show first 3 IOCs
            print(f"\n--- Sample ThreatFox IOCs ---")
            for i, ioc in enumerate(threatfox_iocs[:3], 1):
                print(f"\n   IOC #{i}:")
                print(f"      Type:          {ioc['ioc_type']}")
                print(f"      Value:         {ioc['ioc_value'][:60]}")
                print(f"      Threat Type:   {ioc['threat_type']}")
                print(f"      Malware:       {ioc['malware_family']}")
                print(f"      Confidence:    {ioc['confidence']:.2f}")
                print(f"      Tags:          {', '.join(ioc['tags'][:3])}")

        # Get URLhaus URLs
        urlhaus_raw = await collector.get_urlhaus_urls(limit=10)
        urlhaus_iocs = []

        if urlhaus_raw:
            print(f"\n📊 Processing {len(urlhaus_raw)} URLhaus entries...")
            urlhaus_iocs = collector.extract_iocs_from_urlhaus(urlhaus_raw)

            # Show first 3 URLs
            print(f"\n--- Sample URLhaus IOCs ---")
            for i, ioc in enumerate(urlhaus_iocs[:3], 1):
                print(f"\n   URL #{i}:")
                print(f"      URL:           {ioc['ioc_value'][:60]}")
                print(f"      Threat Type:   {ioc['threat_type']}")
                print(f"      Status:        {ioc['url_status']}")
                print(f"      Confidence:    {ioc['confidence']:.2f}")
                print(f"      Tags:          {', '.join(ioc['tags'][:3])}")

        # Extract threats from all IOCs
        print(f"\n🎯 Extracting threat intelligence...")
        threats = collector.extract_threats(threatfox_iocs, urlhaus_iocs)
        all_associations = []

        if threats:
            print(f"\n--- Threats Extracted: {len(threats)} ---")
            for i, threat in enumerate(threats, 1):
                print(f"\n   Threat #{i}: {threat['name']} ({threat['threat_category']})")
                print(f"      Type:         {threat['threat_type']}")
                print(f"      Confidence:   {threat['confidence']:.2f}")
                if threat.get('metadata'):
                    metadata = threat['metadata']
                    if metadata.get('malware_type'):
                        print(f"      Malware Type: {metadata['malware_type']}")
                    if metadata.get('platform'):
                        print(f"      Platform:     {metadata['platform']}")
                    if metadata.get('feed'):
                        print(f"      Feed:         {metadata['feed']}")

                # Extract associations for this threat
                associations = collector.extract_threat_ioc_associations(
                    threatfox_iocs, urlhaus_iocs, threat['threat_id']
                )
                all_associations.extend(associations)
                print(f"      Associated IOCs: {len(associations)}")

        # Summary
        print(f"\n" + "=" * 80)
        print(f"✅ Collection Complete!")

        total_iocs = len(threatfox_iocs) + len(urlhaus_iocs)

        print(f"   ThreatFox IOCs: {len(threatfox_iocs)}")
        print(f"   URLhaus IOCs:   {len(urlhaus_iocs)}")
        print(f"   Total IOCs:     {total_iocs}")
        print(f"   Total Threats:  {len(threats)}")
        print(f"   Total Threat-IOC Associations: {len(all_associations)}")
        print("=" * 80)

        # Show threat summary
        if threats:
            print(f"\n📊 Threat Summary:")
            threat_categories = {}
            for threat in threats:
                category = threat['threat_category']
                threat_categories[category] = threat_categories.get(category, 0) + 1
            for category, count in threat_categories.items():
                print(f"   • {category}: {count}")

        # Save sample output
        if threatfox_raw or urlhaus_raw:
            output_file = Path(__file__).parent / "sample_abusech_output.json"
            with open(output_file, "w") as f:
                sample_data = {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "threatfox_iocs": threatfox_iocs,
                    "urlhaus_iocs": urlhaus_iocs,
                    "total_iocs": total_iocs,
                    "threats": threats[:3],  # Save first 3 threats
                    "total_threats": len(threats),
                    "associations": all_associations[:5],  # Save first 5 associations
                    "total_associations": len(all_associations),
                }
                json.dump(sample_data, f, indent=2)
            print(f"\n💾 Sample data saved to: {output_file}")

        # Comparison with AlienVault
        print(f"\n🔍 Comparison with AlienVault OTX:")
        print(f"   abuse.ch ThreatFox:  Free, no API key, C2 and malware IOCs")
        print(f"   abuse.ch URLhaus:    Free, no API key, malicious URLs")
        print(f"   AlienVault OTX:      Free, API key required, broad coverage")
        print(f"\n   Both sources complement each other well!")

    finally:
        await collector.close()


if __name__ == "__main__":
    asyncio.run(main())
