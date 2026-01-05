#!/usr/bin/env python3
"""Test script for AlienVault OTX collection.

This script:
1. Fetches IOCs from AlienVault OTX API
2. Publishes to Pub/Sub (or prints to console)
3. Tests the collection pipeline

Usage:
    # Option 1: Use .env file (recommended)
    cp .env.example .env
    # Edit .env and add your API key
    python scripts/test_alienvault.py

    # Option 2: Export environment variable
    export ALIENVAULT_API_KEY="your_api_key_here"
    python scripts/test_alienvault.py
"""

import asyncio
import json
import os
import sys
from datetime import datetime, timezone
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

from threat_extractors.alienvault_threat_extractor import AlienVaultThreatExtractor


class AlienVaultOTXCollector:
    """Collector for AlienVault OTX threat intelligence feed."""

    def __init__(self, api_key: str):
        """Initialize AlienVault OTX collector.

        Args:
            api_key: AlienVault OTX API key
        """
        self.api_key = api_key
        self.base_url = "https://otx.alienvault.com/api/v1"
        self.session = None
        self.threat_extractor = AlienVaultThreatExtractor()

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create HTTP session."""
        if self.session is None or self.session.closed:
            import ssl
            headers = {"X-OTX-API-KEY": self.api_key}
            # Create SSL context that doesn't verify certificates (for testing only)
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

    async def get_pulses(self, modified_since: str = None, limit: int = 10):
        """Get threat intelligence pulses from AlienVault OTX.

        Args:
            modified_since: ISO timestamp to get pulses modified since (e.g., "2024-01-01T00:00:00")
            limit: Maximum number of pulses to retrieve

        Returns:
            List of pulses
        """
        session = await self._get_session()
        url = f"{self.base_url}/pulses/subscribed"

        params = {"limit": limit}
        if modified_since:
            params["modified_since"] = modified_since

        print(f"\n🔍 Fetching pulses from AlienVault OTX...")
        print(f"   URL: {url}")
        print(f"   Params: {params}")

        try:
            async with session.get(url, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    pulses = data.get("results", [])
                    print(f"✅ Retrieved {len(pulses)} pulses")
                    return pulses
                else:
                    error_text = await response.text()
                    print(f"❌ Error {response.status}: {error_text}")
                    return []
        except Exception as e:
            print(f"❌ Exception: {e}")
            return []

    def extract_iocs_from_pulse(self, pulse: dict):
        """Extract IOCs from a pulse.

        Args:
            pulse: AlienVault pulse dictionary

        Returns:
            List of raw IOC events
        """
        iocs = []
        pulse_indicators = pulse.get("indicators", [])

        for indicator in pulse_indicators:
            ioc = {
                "source": "alienvault",
                "pulse_id": pulse.get("id"),
                "pulse_name": pulse.get("name"),
                "ioc_value": indicator.get("indicator"),
                "ioc_type": indicator.get("type"),
                "description": indicator.get("description"),
                "created": indicator.get("created"),
                "tags": pulse.get("tags", []),
                "threat_type": self._map_threat_type(pulse.get("tags", [])),
                "confidence": self._calculate_confidence(pulse),
                "tlp": pulse.get("TLP", "white"),
                "adversary": pulse.get("adversary"),
                "malware_families": pulse.get("malware_families", []),
                "attack_ids": pulse.get("attack_ids", []),
                "industries": pulse.get("industries", []),
                "countries": pulse.get("targeted_countries", []),
            }
            iocs.append(ioc)

        return iocs

    def extract_threats_from_pulse(self, pulse: dict):
        """Extract threat intelligence from a pulse.

        Args:
            pulse: AlienVault pulse dictionary

        Returns:
            List of threat dictionaries
        """
        threats = self.threat_extractor.extract_threats(pulse)
        return threats

    def extract_threat_ioc_associations(self, pulse: dict, threat_id: str):
        """Extract threat-IOC associations from a pulse.

        Args:
            pulse: AlienVault pulse dictionary
            threat_id: ID of the threat

        Returns:
            List of threat-IOC association dictionaries
        """
        associations = self.threat_extractor.extract_threat_ioc_associations(pulse, threat_id)
        return associations

    def _map_threat_type(self, tags: list) -> str:
        """Map tags to threat type."""
        tag_str = " ".join(tags).lower()

        if any(word in tag_str for word in ["malware", "trojan", "virus", "backdoor"]):
            return "malware"
        elif any(word in tag_str for word in ["c2", "c&c", "command", "control"]):
            return "c2"
        elif any(word in tag_str for word in ["phishing", "phish"]):
            return "phishing"
        elif any(word in tag_str for word in ["exploit", "vulnerability", "cve"]):
            return "exploit"
        elif any(word in tag_str for word in ["ransomware", "ransom"]):
            return "ransomware"
        else:
            return "unknown"

    def _calculate_confidence(self, pulse: dict) -> float:
        """Calculate confidence score based on pulse metadata."""
        base_confidence = 0.5

        # Increase confidence for verified sources
        if pulse.get("author_name") in ["AlienVault", "Verified"]:
            base_confidence += 0.2

        # Increase confidence based on subscriber count
        subscriber_count = pulse.get("subscriber_count", 0)
        if subscriber_count > 100:
            base_confidence += 0.1
        elif subscriber_count > 50:
            base_confidence += 0.05

        # Increase confidence for recent pulses
        created = pulse.get("created")
        if created:
            # Recent pulses are more valuable
            base_confidence += 0.1

        return min(base_confidence, 1.0)


async def main():
    """Test AlienVault collection."""
    # Get API key
    api_key = os.getenv("ALIENVAULT_API_KEY")
    if not api_key:
        print("❌ Error: ALIENVAULT_API_KEY environment variable not set")
        print("\nTo get an API key:")
        print("1. Sign up at https://otx.alienvault.com/")
        print("2. Go to Settings > API Integration")
        print("3. Copy your API key")
        print("4. Set environment variable: export ALIENVAULT_API_KEY='your_key'")
        return

    print("=" * 80)
    print("AlienVault OTX Collection Test")
    print("=" * 80)

    # Create collector
    collector = AlienVaultOTXCollector(api_key)

    try:
        # Get recent pulses (last 7 days)
        # For testing, get only 5 pulses
        pulses = await collector.get_pulses(limit=5)

        if not pulses:
            print("\n⚠️  No pulses retrieved. Check your API key and network connection.")
            return

        # Extract IOCs and threats from pulses
        print(f"\n📊 Processing {len(pulses)} pulses...")
        total_iocs = 0
        total_threats = 0
        total_associations = 0

        all_threats = []
        all_associations = []

        for i, pulse in enumerate(pulses, 1):
            print(f"\n--- Pulse {i}: {pulse.get('name')} ---")
            print(f"   Author: {pulse.get('author_name')}")
            print(f"   Created: {pulse.get('created')}")
            print(f"   Tags: {', '.join(pulse.get('tags', [])[:5])}")
            print(f"   Indicators: {len(pulse.get('indicators', []))}")

            # Extract IOCs
            iocs = collector.extract_iocs_from_pulse(pulse)
            total_iocs += len(iocs)

            # Extract threats
            threats = collector.extract_threats_from_pulse(pulse)
            total_threats += len(threats)
            all_threats.extend(threats)

            # Show threat information
            if threats:
                print(f"\n   🎯 Threats Extracted: {len(threats)}")
                for threat in threats:
                    print(f"      • {threat['name']} ({threat['threat_category']})")
                    print(f"        Type: {threat['threat_type']}")
                    print(f"        Confidence: {threat['confidence']:.2f}")
                    if threat.get('techniques'):
                        print(f"        MITRE Techniques: {len(threat['techniques'])}")
                        # Show first 2 techniques
                        for tech in threat['techniques'][:2]:
                            print(f"          - {tech['technique_id']}: {tech['technique_name']}")
                    if threat.get('tactics'):
                        print(f"        Tactics: {', '.join(threat['tactics'][:3])}")

                    # Extract associations for this threat
                    associations = collector.extract_threat_ioc_associations(pulse, threat['threat_id'])
                    total_associations += len(associations)
                    all_associations.extend(associations)
                    print(f"        Associated IOCs: {len(associations)}")

            # Show first 3 IOCs from this pulse
            print(f"\n   Sample IOCs:")
            for ioc in iocs[:3]:
                print(f"      • {ioc['ioc_type']}: {ioc['ioc_value']}")
                print(f"        Threat: {ioc['threat_type']}, Confidence: {ioc['confidence']:.2f}")

        print(f"\n" + "=" * 80)
        print(f"✅ Collection Complete!")
        print(f"   Total Pulses: {len(pulses)}")
        print(f"   Total IOCs: {total_iocs}")
        print(f"   Total Threats: {total_threats}")
        print(f"   Total Threat-IOC Associations: {total_associations}")
        print(f"   Average IOCs per pulse: {total_iocs / len(pulses):.1f}")
        print(f"   Average Threats per pulse: {total_threats / len(pulses):.1f}")
        print("=" * 80)

        # Show threat summary
        if all_threats:
            print(f"\n📊 Threat Summary:")
            threat_categories = {}
            for threat in all_threats:
                category = threat['threat_category']
                threat_categories[category] = threat_categories.get(category, 0) + 1
            for category, count in threat_categories.items():
                print(f"   • {category}: {count}")

        # Save sample output
        output_file = Path(__file__).parent / "sample_alienvault_output.json"
        with open(output_file, "w") as f:
            sample_data = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "pulses_count": len(pulses),
                "total_iocs": total_iocs,
                "total_threats": total_threats,
                "total_associations": total_associations,
                "sample_pulses": pulses[:2],  # Save first 2 pulses as sample
                "sample_threats": all_threats[:3],  # Save first 3 threats
                "sample_associations": all_associations[:5],  # Save first 5 associations
            }
            json.dump(sample_data, f, indent=2)
        print(f"\n💾 Sample data saved to: {output_file}")

    finally:
        await collector.close()


if __name__ == "__main__":
    asyncio.run(main())
