#!/usr/bin/env python3
"""Test AlienVault IOC normalization.

This script:
1. Loads the sample AlienVault data collected earlier
2. Feeds it through the AlienVaultOTXNormalizer
3. Shows before/after transformation
4. Validates the normalized output

Usage:
    python scripts/test_normalization.py
"""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

# Add paths
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "normalization" / "src"))

try:
    from normalizers.ioc_normalizers import AlienVaultOTXNormalizer
    from ladon_models import NormalizedIOC
except ImportError as e:
    print(f"❌ Import error: {e}")
    print("\nMake sure you're in the collection service directory:")
    print("  cd /Users/chemch/ladon/services/collection")
    sys.exit(1)


def load_sample_data():
    """Load the sample AlienVault data."""
    sample_file = Path(__file__).parent / "sample_alienvault_output.json"

    if not sample_file.exists():
        print(f"❌ Sample data not found: {sample_file}")
        print("\nRun this first to collect sample data:")
        print("  python scripts/test_alienvault.py")
        sys.exit(1)

    with open(sample_file, "r") as f:
        data = json.load(f)

    return data


def extract_iocs_from_pulse(pulse: dict):
    """Extract raw IOC events from a pulse (same as collector does)."""
    iocs = []
    pulse_indicators = pulse.get("indicators", [])

    for indicator in pulse_indicators:
        # This is the RAW format that the Collection Service would send
        ioc = {
            "source": "alienvault",
            "pulse_id": pulse.get("id"),
            "pulse_name": pulse.get("name"),
            "ioc_value": indicator.get("indicator"),
            "ioc_type": indicator.get("type"),
            "description": indicator.get("description"),
            "created": indicator.get("created"),
            "tags": pulse.get("tags", []),
            "threat_type": _map_threat_type(pulse.get("tags", [])),  # ← Add this
            "confidence": _calculate_confidence(pulse),  # ← Add this
            "tlp": pulse.get("TLP", "white"),
            "adversary": pulse.get("adversary"),
            "malware_families": pulse.get("malware_families", []),
            "attack_ids": pulse.get("attack_ids", []),
            "industries": pulse.get("industries", []),
            "countries": pulse.get("targeted_countries", []),
        }
        iocs.append(ioc)

    return iocs


def _map_threat_type(tags: list) -> str:
    """Map tags to threat type (same as collector does)."""
    tag_str = " ".join(tags).lower()

    if any(word in tag_str for word in ["malware", "trojan", "virus", "backdoor", "rat", "stealer"]):
        return "malware"
    elif any(word in tag_str for word in ["c2", "c&c", "command", "control"]):
        return "c2"
    elif any(word in tag_str for word in ["phishing", "phish"]):
        return "phishing"
    elif any(word in tag_str for word in ["exploit", "vulnerability", "cve"]):
        return "exploit"
    elif any(word in tag_str for word in ["ransomware", "ransom"]):
        return "ransomware"
    elif any(word in tag_str for word in ["spyware", "surveillance"]):
        return "spyware"
    else:
        return "unknown"


def _calculate_confidence(pulse: dict) -> float:
    """Calculate confidence score (same as collector does)."""
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

    return min(base_confidence, 1.0)


def print_section(title, char="="):
    """Print a section header."""
    print(f"\n{char * 80}")
    print(title)
    print(f"{char * 80}\n")


def print_ioc_comparison(raw_ioc, normalized_ioc):
    """Print before/after comparison."""
    print("┌─ RAW IOC (from AlienVault) ─────────────────────────────────────┐")
    print(f"│ Value: {raw_ioc.get('ioc_value', 'N/A')[:50]}")
    print(f"│ Type:  {raw_ioc.get('ioc_type', 'N/A')}")
    print(f"│ Tags:  {', '.join(raw_ioc.get('tags', [])[:3])}")
    print("└──────────────────────────────────────────────────────────────────┘")
    print("                            ↓ NORMALIZATION ↓")
    print("┌─ NORMALIZED IOC (LADON format) ──────────────────────────────────┐")
    if normalized_ioc:
        print(f"│ Value:       {normalized_ioc.ioc_value[:50]}")
        print(f"│ Type:        {normalized_ioc.ioc_type}")
        print(f"│ Threat Type: {normalized_ioc.threat_type}")
        print(f"│ Confidence:  {normalized_ioc.confidence:.2f}")
        print(f"│ Source:      {normalized_ioc.source}")
        print(f"│ First Seen:  {normalized_ioc.first_seen}")
        print(f"│ Tags:        {', '.join(normalized_ioc.tags[:3])}")
        if hasattr(normalized_ioc.metadata, '__dict__'):
            print(f"│ Metadata:    {len(vars(normalized_ioc.metadata))} fields")
        print("└──────────────────────────────────────────────────────────────────┘")
    else:
        print("│ ❌ FAILED TO NORMALIZE")
        print("└──────────────────────────────────────────────────────────────────┘")


def main():
    """Test normalization."""
    print_section("AlienVault IOC Normalization Test")

    # Load sample data
    print("📂 Loading sample AlienVault data...")
    sample_data = load_sample_data()

    pulses = sample_data.get("sample_pulses", [])
    print(f"   Found {len(pulses)} pulses in sample data")

    # Create normalizer
    print("\n🔧 Creating AlienVaultOTXNormalizer...")
    normalizer = AlienVaultOTXNormalizer(skip_invalid=False)

    # Process all IOCs
    all_raw_iocs = []
    for pulse in pulses:
        iocs = extract_iocs_from_pulse(pulse)
        all_raw_iocs.extend(iocs)

    print(f"   Extracted {len(all_raw_iocs)} raw IOCs from pulses")

    # Normalize IOCs
    print_section("Normalization Results", "-")

    normalized_count = 0
    failed_count = 0
    skipped_count = 0

    # Show first 5 IOCs in detail
    print("📊 Detailed view (first 5 IOCs):\n")
    for i, raw_ioc in enumerate(all_raw_iocs[:5], 1):
        print(f"--- IOC #{i} ---")

        normalized_ioc = normalizer.normalize(raw_ioc)

        if normalized_ioc:
            normalized_count += 1
            print_ioc_comparison(raw_ioc, normalized_ioc)
        else:
            failed_count += 1
            print(f"❌ Failed to normalize: {raw_ioc.get('ioc_value')}")
            print(f"   Type: {raw_ioc.get('ioc_type')}")

        print()

    # Process remaining IOCs (just count)
    if len(all_raw_iocs) > 5:
        print(f"\n⏩ Processing remaining {len(all_raw_iocs) - 5} IOCs...\n")
        for raw_ioc in all_raw_iocs[5:]:
            normalized_ioc = normalizer.normalize(raw_ioc)
            if normalized_ioc:
                normalized_count += 1
            else:
                failed_count += 1

    # Summary
    print_section("Normalization Summary")

    print(f"📊 Statistics:")
    print(f"   Total Raw IOCs:        {len(all_raw_iocs)}")
    print(f"   ✅ Successfully Normalized: {normalized_count}")
    print(f"   ❌ Failed to Normalize:     {failed_count}")
    print(f"   ⏭️  Skipped (invalid):       {skipped_count}")
    print(f"   📈 Success Rate:            {(normalized_count / len(all_raw_iocs) * 100):.1f}%")

    # IOC type breakdown
    print(f"\n📋 IOC Types Normalized:")
    type_counts = {}
    for raw_ioc in all_raw_iocs:
        ioc_type = raw_ioc.get("ioc_type", "unknown")
        type_counts[ioc_type] = type_counts.get(ioc_type, 0) + 1

    for ioc_type, count in sorted(type_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"   • {ioc_type:20s}: {count:3d} IOCs")

    # Threat type breakdown
    print(f"\n🎯 Threat Types Identified:")
    threat_counts = {}
    for raw_ioc in all_raw_iocs:
        normalized_ioc = normalizer.normalize(raw_ioc)
        if normalized_ioc:
            threat_type = normalized_ioc.threat_type
            threat_counts[threat_type] = threat_counts.get(threat_type, 0) + 1

    for threat_type, count in sorted(threat_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"   • {threat_type:20s}: {count:3d} IOCs")

    print("\n" + "=" * 80)

    if normalized_count == len(all_raw_iocs):
        print("✅ All IOCs normalized successfully!")
    elif normalized_count > 0:
        print(f"⚠️  {failed_count} IOCs failed to normalize (check logs above)")
    else:
        print("❌ Normalization failed completely")

    print("=" * 80 + "\n")

    # Next steps
    print("🎯 Next Steps:")
    print("   1. Review the normalized IOC format above")
    print("   2. Check if threat_type mapping is accurate")
    print("   3. Verify confidence scores make sense")
    print("   4. Test with the actual Normalization Service (Option B)")
    print()


if __name__ == "__main__":
    main()
