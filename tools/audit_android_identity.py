#!/usr/bin/env python3
"""Source-only Android identity audit. Never rewrites or packages upstream."""
import json
import re
from pathlib import Path

UPSTREAM_ID = "com.winlator.banner"
TARGET_ID = "com.kernix.engine"
SOURCE = Path("engines/bannerlator_3_1_7")
OUTPUT = Path("identity-source-audit.json")

def main():
    gradle = (SOURCE / "app/build.gradle").read_text(encoding="utf-8")
    manifest = (SOURCE / "app/src/main/AndroidManifest.xml").read_text(encoding="utf-8")
    found = re.findall(r'applicationId\s+"([^"]+)"', gradle)
    if UPSTREAM_ID not in found:
        raise SystemExit("IDENTITY_AUDIT_FAIL: upstream standard package changed")
    if TARGET_ID in found:
        raise SystemExit("IDENTITY_AUDIT_FAIL: target already present unexpectedly")
    if len(found) != len(set(found)):
        raise SystemExit("IDENTITY_AUDIT_FAIL: duplicate flavors")
    providers = re.findall(r'<provider\b[^>]*?android:authorities="([^"]+)"', manifest, re.S)
    hardcoded = [p for p in providers if "${applicationId}" not in p]
    result = {
        "schema": "kernix.android-identity-source-audit.v1",
        "source_only": True,
        "upstream_standard_application_id": UPSTREAM_ID,
        "proposed_kernix_application_id": TARGET_ID,
        "upstream_flavor_application_ids": found,
        "provider_authorities": providers,
        "hardcoded_provider_authorities_require_review": hardcoded,
        "independent_kernix_apk_built": False,
        "data_migration_performed": False,
    }
    OUTPUT.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print("KERNIX_IDENTITY_SOURCE_AUDIT_PASS")
    if hardcoded:
        print("IDENTITY_REVIEW_REQUIRED:", hardcoded)

if __name__ == "__main__":
    main()
