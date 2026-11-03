#!/usr/bin/env python3
"""Check that owasp-suppressions.xml hasn't drifted from the canonical YAML.

Validates that changes to the OWASP DC XML are made through the canonical YAML
(edit YAML → regenerate XML), not by editing the XML directly. Compares
suppression IDs and CVE lists from both paths to detect drift.

Used by: .github/workflows/validate-suppressions.yaml
"""

import sys
import tempfile
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).parent))
from migrate_from_owaspdc import migrate
from convert_to_owaspdc import convert as convert_to_owaspdc


def check_drift(original_xml_path, canonical_yaml_path):
    """Compare original XML against canonical YAML via round-trip migration.

    Round-trips both directions and compares the normalized suppression data:
      1. original XML → migrate → YAML₁
      2. canonical YAML → convert to XML → migrate back → YAML₂
    If the sorted (id, CVEs) tuples differ, the XML has drifted.
    """
    with tempfile.TemporaryDirectory() as tmp:
        from_xml_path = str(Path(tmp) / "from-xml.yaml")
        from_yaml_xml_path = str(Path(tmp) / "from-yaml.xml")
        from_yaml_rt_path = str(Path(tmp) / "from-yaml-rt.yaml")

        migrate(original_xml_path, from_xml_path)
        convert_to_owaspdc(canonical_yaml_path, from_yaml_xml_path)
        migrate(from_yaml_xml_path, from_yaml_rt_path)

        from_xml = _extract_signatures(from_xml_path)
        from_yaml = _extract_signatures(from_yaml_rt_path)

        if from_xml != from_yaml:
            print("ERROR: owasp-suppressions.xml has drifted from suppressions.yaml "
                  "— edit the canonical YAML and regenerate", file=sys.stderr)
            return False
        return True


def _extract_signatures(yaml_path):
    """Extract sorted signature tuples for comparison.

    Compares: id, type, CVEs, vulnerability-names, CPEs, until date, and match patterns.
    """
    with open(yaml_path) as f:
        data = yaml.safe_load(f)
    entries = []
    for s in sorted(data["suppressions"], key=lambda x: x["id"]):
        suppress = s.get("suppress") or {}
        match = s.get("match") or {}
        sig = (
            s["id"],
            s.get("type"),
            sorted(suppress.get("cves", [])),
            sorted(suppress.get("vulnerability-names", [])),
            sorted(suppress.get("cpes", [])),
            s.get("until"),
            match.get("package-url"),
            match.get("file-path"),
        )
        entries.append(sig)
    return entries


if __name__ == "__main__":
    original_xml = sys.argv[1] if len(sys.argv) > 1 else "owasp-suppressions/owasp-suppressions.xml"
    canonical_yaml = sys.argv[2] if len(sys.argv) > 2 else "suppressions/suppressions.yaml"
    if not check_drift(original_xml, canonical_yaml):
        sys.exit(1)
    print("OK: owasp-suppressions.xml is consistent with suppressions.yaml")
