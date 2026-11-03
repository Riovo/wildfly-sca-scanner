#!/usr/bin/env python3
"""Convert canonical YAML → OWASP Dependency Check XML format.

Generates the roundtrip XML (owasp-suppressions/owasp-suppressions-roundtrip.xml) and is
used by CI validation to verify that the canonical YAML and original OWASP DC XML haven't
drifted apart. The XML preserves all information losslessly — OWASP DC uses every field
(packageUrl, filePath, cve, vulnerabilityName, cpe, until, notes).

This is the reverse of migrate_from_owaspdc.py. Together they form a round-trip:
    XML → migrate → YAML → convert_to_owaspdc → XML (should match original)

See also:
    - migrate_from_owaspdc.py: the forward direction (XML → YAML)
    - validate-suppressions.yaml: CI workflow that runs the drift check
"""

import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).parent))
from model import Suppression

NS = "https://jeremylong.github.io/DependencyCheck/dependency-suppression.1.3.xsd"


def _escape_xml(text):
    """Escape XML special characters."""
    text = text.replace("&", "&amp;")
    text = text.replace("<", "&lt;")
    text = text.replace(">", "&gt;")
    text = text.replace('"', "&quot;")
    return text


def _escape_cdata(text):
    """Escape text for use inside CDATA sections.

    CDATA sections cannot contain the literal ']]>' — the XML spec requires splitting
    the section at that point: close the current CDATA, emit '>' as text, reopen CDATA.
    """
    return text.replace("]]>", "]]]]><![CDATA[>")


def _build_suppress_xml(s):
    """Build a single <suppress> element as a string.

    Element ordering (notes, packageUrl, filePath, cve, vulnerabilityName, cpe) follows
    OWASP DC conventions for consistency with the original hand-maintained XML.
    """
    parts = []

    attr = ""
    if s.until:
        attr = f' until="{_escape_xml(s.until)}"'

    parts.append(f"   <suppress{attr}>")
    notes = _escape_cdata(s.notes or "")
    parts.append(f"      <notes><![CDATA[\n      {notes}\n      ]]></notes>")

    if s.package_url:
        parts.append(f'      <packageUrl regex="true">{_escape_xml(s.package_url)}</packageUrl>')
    if s.file_path:
        parts.append(f'      <filePath regex="true">{_escape_xml(s.file_path)}</filePath>')

    for cve in s.cves:
        parts.append(f"      <cve>{_escape_xml(cve)}</cve>")

    for vn in s.vulnerability_names:
        parts.append(f"      <vulnerabilityName>{_escape_xml(vn)}</vulnerabilityName>")

    for cpe in s.cpes:
        parts.append(f"      <cpe>{_escape_xml(cpe)}</cpe>")

    parts.append("   </suppress>")
    return "\n".join(parts)


def convert(input_path, output_path):
    with open(input_path) as f:
        data = yaml.safe_load(f)

    if not data or "suppressions" not in data:
        raise ValueError(f"{input_path} is empty or missing 'suppressions' key")

    suppressions = [Suppression.from_dict(d) for d in data["suppressions"]]

    cpe_corrections = [s for s in suppressions if s.type == "cpe-correction"]
    cve_triages = [s for s in suppressions if s.type == "cve-triage"]

    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        f'<suppressions xmlns="{NS}">',
        "   <!-- CPE Suppressions -->",
        "   <!-- Sometimes the mapping from GAV to CPE creates a bad match, this section suppresses those matches. -->",
    ]

    for s in cpe_corrections:
        lines.append(_build_suppress_xml(s))

    lines.append("")
    lines.append("   <!-- CVE Suppressions -->")
    lines.append("")

    for s in cve_triages:
        lines.append(_build_suppress_xml(s))

    lines.append("</suppressions>")
    lines.append("")

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    print(f"Converted {len(suppressions)} suppressions to OWASP DC XML")
    print(f"  - {len(cpe_corrections)} CPE corrections")
    print(f"  - {len(cve_triages)} CVE triages")
    print(f"Output: {output_path}")


if __name__ == "__main__":
    input_path = sys.argv[1] if len(sys.argv) > 1 else "suppressions/suppressions.yaml"
    output_path = sys.argv[2] if len(sys.argv) > 2 else "owasp-suppressions/owasp-suppressions-roundtrip.xml"
    try:
        convert(input_path, output_path)
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)
