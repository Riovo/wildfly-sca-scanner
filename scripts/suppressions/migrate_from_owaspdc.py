#!/usr/bin/env python3
"""Migrate OWASP Dependency Check suppression XML to canonical YAML format."""

import re
import sys
from datetime import date
from pathlib import Path

import defusedxml.ElementTree as ET
import yaml

sys.path.insert(0, str(Path(__file__).parent))
from model import Suppression

NS = {"dc": "https://jeremylong.github.io/DependencyCheck/dependency-suppression.1.3.xsd"}


def slugify(text):
    text = text.lower()
    text = re.sub(r"[^a-z0-9]+", "-", text)
    return text.strip("-")[:60]


def extract_id(suppression):
    """Generate a human-readable ID from the suppression's match pattern and suppress targets."""
    if suppression.package_url:
        match = re.search(r"pkg:maven/([^@]+)@", suppression.package_url)
        if match:
            artifact = match.group(1).replace("/", "-").replace("\\.", ".").replace("\\-", "-")
            artifact = re.sub(r"[\\().*+?^$\[\]{}|]", "", artifact)
        else:
            artifact = slugify(suppression.package_url[:40])
    elif suppression.file_path:
        match = re.search(r"([a-zA-Z0-9_-]+)\.jar", suppression.file_path)
        artifact = match.group(1) if match else slugify(suppression.file_path[:40])
    else:
        artifact = "unknown"

    all_cve_ids = suppression.cves + suppression.vulnerability_names
    if suppression.cpes and not all_cve_ids:
        cpe_part = suppression.cpes[0].split(":")[-1] if suppression.cpes else ""
        return slugify(f"cpe-{artifact}-{cpe_part}")
    elif all_cve_ids:
        cve_part = all_cve_ids[0].lower()
        return slugify(f"{artifact}-{cve_part}")
    else:
        return slugify(f"suppress-{artifact}")


def parse_suppress_element(elem):
    """Parse a single <suppress> element into a Suppression object."""
    until = elem.get("until")

    notes_elem = elem.find("dc:notes", NS)
    notes = notes_elem.text.strip() if notes_elem is not None and notes_elem.text else ""

    pkg_url_elem = elem.find("dc:packageUrl", NS)
    package_url = None
    if pkg_url_elem is not None and pkg_url_elem.text:
        package_url = pkg_url_elem.text.strip()

    file_path_elem = elem.find("dc:filePath", NS)
    file_path = None
    if file_path_elem is not None and file_path_elem.text:
        file_path = file_path_elem.text.strip()

    cves = []
    for cve_elem in elem.findall("dc:cve", NS):
        if cve_elem.text:
            cves.append(cve_elem.text.strip())

    vulnerability_names = []
    for vuln_elem in elem.findall("dc:vulnerabilityName", NS):
        if vuln_elem.text:
            vulnerability_names.append(vuln_elem.text.strip())

    cpes = []
    for cpe_elem in elem.findall("dc:cpe", NS):
        if cpe_elem.text:
            cpes.append(cpe_elem.text.strip())

    all_cve_ids = cves + vulnerability_names
    if cpes and not all_cve_ids:
        sup_type = "cpe-correction"
    else:
        sup_type = "cve-triage"

    suppression = Suppression(
        id="",  # set after creation
        type=sup_type,
        notes=notes,
        package_url=package_url,
        file_path=file_path,
        cves=cves,
        cpes=cpes,
        until=until,
        vulnerability_names=vulnerability_names,
    )

    references = []
    for line in notes.split("\n"):
        line = line.strip()
        if line.startswith("http://") or line.startswith("https://"):
            references.append(line)
    suppression.references = references

    suppression.id = extract_id(suppression)

    return suppression


def deduplicate_ids(suppressions):
    """Ensure all IDs are unique by appending a counter to duplicates."""
    seen = {}
    all_ids = {s.id for s in suppressions}
    for s in suppressions:
        if s.id in seen:
            seen[s.id] += 1
            new_id = f"{s.id}-{seen[s.id]}"
            while new_id in all_ids:
                seen[s.id] += 1
                new_id = f"{s.id}-{seen[s.id]}"
            s.id = new_id
            all_ids.add(new_id)
        else:
            seen[s.id] = 1


def migrate(input_path, output_path):
    tree = ET.parse(input_path)
    root = tree.getroot()

    suppressions = []
    for elem in root.findall("dc:suppress", NS):
        suppression = parse_suppress_element(elem)
        suppressions.append(suppression)

    deduplicate_ids(suppressions)

    cpe_corrections = [s for s in suppressions if s.type == "cpe-correction"]
    cve_triages = [s for s in suppressions if s.type == "cve-triage"]

    today = date.today().isoformat()
    expired = [s for s in cve_triages if s.until and s.until < today]
    if expired:
        print(f"\nWARNING: {len(expired)} suppression(s) have expired 'until' dates:")
        for s in expired:
            all_ids = s.cves + s.vulnerability_names
            print(f"  - {s.id}: until={s.until} ({', '.join(all_ids)})")
        print()

    ordered = cpe_corrections + cve_triages
    data = {
        "version": "1.0",
        "suppressions": [s.to_dict() for s in ordered],
    }

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w") as f:
        f.write("# Canonical vulnerability suppression rules\n")
        f.write("# Source of truth — scanner-specific formats are generated from this file.\n")
        f.write("# Migrated from owasp-suppressions/owasp-suppressions.xml\n\n")
        yaml.dump(data, f, default_flow_style=False, sort_keys=False, allow_unicode=True, width=120)

    print(f"Migrated {len(suppressions)} suppressions:")
    print(f"  - {len(cpe_corrections)} CPE corrections (permanent)")
    print(f"  - {len(cve_triages)} CVE triages")
    print(f"Output: {output_path}")


if __name__ == "__main__":
    input_path = sys.argv[1] if len(sys.argv) > 1 else "owasp-suppressions/owasp-suppressions.xml"
    output_path = sys.argv[2] if len(sys.argv) > 2 else "suppressions/suppressions.yaml"
    migrate(input_path, output_path)
