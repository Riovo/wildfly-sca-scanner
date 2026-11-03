#!/usr/bin/env python3
"""Scan-time PURL resolver for Trivy suppression files.

Problem:
    The canonical suppression YAML (suppressions/suppressions.yaml) uses regex patterns
    to match packages (e.g. ^pkg:maven/org\\.wildfly\\.core/.*@.*$). Trivy's .trivyignore.yaml
    only accepts exact PURLs — no regex, no wildcards. The static converter (convert_to_trivy.py)
    handles simple group/artifact patterns but must emit wildcards as global CVE suppressions
    (no PURL filter), which is overly broad, and must skip complex patterns entirely.

Solution:
    Two-pass scan. A preliminary Trivy scan discovers all actual packages (with real PURLs).
    This script matches each suppression regex against those real PURLs and outputs a resolved
    .trivyignore.yaml where every entry has exact PURLs. No global suppressions, no skipped
    patterns — even negative lookahead and character classes work because we run the original
    regex against real data instead of trying to invert it into a PURL.

Workflow (in scan-wildfly-trivy.yaml):
    1. trivy rootfs → trivy-preliminary.json     (discover packages)
    2. resolve_suppressions.py                    (regex match → exact PURLs)
    3. trivy rootfs --trivyignores resolved.yaml  (suppressed scan)

See also:
    - convert_to_trivy.py: static/commit-time converter (reference output, used by CI validation)
    - model.py: Suppression dataclass shared across all scripts
    - suppressions/suppressions.yaml: canonical source of truth for all suppression rules
"""

import json
import re
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).parent))
from model import Suppression, SIMPLE_PURL_RE, purl_from_simple_match, parse_until_date


def _strip_version(purl):
    """Remove version from a PURL: pkg:maven/g/a@1.0 → pkg:maven/g/a

    Trivy's .trivyignore.yaml matches all versions when the PURL has no version qualifier.

    Caveat: for version-specific suppression patterns (e.g. httpcore@4\\..*), stripping
    the version means the emitted PURL suppresses the CVE for ALL versions of that artifact,
    not just the matched version range. This is intentional — Trivy has no PURL version range
    syntax, and versioned PURLs break on patch bumps. WildFly doesn't ship multiple major
    versions of the same artifact, so this is the safer tradeoff.
    """
    # Also strips qualifiers (?type=pom) and subpaths (#sub/path) — intentional,
    # since Trivy matches on the pkg:type/ns/name prefix.
    at = purl.find("@")
    return purl[:at] if at != -1 else purl


def _extract_purls(trivy_json):
    """Extract all unique PURLs from Trivy JSON scan output.

    Reads from two locations in the Trivy JSON structure:
    - Results[].Packages[].Identifier.PURL — all detected packages (including those without vulns)
    - Results[].Vulnerabilities[].PkgIdentifier.PURL — packages with known vulnerabilities

    Both are needed: Packages gives us the full inventory for pattern matching,
    Vulnerabilities catches any PURLs that might only appear there.
    """
    purls = set()
    for result in trivy_json.get("Results", []):
        for pkg in result.get("Packages", []):
            purl = pkg.get("Identifier", {}).get("PURL", "")
            if purl:
                purls.add(purl)
        for vuln in result.get("Vulnerabilities", []):
            purl = vuln.get("PkgIdentifier", {}).get("PURL", "")
            if purl:
                purls.add(purl)
    return purls


def _resolve_pattern(pattern, discovered_purls):
    """Match a suppression regex against discovered PURLs.

    Uses fullmatch() rather than search() for defensive matching — all canonical
    patterns use ^...$ anchors, but fullmatch prevents partial matches if an
    unanchored pattern is added.

    Handles all pattern types: wildcards, negative lookahead (?!...), character
    classes [^/], alternation (a|b), and version-specific constraints (@4\\..*).

    Returns version-stripped PURLs (sorted, deduplicated) so the .trivyignore.yaml
    entry matches all versions of each matched artifact.
    """
    try:
        compiled = re.compile(pattern)
    except re.error:
        return []

    matched = set()
    for purl in discovered_purls:
        if compiled.fullmatch(purl):
            matched.add(_strip_version(purl))
    return sorted(matched)


def resolve(canonical_yaml_path, trivy_json_path, output_path):
    """Resolve suppression patterns against discovered PURLs and write .trivyignore.yaml.

    Processing order for each suppression entry:
        1. CPE-only corrections → skip (Trivy doesn't use CPE matching)
        2. No package-url (filePath-only) → skip with warning
        3. Exact group/artifact pattern → pass through as-is (no scan data needed)
        4. Wildcard/complex pattern → regex match against discovered PURLs
           - Matches found → emit with exact PURLs
           - No matches → skip (package absent from this WildFly version)

    The output file is guaranteed to have no global suppressions — every entry has a
    purls list. This is the key improvement over the static converter.
    """
    with open(canonical_yaml_path) as f:
        data = yaml.safe_load(f)

    if not data or "suppressions" not in data:
        raise ValueError(f"{canonical_yaml_path} is empty or missing 'suppressions' key")

    with open(trivy_json_path) as f:
        trivy_json = json.load(f)

    discovered_purls = _extract_purls(trivy_json)
    suppressions = [Suppression.from_dict(d) for d in data["suppressions"]]

    resolved_count = 0
    exact_count = 0
    skipped_cpe = 0
    skipped_filepath = 0
    skipped_no_match = 0
    trivy_entries = []

    for s in suppressions:
        all_cve_ids = s.cves + s.vulnerability_names

        # CPE corrections only suppress CPE-to-product mappings — Trivy doesn't use CPEs
        if s.type == "cpe-correction" and not all_cve_ids:
            skipped_cpe += 1
            continue

        if not all_cve_ids:
            print(
                f"  WARNING: Skipping {s.id} — no CVEs or vulnerability-names to suppress.",
                file=sys.stderr,
            )
            continue

        # filePath-based matches have no PURL equivalent in Trivy
        if not s.package_url:
            if s.file_path:
                skipped_filepath += 1
                print(
                    f"  WARNING: Skipping {s.id} — filePath-based match cannot be resolved to PURLs.",
                    file=sys.stderr,
                )
            else:
                print(
                    f"  WARNING: Skipping {s.id} — no package-url or file-path match defined.",
                    file=sys.stderr,
                )
            continue

        # Fast path: exact group/artifact patterns don't need scan data
        m = SIMPLE_PURL_RE.match(s.package_url)
        if m:
            purl = purl_from_simple_match(m)
            exact_count += 1

            for cve in all_cve_ids:
                entry = {"id": cve, "purls": [purl]}
                # expired_at must be a datetime.date for PyYAML to emit an unquoted YAML date.
                # Trivy's Go YAML parser rejects quoted date strings.
                if s.until:
                    entry["expired_at"] = parse_until_date(s.until, s.id)
                statement_parts = []
                if s.notes:
                    statement_parts.append(s.notes.strip().split("\n")[0].strip())
                if s.references:
                    statement_parts.append(s.references[0])
                if statement_parts:
                    entry["statement"] = " | ".join(statement_parts)
                trivy_entries.append(entry)
            continue

        # Wildcard/complex path: match the regex against real PURLs from the scan
        matched_purls = _resolve_pattern(s.package_url, discovered_purls)
        if not matched_purls:
            skipped_no_match += 1
            print(
                f"  INFO: Skipping {s.id} — pattern {s.package_url} matched no packages in this scan.",
                file=sys.stderr,
            )
            continue

        resolved_count += 1
        for cve in all_cve_ids:
            entry = {"id": cve, "purls": matched_purls}
            if s.until:
                entry["expired_at"] = parse_until_date(s.until, s.id)
            statement_parts = [f"Resolved from pattern: {s.package_url}"]
            if s.notes:
                statement_parts.append(s.notes.strip().split("\n")[0].strip())
            if s.references:
                statement_parts.append(s.references[0])
            entry["statement"] = " | ".join(statement_parts)
            trivy_entries.append(entry)

    trivy_data = {"vulnerabilities": trivy_entries}

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w") as f:
        f.write("# Resolved .trivyignore.yaml — generated at scan time from canonical YAML + Trivy scan.\n")
        f.write("# All entries have exact PURLs; no global suppressions.\n\n")
        yaml.dump(trivy_data, f, default_flow_style=False, sort_keys=False, allow_unicode=True, width=120)

    print(f"Resolved {len(trivy_entries)} CVE suppression entries")
    print(f"  {exact_count} exact-match entries (pass-through)")
    print(f"  {resolved_count} wildcard/complex patterns resolved against {len(discovered_purls)} discovered PURLs")
    if skipped_cpe:
        print(f"  {skipped_cpe} CPE-only corrections skipped (not applicable to Trivy)")
    if skipped_filepath:
        print(f"  {skipped_filepath} filePath-only entries skipped")
    if skipped_no_match:
        print(f"  {skipped_no_match} patterns matched no packages in this scan")
    print(f"Output: {output_path}")


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: resolve_suppressions.py <canonical.yaml> <trivy-scan.json> <output.yaml>", file=sys.stderr)
        sys.exit(1)
    try:
        resolve(sys.argv[1], sys.argv[2], sys.argv[3])
    except (ValueError, json.JSONDecodeError) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)
