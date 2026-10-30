#!/usr/bin/env python3
"""Convert canonical YAML suppressions to Trivy .trivyignore.yaml format."""

import datetime
import re
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).parent))
from model import Suppression

# Matches patterns like: ^pkg:maven/group\.name/artifact-name@.*$
SIMPLE_PURL_RE = re.compile(
    r"^\^?pkg:maven/"
    r"([a-zA-Z0-9_.\\-]+)"    # group (may have escaped dots/hyphens)
    r"/"
    r"([a-zA-Z0-9_.\\-]+)"    # artifact (exact, no wildcards)
    r"@\.\*\$?$"              # @.* (match all versions)
)


def _regex_to_purl(pattern):
    """Convert an OWASP DC packageUrl regex to a plain Trivy PURL.

    Returns (purl, is_exact) where:
    - purl is the plain PURL string (e.g., "pkg:maven/com.example/lib")
    - is_exact is True if the pattern maps cleanly to a single PURL,
      False if it contains wildcards and the conversion is lossy.

    Returns (None, False) if the pattern can't be converted at all.
    """
    m = SIMPLE_PURL_RE.match(pattern)
    if m:
        group = m.group(1).replace("\\.", ".").replace("\\-", "-")
        artifact = m.group(2).replace("\\.", ".").replace("\\-", "-")
        return f"pkg:maven/{group}/{artifact}", True

    # Try to extract at least a group-level PURL for wildcard patterns
    # e.g., ^pkg:maven/org\.wildfly\.core/.*@.*$ → pkg:maven/org.wildfly.core
    group_match = re.match(
        r"^\^?pkg:maven/([a-zA-Z0-9_.\\-]+)/",
        pattern,
    )
    if group_match:
        group = group_match.group(1).replace("\\.", ".").replace("\\-", "-")
        # Check if this has negative lookahead or character classes — too complex
        if "(?!" in pattern or "[^" in pattern:
            return None, False
        return f"pkg:maven/{group}", False

    return None, False


def convert(input_path, output_path):
    with open(input_path) as f:
        data = yaml.safe_load(f)

    if not data or "suppressions" not in data:
        raise ValueError(f"{input_path} is empty or missing 'suppressions' key")

    suppressions = [Suppression.from_dict(d) for d in data["suppressions"]]

    skipped_cpe = 0
    skipped_filepath_only = 0
    skipped_complex = 0
    global_suppress = 0
    trivy_entries = []

    for s in suppressions:
        all_cve_ids = s.cves + s.vulnerability_names
        if s.type == "cpe-correction" and not all_cve_ids:
            skipped_cpe += 1
            continue

        if not s.package_url:
            if s.file_path:
                skipped_filepath_only += 1
                print(
                    f"  WARNING: Skipping {s.id} — filePath-based match has no packageUrl equivalent. "
                    f"CVEs {all_cve_ids} would be globally suppressed without a PURL filter, which is unsafe.",
                    file=sys.stderr,
                )
            else:
                print(
                    f"  WARNING: Skipping {s.id} — no packageUrl or filePath match. "
                    f"CVEs {all_cve_ids} would be globally suppressed, which is unsafe.",
                    file=sys.stderr,
                )
            continue

        purl, is_exact = _regex_to_purl(s.package_url)

        if purl is None:
            skipped_complex += 1
            print(
                f"  WARNING: Skipping {s.id} — complex regex pattern cannot be converted to PURL: "
                f"{s.package_url}",
                file=sys.stderr,
            )
            continue

        for cve in all_cve_ids:
            entry = {"id": cve}

            if is_exact:
                entry["purls"] = [purl]
            else:
                # Wildcard pattern — emit without purls (global CVE suppression)
                # This is intentional: the CVE has been triaged as safe across all
                # packages matching the original pattern.
                global_suppress += 1
                entry["statement"] = f"Triaged globally (original pattern: {s.package_url})"

            if s.until:
                entry["expired_at"] = datetime.date.fromisoformat(s.until)

            if "statement" not in entry:
                statement_parts = []
                if s.notes:
                    first_line = s.notes.strip().split("\n")[0].strip()
                    statement_parts.append(first_line)
                if s.references:
                    statement_parts.append(s.references[0])
                if statement_parts:
                    entry["statement"] = " | ".join(statement_parts)

            trivy_entries.append(entry)

    trivy_data = {"vulnerabilities": trivy_entries}

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w") as f:
        f.write("# Generated from suppressions/suppressions.yaml — do not edit directly.\n")
        f.write("# Regenerate with: python scripts/suppressions/convert_to_trivy.py\n\n")
        yaml.dump(trivy_data, f, default_flow_style=False, sort_keys=False, allow_unicode=True, width=120)

    print(f"Converted {len(trivy_entries)} CVE suppressions to Trivy format")
    if global_suppress:
        print(f"  {global_suppress} entries are global (wildcard pattern, no PURL filter)")
    print(f"Skipped {skipped_cpe} CPE-only corrections (not applicable to Trivy)")
    if skipped_filepath_only:
        print(f"Skipped {skipped_filepath_only} filePath-only suppressions (no safe Trivy equivalent)")
    if skipped_complex:
        print(f"Skipped {skipped_complex} complex regex patterns (cannot convert to PURL)")
    print(f"Output: {output_path}")


if __name__ == "__main__":
    input_path = sys.argv[1] if len(sys.argv) > 1 else "suppressions/suppressions.yaml"
    output_path = sys.argv[2] if len(sys.argv) > 2 else "suppressions/.trivyignore.yaml"
    try:
        convert(input_path, output_path)
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)
