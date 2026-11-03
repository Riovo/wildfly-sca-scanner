#!/usr/bin/env python3
"""Validate suppressions/suppressions.yaml for schema correctness and consistency.

Run by CI on every push that touches suppressions/ (see .github/workflows/validate-suppressions.yaml).
Catches: missing required fields, invalid regex syntax, duplicate IDs, expired until dates, and
type mismatches. Returns errors (block merge) and warnings (informational, e.g. expired dates).

See also:
    - validate-suppressions.yaml: CI workflow that calls this script
    - model.py: Suppression dataclass this validates against
"""

import re
import sys
from datetime import date
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).parent))
from model import Suppression

# Standard CVE ID format (CVE-YYYY-NNNNN). Used to warn about non-standard IDs
# in the vulnerability-names field, which OWASP DC accepts as free-text.
CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")


def validate(input_path):
    with open(input_path) as f:
        data = yaml.safe_load(f)

    errors = []
    warnings = []

    if data is None:
        errors.append("File is empty or not valid YAML")
        return errors, warnings
    if not isinstance(data, dict):
        errors.append(f"Expected YAML mapping at top level, got {type(data).__name__}")
        return errors, warnings

    if "version" not in data:
        errors.append("Missing 'version' field")
    if "suppressions" not in data:
        errors.append("Missing 'suppressions' field")
        return errors, warnings
    if not isinstance(data["suppressions"], list):
        errors.append(f"'suppressions' must be a list, got {type(data['suppressions']).__name__}")
        return errors, warnings

    seen_ids = set()
    today = date.today().isoformat()

    for i, entry in enumerate(data["suppressions"]):
        prefix = f"suppression[{i}]"

        if not isinstance(entry, dict):
            errors.append(f"{prefix}: expected a mapping, got {type(entry).__name__}")
            continue

        for field in ("id", "type", "notes"):
            if field not in entry:
                errors.append(f"{prefix}: missing required field '{field}'")

        sup_id = entry.get("id", f"<unnamed-{i}>")

        if sup_id in seen_ids:
            errors.append(f"{prefix} ({sup_id}): duplicate ID")
        seen_ids.add(sup_id)

        sup_type = entry.get("type", "")
        if sup_type not in ("cpe-correction", "cve-triage"):
            errors.append(f"{prefix} ({sup_id}): invalid type '{sup_type}' (expected 'cpe-correction' or 'cve-triage')")

        match = entry.get("match") or {}
        if not match.get("package-url") and not match.get("file-path"):
            errors.append(f"{prefix} ({sup_id}): must have at least one of 'package-url' or 'file-path' in match")

        for key in ("package-url", "file-path"):
            pattern = match.get(key)
            if pattern:
                if not isinstance(pattern, str):
                    errors.append(f"{prefix} ({sup_id}): match.{key} must be a string, got {type(pattern).__name__}")
                    continue
                try:
                    re.compile(pattern)
                except re.error as e:
                    errors.append(f"{prefix} ({sup_id}): invalid regex in match.{key}: {e}")

        suppress = entry.get("suppress") or {}
        if not suppress.get("cves") and not suppress.get("cpes") and not suppress.get("vulnerability-names"):
            errors.append(f"{prefix} ({sup_id}): must suppress at least one CVE, vulnerability-name, or CPE")

        for cve in (suppress.get("cves") or []) + (suppress.get("vulnerability-names") or []):
            if not CVE_PATTERN.match(cve):
                warnings.append(f"{prefix} ({sup_id}): CVE '{cve}' doesn't match expected format CVE-YYYY-NNNNN")

        # Until date validation: type check → format check → parse check → expiry check.
        # Expired dates are warnings, not errors — the suppression may still be valid
        # pending re-evaluation by the security team.
        until = entry.get("until")
        if until:
            # PyYAML parses unquoted YYYY-MM-DD as datetime.date — coerce to string
            # so authors don't need to remember to quote dates in YAML.
            if isinstance(until, date):
                until = until.isoformat()
            if not isinstance(until, str):
                errors.append(f"{prefix} ({sup_id}): 'until' must be a date string (YYYY-MM-DD), got {type(until).__name__}")
                until = None
            elif len(until) != 10 or until[4] != '-' or until[7] != '-':
                errors.append(f"{prefix} ({sup_id}): invalid 'until' date format: {until} (expected YYYY-MM-DD)")
                until = None
        if until:
            try:
                date.fromisoformat(until)
                if until < today:
                    warnings.append(f"{prefix} ({sup_id}): 'until' date {until} has expired — re-evaluate this suppression")
            except ValueError:
                errors.append(f"{prefix} ({sup_id}): invalid 'until' date format: {until} (expected YYYY-MM-DD)")

        if sup_type == "cpe-correction" and until:
            warnings.append(f"{prefix} ({sup_id}): CPE corrections typically don't need 'until' dates")

    return errors, warnings


def main():
    input_path = sys.argv[1] if len(sys.argv) > 1 else "suppressions/suppressions.yaml"

    print(f"Validating {input_path}...")
    errors, warnings = validate(input_path)

    for w in warnings:
        print(f"  WARNING: {w}")
    for e in errors:
        print(f"  ERROR: {e}")

    print()
    if errors:
        print(f"FAILED: {len(errors)} error(s), {len(warnings)} warning(s)")
        sys.exit(1)
    else:
        print(f"PASSED: 0 errors, {len(warnings)} warning(s)")
        sys.exit(0)


if __name__ == "__main__":
    main()
