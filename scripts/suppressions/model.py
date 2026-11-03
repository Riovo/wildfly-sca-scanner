"""Shared data model for the suppression system.

The Suppression dataclass maps 1:1 to entries in the canonical suppressions/suppressions.yaml.
All scripts (migration, conversion, validation, resolution) operate on Suppression objects,
keeping the YAML schema in one place.

SIMPLE_PURL_RE is also defined here because both the static converter (convert_to_trivy.py)
and the scan-time resolver (resolve_suppressions.py) need to distinguish exact group/artifact
patterns from wildcards that require regex resolution.

See also:
    - suppressions/suppressions.yaml: the canonical file whose entries this dataclass represents
    - migrate_from_owaspdc.py: creates Suppression objects from OWASP DC XML
    - convert_to_trivy.py, convert_to_owaspdc.py: consume Suppression objects for output
"""

import re
from dataclasses import dataclass, field
from datetime import date
from typing import Optional

# Matches exact group/artifact OWASP DC regex patterns like: ^pkg:maven/group\.name/artifact-name@.*$
# Used by both convert_to_trivy.py (static) and resolve_suppressions.py (scan-time) to distinguish
# patterns that map cleanly to a single PURL from those requiring regex resolution.
SIMPLE_PURL_RE = re.compile(
    r"^\^?pkg:maven/"
    r"([a-zA-Z0-9_.\\-]+)"    # group (may have escaped dots/hyphens)
    r"/"
    r"([a-zA-Z0-9_.\\-]+)"    # artifact (exact, no wildcards)
    r"@\.\*\$?$"              # @.* (match all versions)
)


def purl_from_simple_match(m):
    """Extract a plain PURL from a SIMPLE_PURL_RE match, unescaping regex characters."""
    group = m.group(1).replace("\\.", ".").replace("\\-", "-")
    artifact = m.group(2).replace("\\.", ".").replace("\\-", "-")
    return f"pkg:maven/{group}/{artifact}"


def parse_until_date(until_str, suppression_id):
    """Parse an until date string into a datetime.date, with context on failure."""
    try:
        return date.fromisoformat(until_str)
    except (ValueError, TypeError) as e:
        raise ValueError(f"Suppression '{suppression_id}': invalid until date '{until_str}': {e}") from e


@dataclass
class Suppression:
    id: str
    type: str  # "cpe-correction" or "cve-triage"
    notes: str
    package_url: Optional[str] = None  # regex pattern
    file_path: Optional[str] = None  # regex pattern
    cves: list = field(default_factory=list)
    cpes: list = field(default_factory=list)
    until: Optional[str] = None  # ISO 8601 date
    references: list = field(default_factory=list)
    vulnerability_names: list = field(default_factory=list)

    def to_dict(self):
        """Serialize to the canonical YAML structure with match/suppress nesting.

        Empty lists are omitted so the YAML stays clean and readable.
        """
        d = {"id": self.id, "type": self.type, "notes": self.notes}

        match = {}
        if self.package_url:
            match["package-url"] = self.package_url
        if self.file_path:
            match["file-path"] = self.file_path
        d["match"] = match

        suppress = {}
        if self.cves:
            suppress["cves"] = self.cves
        if self.cpes:
            suppress["cpes"] = self.cpes
        if self.vulnerability_names:
            suppress["vulnerability-names"] = self.vulnerability_names
        d["suppress"] = suppress

        if self.until:
            d["until"] = self.until
        if self.references:
            d["references"] = self.references

        return d

    @classmethod
    def from_dict(cls, d):
        """Deserialize from canonical YAML dict.

        The `or {}` guards handle None match/suppress blocks that can appear in
        malformed or minimal YAML entries without crashing on .get() calls.
        """
        match = d.get("match") or {}
        suppress = d.get("suppress") or {}
        until = d.get("until")
        if isinstance(until, date):
            until = until.isoformat()
        return cls(
            id=d.get("id", ""),
            type=d.get("type", ""),
            notes=d.get("notes", ""),
            package_url=match.get("package-url"),
            file_path=match.get("file-path"),
            cves=suppress.get("cves") or [],
            cpes=suppress.get("cpes") or [],
            until=until,
            references=d.get("references") or [],
            vulnerability_names=suppress.get("vulnerability-names") or [],
        )
