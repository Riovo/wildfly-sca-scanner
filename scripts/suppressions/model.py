from dataclasses import dataclass, field
from typing import Optional


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
        match = d.get("match") or {}
        suppress = d.get("suppress") or {}
        return cls(
            id=d.get("id", ""),
            type=d.get("type", ""),
            notes=d.get("notes", ""),
            package_url=match.get("package-url"),
            file_path=match.get("file-path"),
            cves=suppress.get("cves", []),
            cpes=suppress.get("cpes", []),
            until=d.get("until"),
            references=d.get("references", []),
            vulnerability_names=suppress.get("vulnerability-names", []),
        )
