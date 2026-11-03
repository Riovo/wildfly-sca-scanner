#!/usr/bin/env python3
"""Tests for the Suppression dataclass serialization to/from canonical YAML dict format.

Covers: round-trip fidelity (dict→Suppression→dict), empty/None handling for optional fields,
and regex preservation — particularly negative lookahead patterns (e.g. the netty suppression)
which are the most fragile to serialize.
"""

import pytest
from model import Suppression


class TestSuppressionToDict:
    """Verify to_dict() produces the canonical YAML structure with correct nesting."""
    def test_minimal_cpe_correction(self):
        s = Suppression(
            id="test-cpe",
            type="cpe-correction",
            notes="Test note",
            package_url="^pkg:maven/com\\.example/lib@.*$",
            cpes=["cpe:/a:example:product"],
        )
        d = s.to_dict()
        assert d["id"] == "test-cpe"
        assert d["type"] == "cpe-correction"
        assert d["match"]["package-url"] == "^pkg:maven/com\\.example/lib@.*$"
        assert d["suppress"]["cpes"] == ["cpe:/a:example:product"]
        assert "cves" not in d["suppress"]
        assert "until" not in d
        assert "references" not in d

    def test_full_cve_triage(self):
        s = Suppression(
            id="test-cve",
            type="cve-triage",
            notes="Disputed",
            package_url="^pkg:maven/com\\.h2database/h2@.*$",
            cves=["CVE-2018-14335"],
            until="2027-03-26",
            references=["https://github.com/h2database/h2database/issues/1294"],
        )
        d = s.to_dict()
        assert d["until"] == "2027-03-26"
        assert d["references"] == ["https://github.com/h2database/h2database/issues/1294"]
        assert d["suppress"]["cves"] == ["CVE-2018-14335"]

    def test_file_path_match(self):
        s = Suppression(
            id="test-filepath",
            type="cpe-correction",
            notes="Uber-JAR",
            file_path="^.*/wildfly/bin/client/jboss-client\\.jar$",
            cpes=["cpe:/a:redhat:wildfly"],
        )
        d = s.to_dict()
        assert "package-url" not in d["match"]
        assert d["match"]["file-path"] == "^.*/wildfly/bin/client/jboss-client\\.jar$"

    def test_both_match_types(self):
        s = Suppression(
            id="test-both",
            type="cve-triage",
            notes="Both match types",
            package_url="^pkg:maven/com\\.example/lib@.*$",
            file_path="^.*/lib\\.jar$",
            cves=["CVE-2024-00001"],
        )
        d = s.to_dict()
        assert "package-url" in d["match"]
        assert "file-path" in d["match"]

    def test_multiple_cves_and_cpes(self):
        s = Suppression(
            id="test-multi",
            type="cve-triage",
            notes="Multiple",
            package_url="^pkg:maven/com\\.example/lib@.*$",
            cves=["CVE-2024-00001", "CVE-2024-00002", "CVE-2024-00003"],
            cpes=["cpe:/a:example:one", "cpe:/a:example:two"],
        )
        d = s.to_dict()
        assert len(d["suppress"]["cves"]) == 3
        assert len(d["suppress"]["cpes"]) == 2

    def test_empty_lists_omitted(self):
        s = Suppression(
            id="test-empty",
            type="cpe-correction",
            notes="No CVEs",
            package_url="^pkg:maven/com\\.example/lib@.*$",
            cpes=["cpe:/a:example:product"],
        )
        d = s.to_dict()
        assert "cves" not in d["suppress"]


class TestSuppressionFromDict:
    """Verify from_dict() correctly parses canonical YAML dicts back into Suppression objects."""
    def test_round_trip(self):
        original = Suppression(
            id="round-trip",
            type="cve-triage",
            notes="Test round trip",
            package_url="^pkg:maven/io\\.netty/(?!netty-codec-http3).*@.*$",
            cves=["CVE-2026-42582"],
            until="2027-05-20",
            references=["https://example.com/issue/66"],
        )
        d = original.to_dict()
        restored = Suppression.from_dict(d)

        assert restored.id == original.id
        assert restored.type == original.type
        assert restored.notes == original.notes
        assert restored.package_url == original.package_url
        assert restored.file_path == original.file_path
        assert restored.cves == original.cves
        assert restored.cpes == original.cpes
        assert restored.until == original.until
        assert restored.references == original.references

    def test_missing_optional_fields(self):
        d = {
            "id": "minimal",
            "type": "cpe-correction",
            "notes": "Minimal entry",
            "match": {"package-url": "^pkg:maven/com\\.example/lib@.*$"},
            "suppress": {"cpes": ["cpe:/a:example:product"]},
        }
        s = Suppression.from_dict(d)
        assert s.until is None
        assert s.references == []
        assert s.cves == []
        assert s.file_path is None

    def test_negative_lookahead_regex_preserved(self):
        """The netty suppression uses a negative lookahead — ensure it survives round-trip."""
        regex = "^pkg:maven/io\\.netty/(?!netty-codec-http3).*@.*$"
        d = {
            "id": "netty-lookahead",
            "type": "cve-triage",
            "notes": "Negative lookahead test",
            "match": {"package-url": regex},
            "suppress": {"cves": ["CVE-2026-42582"]},
        }
        s = Suppression.from_dict(d)
        assert s.package_url == regex
        d2 = s.to_dict()
        assert d2["match"]["package-url"] == regex

    def test_none_match_and_suppress_handled(self):
        """from_dict should handle None match/suppress without crashing."""
        d = {
            "id": "null-blocks",
            "type": "cve-triage",
            "notes": "Test",
            "match": None,
            "suppress": None,
        }
        s = Suppression.from_dict(d)
        assert s.package_url is None
        assert s.file_path is None
        assert s.cves == []
        assert s.cpes == []

    def test_null_list_values_in_suppress_handled(self):
        """YAML `cves:` (no value) parses as None — from_dict must not crash."""
        d = {
            "id": "null-lists",
            "type": "cve-triage",
            "notes": "Test",
            "match": {"package-url": "^pkg:maven/com\\.example/lib@.*$"},
            "suppress": {"cves": None, "cpes": None, "vulnerability-names": None},
            "references": None,
        }
        s = Suppression.from_dict(d)
        assert s.cves == []
        assert s.cpes == []
        assert s.vulnerability_names == []
        assert s.references == []

    def test_datetime_date_until_coerced_to_string(self):
        """PyYAML parses unquoted dates as datetime.date — from_dict must coerce to str."""
        from datetime import date
        d = {
            "id": "date-coerce",
            "type": "cve-triage",
            "notes": "Test",
            "match": {"package-url": "^pkg:maven/a/b@.*$"},
            "suppress": {"cves": ["CVE-2024-00001"]},
            "until": date(2027, 3, 26),
        }
        s = Suppression.from_dict(d)
        assert s.until == "2027-03-26"
        assert isinstance(s.until, str)
