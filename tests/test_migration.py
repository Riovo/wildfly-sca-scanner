#!/usr/bin/env python3
"""Tests for the OWASP DC XML to canonical YAML migration.

Covers three areas:
  - XML element parsing: individual <suppress> elements into Suppression objects
  - ID deduplication: ensuring generated IDs are unique even with collisions
  - Full migration: running against the real owasp-suppressions.xml and verifying
    counts, uniqueness, and that complex patterns (negative lookahead, filePath) survive
"""

import tempfile
from pathlib import Path

import pytest
import yaml
from migrate_from_owaspdc import parse_suppress_element, deduplicate_ids, extract_id, migrate
from model import Suppression
import defusedxml.ElementTree as ET

NS = {"dc": "https://jeremylong.github.io/DependencyCheck/dependency-suppression.1.3.xsd"}
NS_URI = "https://jeremylong.github.io/DependencyCheck/dependency-suppression.1.3.xsd"


def make_xml(inner_xml):
    """Wrap a <suppress> fragment in the required root element for parsing."""
    return f'<suppressions xmlns="{NS_URI}">{inner_xml}</suppressions>'


def parse_single(xml_str):
    """Parse a single <suppress> XML fragment into a Suppression object."""
    root = ET.fromstring(make_xml(xml_str))
    elem = root.find("dc:suppress", NS)
    return parse_suppress_element(elem)


class TestParseSuppress:
    """Test parsing individual <suppress> XML elements into Suppression objects."""
    def test_cpe_correction(self):
        s = parse_single("""
        <suppress>
            <notes><![CDATA[Test CPE correction]]></notes>
            <packageUrl regex="true">^pkg:maven/io\\.grpc/grpc-api@.*$</packageUrl>
            <cpe>cpe:/a:grpc:grpc</cpe>
        </suppress>
        """)
        assert s.type == "cpe-correction"
        assert s.cpes == ["cpe:/a:grpc:grpc"]
        assert s.cves == []
        assert s.package_url == "^pkg:maven/io\\.grpc/grpc-api@.*$"

    def test_cve_triage_with_until(self):
        s = parse_single("""
        <suppress until="2027-03-26">
            <notes><![CDATA[Disputed by h2database]]></notes>
            <packageUrl regex="true">^pkg:maven/com\\.h2database/h2@.*$</packageUrl>
            <vulnerabilityName>CVE-2018-14335</vulnerabilityName>
        </suppress>
        """)
        assert s.type == "cve-triage"
        assert s.until == "2027-03-26"
        assert s.vulnerability_names == ["CVE-2018-14335"]
        assert s.cves == []

    def test_cve_with_cve_element(self):
        """<cve> maps to cves list, <vulnerabilityName> maps to vulnerability_names list."""
        s = parse_single("""
        <suppress until="2026-03-11">
            <notes><![CDATA[Test]]></notes>
            <packageUrl regex="true">^pkg:maven/org\\.apache/test@.*$</packageUrl>
            <cve>CVE-2010-1151</cve>
        </suppress>
        """)
        assert s.cves == ["CVE-2010-1151"]

    def test_multiple_cves(self):
        s = parse_single("""
        <suppress until="2027-05-01">
            <notes><![CDATA[Multiple CVEs]]></notes>
            <packageUrl regex="true">^pkg:maven/org\\.example/lib@.*$</packageUrl>
            <cve>CVE-2026-34478</cve>
            <cve>CVE-2026-34480</cve>
            <cve>CVE-2026-34481</cve>
        </suppress>
        """)
        assert len(s.cves) == 3
        assert "CVE-2026-34478" in s.cves
        assert "CVE-2026-34481" in s.cves

    def test_mixed_cve_and_vulnerabilityname(self):
        s = parse_single("""
        <suppress>
            <notes><![CDATA[Mixed elements]]></notes>
            <packageUrl regex="true">^pkg:maven/org\\.example/lib@.*$</packageUrl>
            <cve>CVE-2024-00001</cve>
            <vulnerabilityName>CVE-2024-00002</vulnerabilityName>
        </suppress>
        """)
        assert s.cves == ["CVE-2024-00001"]
        assert s.vulnerability_names == ["CVE-2024-00002"]

    def test_filepath_matching(self):
        s = parse_single("""
        <suppress until="2027-05-20">
            <notes><![CDATA[Shaded jar]]></notes>
            <filePath regex="true">^.*/wildfly/bin/client/jboss-client\\.jar$</filePath>
            <cve>CVE-2026-42582</cve>
        </suppress>
        """)
        assert s.file_path == "^.*/wildfly/bin/client/jboss-client\\.jar$"
        assert s.package_url is None

    def test_negative_lookahead_regex(self):
        """The netty suppression uses (?!netty-codec-http3) — must be preserved."""
        s = parse_single("""
        <suppress until="2027-05-20">
            <notes><![CDATA[Negative lookahead]]></notes>
            <packageUrl regex="true">^pkg:maven/io\\.netty/(?!netty-codec-http3).*@.*$</packageUrl>
            <cve>CVE-2026-42582</cve>
        </suppress>
        """)
        assert "(?!netty-codec-http3)" in s.package_url

    def test_cve_without_until_permanent(self):
        """CVE suppressions without until are permanently resolved."""
        s = parse_single("""
        <suppress>
            <notes><![CDATA[Fixed in version]]></notes>
            <packageUrl regex="true">^pkg:maven/org\\.example/lib@.*$</packageUrl>
            <cve>CVE-2022-0866</cve>
        </suppress>
        """)
        assert s.type == "cve-triage"
        assert s.until is None

    def test_references_extracted_from_notes(self):
        s = parse_single("""
        <suppress>
            <notes><![CDATA[
            Test note
            https://github.com/example/issue/1
            https://github.com/example/advisory/2
            ]]></notes>
            <packageUrl regex="true">^pkg:maven/org\\.example/lib@.*$</packageUrl>
            <cve>CVE-2024-00001</cve>
        </suppress>
        """)
        assert len(s.references) == 2
        assert "https://github.com/example/issue/1" in s.references

    def test_multiple_cpes(self):
        s = parse_single("""
        <suppress>
            <notes><![CDATA[Multiple CPEs]]></notes>
            <packageUrl regex="true">^pkg:maven/org\\.example/lib@.*$</packageUrl>
            <cpe>cpe:/a:redhat:wildfly</cpe>
            <cpe>cpe:/a:redhat:jboss_enterprise_application_platform</cpe>
            <cpe>cpe:/a:netapp:active_iq_unified_manager</cpe>
        </suppress>
        """)
        assert len(s.cpes) == 3

    def test_empty_notes(self):
        s = parse_single("""
        <suppress>
            <notes></notes>
            <packageUrl regex="true">^pkg:maven/org\\.example/lib@.*$</packageUrl>
            <cpe>cpe:/a:example:product</cpe>
        </suppress>
        """)
        assert s.notes == ""


class TestDeduplicateIds:
    """Test ID collision resolution when multiple suppressions generate the same slug."""
    def test_no_duplicates(self):
        suppressions = [
            Suppression(id="a", type="cpe-correction", notes=""),
            Suppression(id="b", type="cpe-correction", notes=""),
        ]
        deduplicate_ids(suppressions)
        assert suppressions[0].id == "a"
        assert suppressions[1].id == "b"

    def test_duplicates_get_suffix(self):
        suppressions = [
            Suppression(id="same", type="cpe-correction", notes=""),
            Suppression(id="same", type="cpe-correction", notes=""),
            Suppression(id="same", type="cpe-correction", notes=""),
        ]
        deduplicate_ids(suppressions)
        ids = [s.id for s in suppressions]
        assert len(set(ids)) == 3

    def test_secondary_collision_avoided(self):
        """If 'same-2' already exists naturally, dedup must not collide with it."""
        suppressions = [
            Suppression(id="same", type="cpe-correction", notes=""),
            Suppression(id="same-2", type="cpe-correction", notes=""),
            Suppression(id="same", type="cpe-correction", notes=""),
        ]
        deduplicate_ids(suppressions)
        ids = [s.id for s in suppressions]
        assert len(set(ids)) == 3
        assert "same-2" in ids
        assert ids[0] == "same"
        assert ids[1] == "same-2"
        assert ids[2] == "same-3"


class TestFullMigration:
    """Run migration against the real owasp-suppressions.xml and verify output integrity."""
    def test_migrate_real_file(self):
        """Test migration of the actual OWASP DC suppression file."""
        input_path = Path(__file__).parent.parent / "owasp-suppressions" / "owasp-suppressions.xml"
        if not input_path.exists():
            pytest.skip("Real suppression file not available")

        with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False) as f:
            output_path = f.name

        try:
            migrate(str(input_path), output_path)

            with open(output_path) as f:
                data = yaml.safe_load(f)

            assert data["version"] == "1.0"
            assert len(data["suppressions"]) == 59

            cpe_corrections = [s for s in data["suppressions"] if s["type"] == "cpe-correction"]
            cve_triages = [s for s in data["suppressions"] if s["type"] == "cve-triage"]
            assert len(cpe_corrections) == 31
            assert len(cve_triages) == 28

            # All IDs should be unique
            ids = [s["id"] for s in data["suppressions"]]
            assert len(ids) == len(set(ids)), f"Duplicate IDs found: {[x for x in ids if ids.count(x) > 1]}"

            # All entries should have match and suppress blocks
            for s in data["suppressions"]:
                match = s.get("match", {})
                assert match.get("package-url") or match.get("file-path"), f"{s['id']} has no match"
                suppress = s.get("suppress", {})
                assert suppress.get("cves") or suppress.get("cpes") or suppress.get("vulnerability-names"), f"{s['id']} has no suppress target"

            # Verify the negative lookahead regex survived
            netty = [s for s in data["suppressions"] if "netty" in s["id"] and "(?!" in s.get("match", {}).get("package-url", "")]
            assert len(netty) >= 1, "Negative lookahead regex for netty not found"

            # Verify filePath entries exist
            filepath_entries = [s for s in data["suppressions"] if s.get("match", {}).get("file-path")]
            assert len(filepath_entries) >= 2, "Expected at least 2 filePath-based suppressions"

        finally:
            Path(output_path).unlink(missing_ok=True)
