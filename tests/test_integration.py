#!/usr/bin/env python3
"""End-to-end integration tests running the full pipeline against real suppression files.

Tests the complete chain: OWASP DC XML migration → canonical YAML validation → Trivy
conversion → OWASP DC round-trip. Verifies structural correctness, suppression counts,
date formats, CDATA survival, and lossless round-trip fidelity.

All tests operate on real files (owasp-suppressions.xml, suppressions.yaml) and skip
gracefully if those files aren't available.
"""

import tempfile
from pathlib import Path

import pytest
import yaml
import defusedxml.ElementTree as ET

from model import Suppression
from migrate_from_owaspdc import migrate
from convert_to_trivy import convert as convert_to_trivy
from convert_to_owaspdc import convert as convert_to_owaspdc
from validate import validate


NS = {"dc": "https://jeremylong.github.io/DependencyCheck/dependency-suppression.1.3.xsd"}

REAL_XML = Path(__file__).parent.parent / "owasp-suppressions" / "owasp-suppressions.xml"
REAL_YAML = Path(__file__).parent.parent / "suppressions" / "suppressions.yaml"


class TestFullPipeline:
    """Run the complete pipeline (migrate → convert → round-trip) and verify each output.

    The pipeline_outputs fixture runs once and all tests share its results, so individual
    tests can check specific properties without re-running the pipeline.
    """

    @pytest.fixture
    def pipeline_outputs(self, tmp_path):
        if not REAL_XML.exists():
            pytest.skip("Real OWASP DC XML not available")

        yaml_path = tmp_path / "suppressions.yaml"
        trivy_path = tmp_path / ".trivyignore.yaml"
        roundtrip_xml = tmp_path / "roundtrip.xml"

        migrate(str(REAL_XML), str(yaml_path))
        convert_to_trivy(str(yaml_path), str(trivy_path))
        convert_to_owaspdc(str(yaml_path), str(roundtrip_xml))

        return {
            "yaml_path": yaml_path,
            "trivy_path": trivy_path,
            "roundtrip_xml": roundtrip_xml,
        }

    def test_migration_produces_valid_yaml(self, pipeline_outputs):
        errors, warnings = validate(str(pipeline_outputs["yaml_path"]))
        assert len(errors) == 0, f"Validation errors: {errors}"

    def test_migration_preserves_all_suppressions(self, pipeline_outputs):
        with open(pipeline_outputs["yaml_path"]) as f:
            data = yaml.safe_load(f)
        assert len(data["suppressions"]) == 59

    def test_migration_ids_unique(self, pipeline_outputs):
        with open(pipeline_outputs["yaml_path"]) as f:
            data = yaml.safe_load(f)
        ids = [s["id"] for s in data["suppressions"]]
        assert len(ids) == len(set(ids)), f"Duplicate IDs found: {[x for x in ids if ids.count(x) > 1]}"

    def test_migration_types_correct(self, pipeline_outputs):
        with open(pipeline_outputs["yaml_path"]) as f:
            data = yaml.safe_load(f)
        types = {s["type"] for s in data["suppressions"]}
        assert types == {"cpe-correction", "cve-triage"}

    def test_trivy_output_parseable(self, pipeline_outputs):
        with open(pipeline_outputs["trivy_path"]) as f:
            data = yaml.safe_load(f)
        assert "vulnerabilities" in data
        assert isinstance(data["vulnerabilities"], list)

    def test_trivy_no_empty_ids(self, pipeline_outputs):
        with open(pipeline_outputs["trivy_path"]) as f:
            data = yaml.safe_load(f)
        for entry in data["vulnerabilities"]:
            assert entry.get("id"), f"Empty or missing ID in Trivy entry: {entry}"

    def test_trivy_entries_have_purls_or_global_statement(self, pipeline_outputs):
        """Trivy entries must have purls (scoped) or a global triage statement."""
        with open(pipeline_outputs["trivy_path"]) as f:
            data = yaml.safe_load(f)
        for entry in data["vulnerabilities"]:
            has_purls = "purls" in entry and len(entry["purls"]) > 0
            has_global = "Triaged globally" in entry.get("statement", "")
            assert has_purls or has_global, (
                f"Entry {entry['id']} has neither purls nor global statement"
            )

    def test_trivy_purls_are_plain_not_regex(self, pipeline_outputs):
        """PURL values must be plain package URLs, not OWASP DC regex patterns."""
        with open(pipeline_outputs["trivy_path"]) as f:
            data = yaml.safe_load(f)
        for entry in data["vulnerabilities"]:
            for purl in entry.get("purls", []):
                assert not purl.startswith("^"), f"Regex in PURL: {purl}"
                assert "\\." not in purl, f"Escaped dots in PURL: {purl}"

    def test_trivy_no_paths_field(self, pipeline_outputs):
        """Trivy output must use purls not paths for package matching."""
        with open(pipeline_outputs["trivy_path"]) as f:
            data = yaml.safe_load(f)
        for entry in data["vulnerabilities"]:
            assert "paths" not in entry, (
                f"Entry {entry['id']} uses 'paths' — must use 'purls' for package matching"
            )

    def test_trivy_expired_at_format(self, pipeline_outputs):
        import datetime
        with open(pipeline_outputs["trivy_path"]) as f:
            data = yaml.safe_load(f)
        for entry in data["vulnerabilities"]:
            if "expired_at" in entry:
                val = entry["expired_at"]
                assert isinstance(val, datetime.date), (
                    f"expired_at for {entry['id']} must be a YAML date (unquoted yyyy-mm-dd), got: {val!r}"
                )

    def test_roundtrip_xml_parseable(self, pipeline_outputs):
        with open(pipeline_outputs["roundtrip_xml"]) as f:
            content = f.read()
        ET.fromstring(content)

    def test_roundtrip_xml_preserves_suppression_count(self, pipeline_outputs):
        with open(pipeline_outputs["roundtrip_xml"]) as f:
            content = f.read()
        root = ET.fromstring(content)
        suppress_elems = root.findall("dc:suppress", NS)
        assert len(suppress_elems) == 59

    def test_roundtrip_xml_preserves_cdata(self, pipeline_outputs):
        with open(pipeline_outputs["roundtrip_xml"]) as f:
            content = f.read()
        assert "<![CDATA[" in content

    def test_roundtrip_xml_has_vulnerability_names(self, pipeline_outputs):
        """Entries that were <vulnerabilityName> in the original must remain so after round-trip."""
        with open(pipeline_outputs["roundtrip_xml"]) as f:
            content = f.read()
        assert "<vulnerabilityName>" in content

    def test_cpe_corrections_have_no_cves(self, pipeline_outputs):
        with open(pipeline_outputs["yaml_path"]) as f:
            data = yaml.safe_load(f)
        for s in data["suppressions"]:
            if s["type"] == "cpe-correction":
                assert not s["suppress"].get("cves", []), (
                    f"CPE correction {s['id']} should not have CVEs"
                )
                assert not s["suppress"].get("vulnerability-names", []), (
                    f"CPE correction {s['id']} should not have vulnerability-names"
                )

    def test_cve_triages_have_identifiers(self, pipeline_outputs):
        with open(pipeline_outputs["yaml_path"]) as f:
            data = yaml.safe_load(f)
        for s in data["suppressions"]:
            if s["type"] == "cve-triage":
                has_cves = bool(s["suppress"].get("cves"))
                has_vulns = bool(s["suppress"].get("vulnerability-names"))
                assert has_cves or has_vulns, (
                    f"CVE triage {s['id']} has no CVEs or vulnerability-names"
                )


class TestRoundTripFidelity:
    """Compare original XML elements against round-tripped XML to verify lossless conversion.

    Checks that all CVEs, vulnerability-names, CPEs, and until dates survive the
    XML → YAML → XML round-trip without any additions, losses, or modifications.
    """

    @pytest.fixture
    def round_trip_data(self, tmp_path):
        if not REAL_XML.exists():
            pytest.skip("Real OWASP DC XML not available")

        yaml_path = tmp_path / "suppressions.yaml"
        roundtrip_xml = tmp_path / "roundtrip.xml"
        migrate(str(REAL_XML), str(yaml_path))
        convert_to_owaspdc(str(yaml_path), str(roundtrip_xml))

        orig_tree = ET.parse(str(REAL_XML))
        orig_root = orig_tree.getroot()
        orig_suppressions = orig_root.findall("dc:suppress", NS)

        rt_tree = ET.parse(str(roundtrip_xml))
        rt_root = rt_tree.getroot()
        rt_suppressions = rt_root.findall("dc:suppress", NS)

        return {
            "original": orig_suppressions,
            "roundtrip": rt_suppressions,
            "yaml_path": yaml_path,
        }

    def test_same_count(self, round_trip_data):
        assert len(round_trip_data["original"]) == len(round_trip_data["roundtrip"])

    def test_all_cves_preserved(self, round_trip_data):
        orig_cves = set()
        for elem in round_trip_data["original"]:
            for cve in elem.findall("dc:cve", NS):
                if cve.text:
                    orig_cves.add(cve.text.strip())

        rt_cves = set()
        for elem in round_trip_data["roundtrip"]:
            for cve in elem.findall("dc:cve", NS):
                if cve.text:
                    rt_cves.add(cve.text.strip())

        assert orig_cves == rt_cves, f"CVE mismatch: missing={orig_cves - rt_cves}, extra={rt_cves - orig_cves}"

    def test_all_vulnerability_names_preserved(self, round_trip_data):
        orig_vns = set()
        for elem in round_trip_data["original"]:
            for vn in elem.findall("dc:vulnerabilityName", NS):
                if vn.text:
                    orig_vns.add(vn.text.strip())

        rt_vns = set()
        for elem in round_trip_data["roundtrip"]:
            for vn in elem.findall("dc:vulnerabilityName", NS):
                if vn.text:
                    rt_vns.add(vn.text.strip())

        assert orig_vns == rt_vns, f"VulnName mismatch: missing={orig_vns - rt_vns}, extra={rt_vns - orig_vns}"

    def test_all_cpes_preserved(self, round_trip_data):
        orig_cpes = set()
        for elem in round_trip_data["original"]:
            for cpe in elem.findall("dc:cpe", NS):
                if cpe.text:
                    orig_cpes.add(cpe.text.strip())

        rt_cpes = set()
        for elem in round_trip_data["roundtrip"]:
            for cpe in elem.findall("dc:cpe", NS):
                if cpe.text:
                    rt_cpes.add(cpe.text.strip())

        assert orig_cpes == rt_cpes, f"CPE mismatch: missing={orig_cpes - rt_cpes}, extra={rt_cpes - orig_cpes}"

    def test_until_dates_preserved(self, round_trip_data):
        orig_untils = []
        for elem in round_trip_data["original"]:
            until = elem.get("until")
            if until:
                orig_untils.append(until)

        rt_untils = []
        for elem in round_trip_data["roundtrip"]:
            until = elem.get("until")
            if until:
                rt_untils.append(until)

        assert sorted(orig_untils) == sorted(rt_untils)


class TestEdgeCaseXML:
    """Test migration with hand-crafted XML fragments for edge cases the real file may not cover.

    Each test builds a minimal XML document with one specific edge case (empty notes,
    negative lookahead regex, special characters, filePath-only matching) and verifies
    correct handling through the full migration → conversion pipeline.
    """

    def _make_xml(self, suppress_body):
        return (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<suppressions xmlns="https://jeremylong.github.io/DependencyCheck/dependency-suppression.1.3.xsd">\n'
            f"{suppress_body}\n"
            "</suppressions>"
        )

    def test_empty_notes(self, tmp_path):
        xml = self._make_xml(
            '<suppress>\n'
            '  <notes></notes>\n'
            '  <packageUrl regex="true">^pkg:maven/com\\.example/lib@.*$</packageUrl>\n'
            '  <cpe>cpe:/a:example:product</cpe>\n'
            '</suppress>'
        )
        xml_path = tmp_path / "test.xml"
        yaml_path = tmp_path / "test.yaml"
        xml_path.write_text(xml)
        migrate(str(xml_path), str(yaml_path))

        with open(yaml_path) as f:
            data = yaml.safe_load(f)
        assert len(data["suppressions"]) == 1

    def test_no_notes_element(self, tmp_path):
        xml = self._make_xml(
            '<suppress>\n'
            '  <packageUrl regex="true">^pkg:maven/com\\.example/lib@.*$</packageUrl>\n'
            '  <cpe>cpe:/a:example:product</cpe>\n'
            '</suppress>'
        )
        xml_path = tmp_path / "test.xml"
        yaml_path = tmp_path / "test.yaml"
        xml_path.write_text(xml)
        migrate(str(xml_path), str(yaml_path))

        with open(yaml_path) as f:
            data = yaml.safe_load(f)
        assert data["suppressions"][0]["notes"] == ""

    def test_mixed_cve_and_vulnerability_name(self, tmp_path):
        xml = self._make_xml(
            '<suppress until="2027-06-01">\n'
            '  <notes><![CDATA[Mixed elements]]></notes>\n'
            '  <packageUrl regex="true">^pkg:maven/com\\.example/lib@.*$</packageUrl>\n'
            '  <cve>CVE-2024-00001</cve>\n'
            '  <vulnerabilityName>CVE-2024-00002</vulnerabilityName>\n'
            '</suppress>'
        )
        xml_path = tmp_path / "test.xml"
        yaml_path = tmp_path / "test.yaml"
        xml_path.write_text(xml)
        migrate(str(xml_path), str(yaml_path))

        with open(yaml_path) as f:
            data = yaml.safe_load(f)
        s = data["suppressions"][0]
        assert "CVE-2024-00001" in s["suppress"]["cves"]
        assert "CVE-2024-00002" in s["suppress"]["vulnerability-names"]
        assert s["type"] == "cve-triage"

    def test_filepath_only_suppression(self, tmp_path):
        xml = self._make_xml(
            '<suppress>\n'
            '  <notes><![CDATA[JAR-level match]]></notes>\n'
            '  <filePath regex="true">^.*/jboss-client\\.jar$</filePath>\n'
            '  <cve>CVE-2024-99999</cve>\n'
            '</suppress>'
        )
        xml_path = tmp_path / "test.xml"
        yaml_path = tmp_path / "test.yaml"
        trivy_path = tmp_path / ".trivyignore.yaml"

        xml_path.write_text(xml)
        migrate(str(xml_path), str(yaml_path))
        convert_to_trivy(str(yaml_path), str(trivy_path))

        with open(yaml_path) as f:
            data = yaml.safe_load(f)
        assert data["suppressions"][0]["match"]["file-path"] == "^.*/jboss-client\\.jar$"

        with open(trivy_path) as f:
            trivy = yaml.safe_load(f)
        assert trivy["vulnerabilities"] == [], "filePath-only entries must be skipped in Trivy output"

    def test_negative_lookahead_regex(self, tmp_path):
        regex = "^pkg:maven/io\\.netty/netty(?!.*transport-native).*$"
        xml = self._make_xml(
            '<suppress>\n'
            f'  <notes><![CDATA[Negative lookahead]]></notes>\n'
            f'  <packageUrl regex="true">{regex}</packageUrl>\n'
            '  <cpe>cpe:/a:netty:netty</cpe>\n'
            '</suppress>'
        )
        xml_path = tmp_path / "test.xml"
        yaml_path = tmp_path / "test.yaml"
        roundtrip_xml = tmp_path / "roundtrip.xml"

        xml_path.write_text(xml)
        migrate(str(xml_path), str(yaml_path))
        convert_to_owaspdc(str(yaml_path), str(roundtrip_xml))

        with open(roundtrip_xml) as f:
            content = f.read()
        assert regex in content, "Negative lookahead regex must survive round-trip"

    def test_special_chars_in_notes(self, tmp_path):
        notes = 'Contains <xml> & "quotes" and \'apostrophes\' with © symbols'
        xml = self._make_xml(
            '<suppress>\n'
            f'  <notes><![CDATA[{notes}]]></notes>\n'
            '  <packageUrl regex="true">^pkg:maven/com\\.example/lib@.*$</packageUrl>\n'
            '  <cpe>cpe:/a:example:product</cpe>\n'
            '</suppress>'
        )
        xml_path = tmp_path / "test.xml"
        yaml_path = tmp_path / "test.yaml"
        roundtrip_xml = tmp_path / "roundtrip.xml"

        xml_path.write_text(xml)
        migrate(str(xml_path), str(yaml_path))
        convert_to_owaspdc(str(yaml_path), str(roundtrip_xml))

        with open(roundtrip_xml) as f:
            content = f.read()
        ET.fromstring(content)
        assert notes in content
