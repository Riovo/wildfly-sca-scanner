#!/usr/bin/env python3
"""Tests for the Trivy and OWASP DC converters, plus the canonical YAML validator.

Each converter translates the canonical YAML into a scanner-specific format:
  - Trivy: .trivyignore.yaml with PURL-scoped CVE entries
  - OWASP DC: XML with CDATA-wrapped notes and namespace-qualified elements

The validator checks the canonical YAML for schema errors (missing fields, invalid regex,
duplicate IDs) and warnings (expired until dates). CI runs it on every push to suppressions/.

See also: test_resolver.py for scan-time PURL resolution tests.
"""

import tempfile
from pathlib import Path

import pytest
import yaml
import defusedxml.ElementTree as ET
from model import Suppression
from convert_to_trivy import convert as convert_to_trivy
from convert_to_owaspdc import convert as convert_to_owaspdc


NS = {"dc": "https://jeremylong.github.io/DependencyCheck/dependency-suppression.1.3.xsd"}


def write_yaml(data, path):
    with open(path, "w") as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False)


class TestTrivyConverter:
    """Tests for the static Trivy converter (convert_to_trivy.py).

    This converter runs at commit time and generates suppressions/.trivyignore.yaml.
    Wildcard patterns become global suppressions here (no purls field) — the scan-time
    resolver (resolve_suppressions.py) eliminates those by matching against real PURLs.
    """
    def test_cpe_only_suppressions_skipped(self):
        data = {
            "version": "1.0",
            "suppressions": [
                {
                    "id": "cpe-test",
                    "type": "cpe-correction",
                    "notes": "CPE only",
                    "match": {"package-url": "^pkg:maven/com\\.example/lib@.*$"},
                    "suppress": {"cpes": ["cpe:/a:example:product"]},
                },
            ],
        }
        with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False) as inp:
            yaml.dump(data, inp, default_flow_style=False, sort_keys=False)
            inp_path = inp.name
        with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False) as out:
            out_path = out.name

        try:
            convert_to_trivy(inp_path, out_path)
            with open(out_path) as f:
                content = f.read()
            result = yaml.safe_load(content)
            assert result["vulnerabilities"] == []
        finally:
            Path(inp_path).unlink(missing_ok=True)
            Path(out_path).unlink(missing_ok=True)

    def test_filepath_only_suppressions_skipped(self):
        """filePath-based suppressions should be skipped to avoid global suppression."""
        data = {
            "version": "1.0",
            "suppressions": [
                {
                    "id": "filepath-test",
                    "type": "cve-triage",
                    "notes": "File path only",
                    "match": {"file-path": "^.*/jboss-client\\.jar$"},
                    "suppress": {"cves": ["CVE-2026-42582"]},
                },
            ],
        }
        with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False) as inp:
            yaml.dump(data, inp, default_flow_style=False, sort_keys=False)
            inp_path = inp.name
        with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False) as out:
            out_path = out.name

        try:
            convert_to_trivy(inp_path, out_path)
            with open(out_path) as f:
                result = yaml.safe_load(f)
            assert result["vulnerabilities"] == []
        finally:
            Path(inp_path).unlink(missing_ok=True)
            Path(out_path).unlink(missing_ok=True)

    def test_cve_triage_converted(self):
        data = {
            "version": "1.0",
            "suppressions": [
                {
                    "id": "cve-test",
                    "type": "cve-triage",
                    "notes": "Test note",
                    "match": {"package-url": "^pkg:maven/com\\.h2database/h2@.*$"},
                    "suppress": {"cves": ["CVE-2018-14335"]},
                    "until": "2027-03-26",
                    "references": ["https://example.com"],
                },
            ],
        }
        with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False) as inp:
            yaml.dump(data, inp, default_flow_style=False, sort_keys=False)
            inp_path = inp.name
        with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False) as out:
            out_path = out.name

        try:
            convert_to_trivy(inp_path, out_path)
            with open(out_path) as f:
                result = yaml.safe_load(f)
            assert len(result["vulnerabilities"]) == 1
            entry = result["vulnerabilities"][0]
            assert entry["id"] == "CVE-2018-14335"
            import datetime
            assert entry["expired_at"] == datetime.date(2027, 3, 26)
            assert entry["purls"] == ["pkg:maven/com.h2database/h2"]
        finally:
            Path(inp_path).unlink(missing_ok=True)
            Path(out_path).unlink(missing_ok=True)

    def test_vulnerability_names_converted(self):
        data = {
            "version": "1.0",
            "suppressions": [
                {
                    "id": "vuln-name-test",
                    "type": "cve-triage",
                    "notes": "Via vulnerabilityName",
                    "match": {"package-url": "^pkg:maven/com\\.example/lib@.*$"},
                    "suppress": {"vulnerability-names": ["CVE-2024-00001"]},
                },
            ],
        }
        with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False) as inp:
            yaml.dump(data, inp, default_flow_style=False, sort_keys=False)
            inp_path = inp.name
        with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False) as out:
            out_path = out.name

        try:
            convert_to_trivy(inp_path, out_path)
            with open(out_path) as f:
                result = yaml.safe_load(f)
            assert len(result["vulnerabilities"]) == 1
            assert result["vulnerabilities"][0]["id"] == "CVE-2024-00001"
            assert result["vulnerabilities"][0]["purls"] == ["pkg:maven/com.example/lib"]
        finally:
            Path(inp_path).unlink(missing_ok=True)
            Path(out_path).unlink(missing_ok=True)

    def test_multiple_cves_expanded(self):
        """Each CVE should get its own entry in the Trivy output."""
        data = {
            "version": "1.0",
            "suppressions": [
                {
                    "id": "multi-cve",
                    "type": "cve-triage",
                    "notes": "Multiple",
                    "match": {"package-url": "^pkg:maven/com\\.example/lib@.*$"},
                    "suppress": {"cves": ["CVE-2024-00001", "CVE-2024-00002"]},
                },
            ],
        }
        with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False) as inp:
            yaml.dump(data, inp, default_flow_style=False, sort_keys=False)
            inp_path = inp.name
        with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False) as out:
            out_path = out.name

        try:
            convert_to_trivy(inp_path, out_path)
            with open(out_path) as f:
                result = yaml.safe_load(f)
            assert len(result["vulnerabilities"]) == 2
            ids = {v["id"] for v in result["vulnerabilities"]}
            assert ids == {"CVE-2024-00001", "CVE-2024-00002"}
        finally:
            Path(inp_path).unlink(missing_ok=True)
            Path(out_path).unlink(missing_ok=True)

    def test_empty_suppressions(self):
        data = {"version": "1.0", "suppressions": []}
        with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False) as inp:
            yaml.dump(data, inp, default_flow_style=False, sort_keys=False)
            inp_path = inp.name
        with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False) as out:
            out_path = out.name

        try:
            convert_to_trivy(inp_path, out_path)
            with open(out_path) as f:
                result = yaml.safe_load(f)
            assert result["vulnerabilities"] == []
        finally:
            Path(inp_path).unlink(missing_ok=True)
            Path(out_path).unlink(missing_ok=True)

    def test_no_match_fields_skipped(self):
        """Entry with neither package-url nor file-path must be skipped to avoid global suppression."""
        data = {
            "version": "1.0",
            "suppressions": [
                {
                    "id": "no-match",
                    "type": "cve-triage",
                    "notes": "No match fields",
                    "match": {},
                    "suppress": {"cves": ["CVE-2024-99999"]},
                },
            ],
        }
        with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False) as inp:
            yaml.dump(data, inp, default_flow_style=False, sort_keys=False)
            inp_path = inp.name
        with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False) as out:
            out_path = out.name

        try:
            convert_to_trivy(inp_path, out_path)
            with open(out_path) as f:
                result = yaml.safe_load(f)
            assert result["vulnerabilities"] == [], "Entries with no match must be skipped"
        finally:
            Path(inp_path).unlink(missing_ok=True)
            Path(out_path).unlink(missing_ok=True)

    def test_both_package_url_and_filepath_uses_purl(self):
        """When both match fields are set, Trivy output should use purls from package-url."""
        data = {
            "version": "1.0",
            "suppressions": [
                {
                    "id": "both-match",
                    "type": "cve-triage",
                    "notes": "Both match types",
                    "match": {
                        "package-url": "^pkg:maven/com\\.example/lib@.*$",
                        "file-path": "^.*/lib\\.jar$",
                    },
                    "suppress": {"cves": ["CVE-2024-00001"]},
                },
            ],
        }
        with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False) as inp:
            yaml.dump(data, inp, default_flow_style=False, sort_keys=False)
            inp_path = inp.name
        with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False) as out:
            out_path = out.name

        try:
            convert_to_trivy(inp_path, out_path)
            with open(out_path) as f:
                result = yaml.safe_load(f)
            assert len(result["vulnerabilities"]) == 1
            assert result["vulnerabilities"][0]["purls"] == ["pkg:maven/com.example/lib"]
            assert "paths" not in result["vulnerabilities"][0]
        finally:
            Path(inp_path).unlink(missing_ok=True)
            Path(out_path).unlink(missing_ok=True)

    def test_wildcard_pattern_becomes_global(self):
        """Wildcard artifact patterns can't be PURLs — emitted as global suppression."""
        data = {
            "version": "1.0",
            "suppressions": [
                {
                    "id": "wildcard-test",
                    "type": "cve-triage",
                    "notes": "Wildcard pattern",
                    "match": {"package-url": "^pkg:maven/org\\.wildfly\\.core/.*@.*$"},
                    "suppress": {"cves": ["CVE-2025-23368"]},
                },
            ],
        }
        with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False) as inp:
            yaml.dump(data, inp, default_flow_style=False, sort_keys=False)
            inp_path = inp.name
        with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False) as out:
            out_path = out.name

        try:
            convert_to_trivy(inp_path, out_path)
            with open(out_path) as f:
                result = yaml.safe_load(f)
            assert len(result["vulnerabilities"]) == 1
            assert "purls" not in result["vulnerabilities"][0]
            assert "Triaged globally" in result["vulnerabilities"][0]["statement"]
        finally:
            Path(inp_path).unlink(missing_ok=True)
            Path(out_path).unlink(missing_ok=True)

    def test_negative_lookahead_skipped(self):
        """Negative lookahead patterns can't be expressed in Trivy — must be skipped."""
        data = {
            "version": "1.0",
            "suppressions": [
                {
                    "id": "lookahead-test",
                    "type": "cve-triage",
                    "notes": "Complex regex",
                    "match": {"package-url": "^pkg:maven/io\\.netty/(?!netty-codec-http3).*@.*$"},
                    "suppress": {"cves": ["CVE-2026-42582"]},
                },
            ],
        }
        with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False) as inp:
            yaml.dump(data, inp, default_flow_style=False, sort_keys=False)
            inp_path = inp.name
        with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False) as out:
            out_path = out.name

        try:
            convert_to_trivy(inp_path, out_path)
            with open(out_path) as f:
                result = yaml.safe_load(f)
            assert result["vulnerabilities"] == []
        finally:
            Path(inp_path).unlink(missing_ok=True)
            Path(out_path).unlink(missing_ok=True)

    def test_invalid_input_raises_valueerror(self):
        with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False) as inp:
            inp.write("")
            inp_path = inp.name
        with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False) as out:
            out_path = out.name

        try:
            with pytest.raises(ValueError):
                convert_to_trivy(inp_path, out_path)
        finally:
            Path(inp_path).unlink(missing_ok=True)
            Path(out_path).unlink(missing_ok=True)


class TestOWASPDCConverter:
    """Tests for the OWASP DC XML converter (convert_to_owaspdc.py).

    Generates owasp-suppressions-roundtrip.xml from canonical YAML. The output must be
    valid XML with proper CDATA escaping and namespace-qualified elements.
    """
    def test_cdata_wrapping(self):
        """Notes should be wrapped in CDATA to handle XML special characters."""
        data = {
            "version": "1.0",
            "suppressions": [
                {
                    "id": "cdata-test",
                    "type": "cpe-correction",
                    "notes": "Contains <special> & 'characters'",
                    "match": {"package-url": "^pkg:maven/com\\.example/lib@.*$"},
                    "suppress": {"cpes": ["cpe:/a:example:product"]},
                },
            ],
        }
        with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False) as inp:
            yaml.dump(data, inp, default_flow_style=False, sort_keys=False)
            inp_path = inp.name
        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as out:
            out_path = out.name

        try:
            convert_to_owaspdc(inp_path, out_path)
            with open(out_path) as f:
                content = f.read()
            assert "<![CDATA[" in content
            assert "Contains <special> & 'characters'" in content
            # The XML should be parseable
            ET.fromstring(content)
        finally:
            Path(inp_path).unlink(missing_ok=True)
            Path(out_path).unlink(missing_ok=True)

    def test_vulnerability_name_preserved(self):
        """vulnerability-names should be emitted as <vulnerabilityName>, not <cve>."""
        data = {
            "version": "1.0",
            "suppressions": [
                {
                    "id": "vuln-name",
                    "type": "cve-triage",
                    "notes": "Test",
                    "match": {"package-url": "^pkg:maven/com\\.example/lib@.*$"},
                    "suppress": {"vulnerability-names": ["CVE-2020-1732"]},
                    "until": "2027-03-26",
                },
            ],
        }
        with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False) as inp:
            yaml.dump(data, inp, default_flow_style=False, sort_keys=False)
            inp_path = inp.name
        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as out:
            out_path = out.name

        try:
            convert_to_owaspdc(inp_path, out_path)
            with open(out_path) as f:
                content = f.read()
            assert "<vulnerabilityName>CVE-2020-1732</vulnerabilityName>" in content
            assert "<cve>CVE-2020-1732</cve>" not in content
        finally:
            Path(inp_path).unlink(missing_ok=True)
            Path(out_path).unlink(missing_ok=True)

    def test_until_attribute(self):
        data = {
            "version": "1.0",
            "suppressions": [
                {
                    "id": "until-test",
                    "type": "cve-triage",
                    "notes": "With expiry",
                    "match": {"package-url": "^pkg:maven/com\\.example/lib@.*$"},
                    "suppress": {"cves": ["CVE-2024-00001"]},
                    "until": "2027-01-15",
                },
            ],
        }
        with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False) as inp:
            yaml.dump(data, inp, default_flow_style=False, sort_keys=False)
            inp_path = inp.name
        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as out:
            out_path = out.name

        try:
            convert_to_owaspdc(inp_path, out_path)
            with open(out_path) as f:
                content = f.read()
            assert 'until="2027-01-15"' in content
        finally:
            Path(inp_path).unlink(missing_ok=True)
            Path(out_path).unlink(missing_ok=True)

    def test_cdata_injection_escaped(self):
        """Notes containing ]]> must not break CDATA sections."""
        data = {
            "version": "1.0",
            "suppressions": [
                {
                    "id": "cdata-inject",
                    "type": "cpe-correction",
                    "notes": "see ]]> for details",
                    "match": {"package-url": "^pkg:maven/com\\.example/lib@.*$"},
                    "suppress": {"cpes": ["cpe:/a:example:product"]},
                },
            ],
        }
        with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False) as inp:
            yaml.dump(data, inp, default_flow_style=False, sort_keys=False)
            inp_path = inp.name
        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as out:
            out_path = out.name

        try:
            convert_to_owaspdc(inp_path, out_path)
            with open(out_path) as f:
                content = f.read()
            ET.fromstring(content)
        finally:
            Path(inp_path).unlink(missing_ok=True)
            Path(out_path).unlink(missing_ok=True)

    def test_both_match_fields_preserved(self):
        """Entries with both package-url and file-path should emit both in XML."""
        data = {
            "version": "1.0",
            "suppressions": [
                {
                    "id": "both-match",
                    "type": "cve-triage",
                    "notes": "Both",
                    "match": {
                        "package-url": "^pkg:maven/com\\.example/lib@.*$",
                        "file-path": "^.*/lib\\.jar$",
                    },
                    "suppress": {"cves": ["CVE-2024-00001"]},
                },
            ],
        }
        with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False) as inp:
            yaml.dump(data, inp, default_flow_style=False, sort_keys=False)
            inp_path = inp.name
        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as out:
            out_path = out.name

        try:
            convert_to_owaspdc(inp_path, out_path)
            with open(out_path) as f:
                content = f.read()
            assert "<packageUrl" in content
            assert "<filePath" in content
            ET.fromstring(content)
        finally:
            Path(inp_path).unlink(missing_ok=True)
            Path(out_path).unlink(missing_ok=True)

    def test_none_notes_handled(self):
        """None notes should not render as literal 'None' string."""
        data = {
            "version": "1.0",
            "suppressions": [
                {
                    "id": "null-notes",
                    "type": "cpe-correction",
                    "notes": None,
                    "match": {"package-url": "^pkg:maven/com\\.example/lib@.*$"},
                    "suppress": {"cpes": ["cpe:/a:example:product"]},
                },
            ],
        }
        with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False) as inp:
            yaml.dump(data, inp, default_flow_style=False, sort_keys=False)
            inp_path = inp.name
        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as out:
            out_path = out.name

        try:
            convert_to_owaspdc(inp_path, out_path)
            with open(out_path) as f:
                content = f.read()
            assert "None" not in content.split("<notes>")[1].split("</notes>")[0]
            ET.fromstring(content)
        finally:
            Path(inp_path).unlink(missing_ok=True)
            Path(out_path).unlink(missing_ok=True)

    def test_invalid_input_raises_valueerror(self):
        with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False) as inp:
            inp.write("")
            inp_path = inp.name
        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as out:
            out_path = out.name

        try:
            with pytest.raises(ValueError):
                convert_to_owaspdc(inp_path, out_path)
        finally:
            Path(inp_path).unlink(missing_ok=True)
            Path(out_path).unlink(missing_ok=True)

    def test_valid_xml_output(self):
        """Generated XML must be parseable."""
        real_yaml = Path(__file__).parent.parent / "suppressions" / "suppressions.yaml"
        if not real_yaml.exists():
            pytest.skip("Canonical YAML not available")

        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as out:
            out_path = out.name

        try:
            convert_to_owaspdc(str(real_yaml), out_path)
            with open(out_path) as f:
                content = f.read()
            ET.fromstring(content)
        finally:
            Path(out_path).unlink(missing_ok=True)


class TestValidation:
    """Tests for the canonical YAML schema validator (validate.py).

    The validator runs in CI on every push to suppressions/ and checks for structural
    errors (missing fields, invalid regex, duplicate IDs) and warnings (expired dates).
    """
    def test_empty_file(self):
        from validate import validate

        with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False) as f:
            f.write("")
            path = f.name

        try:
            errors, warnings = validate(path)
            assert len(errors) > 0
            assert any("empty" in e.lower() for e in errors)
        finally:
            Path(path).unlink(missing_ok=True)

    def test_invalid_regex(self):
        from validate import validate

        data = {
            "version": "1.0",
            "suppressions": [
                {
                    "id": "bad-regex",
                    "type": "cve-triage",
                    "notes": "Test",
                    "match": {"package-url": "^pkg:maven/[unclosed"},
                    "suppress": {"cves": ["CVE-2024-00001"]},
                },
            ],
        }
        with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False) as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False)
            path = f.name

        try:
            errors, warnings = validate(path)
            assert any("regex" in e.lower() for e in errors)
        finally:
            Path(path).unlink(missing_ok=True)

    def test_duplicate_ids(self):
        from validate import validate

        data = {
            "version": "1.0",
            "suppressions": [
                {
                    "id": "duplicate",
                    "type": "cpe-correction",
                    "notes": "First",
                    "match": {"package-url": "^pkg:maven/a/b@.*$"},
                    "suppress": {"cpes": ["cpe:/a:x:y"]},
                },
                {
                    "id": "duplicate",
                    "type": "cpe-correction",
                    "notes": "Second",
                    "match": {"package-url": "^pkg:maven/c/d@.*$"},
                    "suppress": {"cpes": ["cpe:/a:x:z"]},
                },
            ],
        }
        with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False) as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False)
            path = f.name

        try:
            errors, warnings = validate(path)
            assert any("duplicate" in e.lower() for e in errors)
        finally:
            Path(path).unlink(missing_ok=True)

    def test_expired_until_warning(self):
        from validate import validate

        data = {
            "version": "1.0",
            "suppressions": [
                {
                    "id": "expired",
                    "type": "cve-triage",
                    "notes": "Expired",
                    "match": {"package-url": "^pkg:maven/a/b@.*$"},
                    "suppress": {"cves": ["CVE-2024-00001"]},
                    "until": "2020-01-01",
                },
            ],
        }
        with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False) as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False)
            path = f.name

        try:
            errors, warnings = validate(path)
            assert len(errors) == 0
            assert any("expired" in w.lower() for w in warnings)
        finally:
            Path(path).unlink(missing_ok=True)

    def test_non_string_regex_reports_error(self):
        from validate import validate

        data = {
            "version": "1.0",
            "suppressions": [
                {
                    "id": "bad-type",
                    "type": "cve-triage",
                    "notes": "Test",
                    "match": {"package-url": 12345},
                    "suppress": {"cves": ["CVE-2024-00001"]},
                },
            ],
        }
        with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False) as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False)
            path = f.name

        try:
            errors, warnings = validate(path)
            assert any("string" in e.lower() for e in errors)
        finally:
            Path(path).unlink(missing_ok=True)

    def test_non_string_until_reports_error(self):
        from validate import validate

        data = {
            "version": "1.0",
            "suppressions": [
                {
                    "id": "bad-until",
                    "type": "cve-triage",
                    "notes": "Test",
                    "match": {"package-url": "^pkg:maven/a/b@.*$"},
                    "suppress": {"cves": ["CVE-2024-00001"]},
                    "until": 20270326,
                },
            ],
        }
        with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False) as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False)
            path = f.name

        try:
            errors, warnings = validate(path)
            assert any("string" in e.lower() for e in errors)
        finally:
            Path(path).unlink(missing_ok=True)

    def test_datetime_date_until_accepted(self):
        """PyYAML parses unquoted YYYY-MM-DD as datetime.date — validator should coerce it."""
        from datetime import date
        from validate import validate

        data = {
            "version": "1.0",
            "suppressions": [
                {
                    "id": "date-obj",
                    "type": "cve-triage",
                    "notes": "Test",
                    "match": {"package-url": "^pkg:maven/a/b@.*$"},
                    "suppress": {"cves": ["CVE-2024-00001"]},
                    "until": date(2027, 3, 26),
                },
            ],
        }
        with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False) as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False)
            path = f.name

        try:
            errors, warnings = validate(path)
            assert not any("until" in e.lower() for e in errors), f"Unexpected errors: {errors}"
        finally:
            Path(path).unlink(missing_ok=True)

    def test_non_dict_entry_reports_error(self):
        from validate import validate

        data = {
            "version": "1.0",
            "suppressions": ["CVE-2024-00001"],
        }
        with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False) as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False)
            path = f.name

        try:
            errors, warnings = validate(path)
            assert any("mapping" in e.lower() for e in errors)
        finally:
            Path(path).unlink(missing_ok=True)

    def test_non_list_suppressions_reports_error(self):
        from validate import validate

        data = {
            "version": "1.0",
            "suppressions": "none",
        }
        with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False) as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False)
            path = f.name

        try:
            errors, warnings = validate(path)
            assert any("list" in e.lower() for e in errors)
        finally:
            Path(path).unlink(missing_ok=True)

    def test_valid_real_file(self):
        from validate import validate

        real_yaml = Path(__file__).parent.parent / "suppressions" / "suppressions.yaml"
        if not real_yaml.exists():
            pytest.skip("Canonical YAML not available")

        errors, warnings = validate(str(real_yaml))
        assert len(errors) == 0
