#!/usr/bin/env python3
"""Tests for the Trivy and OWASP DC converters, plus the canonical YAML validator.

Each converter translates the canonical YAML into a scanner-specific format:
  - Trivy: .trivyignore.yaml with PURL-scoped CVE entries
  - OWASP DC: XML with CDATA-wrapped notes and namespace-qualified elements

The validator checks the canonical YAML for schema errors (missing fields, invalid regex,
duplicate IDs) and warnings (expired until dates). CI runs it on every push to suppressions/.

See also: test_resolver.py for scan-time PURL resolution tests.
"""

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
    def test_cpe_only_suppressions_skipped(self, tmp_path):
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
        inp_path = tmp_path / "input.yaml"
        out_path = tmp_path / "output.yaml"
        write_yaml(data, inp_path)

        convert_to_trivy(str(inp_path), str(out_path))
        result = yaml.safe_load(out_path.read_text())
        assert result["vulnerabilities"] == []

    def test_filepath_only_suppressions_skipped(self, tmp_path):
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
        inp_path = tmp_path / "input.yaml"
        out_path = tmp_path / "output.yaml"
        write_yaml(data, inp_path)

        convert_to_trivy(str(inp_path), str(out_path))
        result = yaml.safe_load(out_path.read_text())
        assert result["vulnerabilities"] == []

    def test_cve_triage_converted(self, tmp_path):
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
        inp_path = tmp_path / "input.yaml"
        out_path = tmp_path / "output.yaml"
        write_yaml(data, inp_path)

        convert_to_trivy(str(inp_path), str(out_path))
        result = yaml.safe_load(out_path.read_text())
        assert len(result["vulnerabilities"]) == 1
        entry = result["vulnerabilities"][0]
        assert entry["id"] == "CVE-2018-14335"
        import datetime
        assert entry["expired_at"] == datetime.date(2027, 3, 26)
        assert entry["purls"] == ["pkg:maven/com.h2database/h2"]

    def test_vulnerability_names_converted(self, tmp_path):
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
        inp_path = tmp_path / "input.yaml"
        out_path = tmp_path / "output.yaml"
        write_yaml(data, inp_path)

        convert_to_trivy(str(inp_path), str(out_path))
        result = yaml.safe_load(out_path.read_text())
        assert len(result["vulnerabilities"]) == 1
        assert result["vulnerabilities"][0]["id"] == "CVE-2024-00001"
        assert result["vulnerabilities"][0]["purls"] == ["pkg:maven/com.example/lib"]

    def test_multiple_cves_expanded(self, tmp_path):
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
        inp_path = tmp_path / "input.yaml"
        out_path = tmp_path / "output.yaml"
        write_yaml(data, inp_path)

        convert_to_trivy(str(inp_path), str(out_path))
        result = yaml.safe_load(out_path.read_text())
        assert len(result["vulnerabilities"]) == 2
        ids = {v["id"] for v in result["vulnerabilities"]}
        assert ids == {"CVE-2024-00001", "CVE-2024-00002"}

    def test_empty_suppressions(self, tmp_path):
        data = {"version": "1.0", "suppressions": []}
        inp_path = tmp_path / "input.yaml"
        out_path = tmp_path / "output.yaml"
        write_yaml(data, inp_path)

        convert_to_trivy(str(inp_path), str(out_path))
        result = yaml.safe_load(out_path.read_text())
        assert result["vulnerabilities"] == []

    def test_no_match_fields_skipped(self, tmp_path):
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
        inp_path = tmp_path / "input.yaml"
        out_path = tmp_path / "output.yaml"
        write_yaml(data, inp_path)

        convert_to_trivy(str(inp_path), str(out_path))
        result = yaml.safe_load(out_path.read_text())
        assert result["vulnerabilities"] == [], "Entries with no match must be skipped"

    def test_both_package_url_and_filepath_uses_purl(self, tmp_path):
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
        inp_path = tmp_path / "input.yaml"
        out_path = tmp_path / "output.yaml"
        write_yaml(data, inp_path)

        convert_to_trivy(str(inp_path), str(out_path))
        result = yaml.safe_load(out_path.read_text())
        assert len(result["vulnerabilities"]) == 1
        assert result["vulnerabilities"][0]["purls"] == ["pkg:maven/com.example/lib"]
        assert "paths" not in result["vulnerabilities"][0]

    def test_wildcard_pattern_becomes_global(self, tmp_path):
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
        inp_path = tmp_path / "input.yaml"
        out_path = tmp_path / "output.yaml"
        write_yaml(data, inp_path)

        convert_to_trivy(str(inp_path), str(out_path))
        result = yaml.safe_load(out_path.read_text())
        assert len(result["vulnerabilities"]) == 1
        assert "purls" not in result["vulnerabilities"][0]
        assert "Triaged globally" in result["vulnerabilities"][0]["statement"]

    def test_negative_lookahead_skipped(self, tmp_path):
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
        inp_path = tmp_path / "input.yaml"
        out_path = tmp_path / "output.yaml"
        write_yaml(data, inp_path)

        convert_to_trivy(str(inp_path), str(out_path))
        result = yaml.safe_load(out_path.read_text())
        assert result["vulnerabilities"] == []

    def test_invalid_input_raises_valueerror(self, tmp_path):
        inp_path = tmp_path / "input.yaml"
        out_path = tmp_path / "output.yaml"
        inp_path.write_text("")

        with pytest.raises(ValueError):
            convert_to_trivy(str(inp_path), str(out_path))


class TestOWASPDCConverter:
    """Tests for the OWASP DC XML converter (convert_to_owaspdc.py).

    Generates owasp-suppressions-roundtrip.xml from canonical YAML. The output must be
    valid XML with proper CDATA escaping and namespace-qualified elements.
    """
    def test_cdata_wrapping(self, tmp_path):
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
        inp_path = tmp_path / "input.yaml"
        out_path = tmp_path / "output.xml"
        write_yaml(data, inp_path)

        convert_to_owaspdc(str(inp_path), str(out_path))
        content = out_path.read_text()
        assert "<![CDATA[" in content
        assert "Contains <special> & 'characters'" in content
        ET.fromstring(content)

    def test_vulnerability_name_preserved(self, tmp_path):
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
        inp_path = tmp_path / "input.yaml"
        out_path = tmp_path / "output.xml"
        write_yaml(data, inp_path)

        convert_to_owaspdc(str(inp_path), str(out_path))
        content = out_path.read_text()
        assert "<vulnerabilityName>CVE-2020-1732</vulnerabilityName>" in content
        assert "<cve>CVE-2020-1732</cve>" not in content

    def test_until_attribute(self, tmp_path):
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
        inp_path = tmp_path / "input.yaml"
        out_path = tmp_path / "output.xml"
        write_yaml(data, inp_path)

        convert_to_owaspdc(str(inp_path), str(out_path))
        content = out_path.read_text()
        assert 'until="2027-01-15"' in content

    def test_cdata_injection_escaped(self, tmp_path):
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
        inp_path = tmp_path / "input.yaml"
        out_path = tmp_path / "output.xml"
        write_yaml(data, inp_path)

        convert_to_owaspdc(str(inp_path), str(out_path))
        content = out_path.read_text()
        ET.fromstring(content)

    def test_both_match_fields_preserved(self, tmp_path):
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
        inp_path = tmp_path / "input.yaml"
        out_path = tmp_path / "output.xml"
        write_yaml(data, inp_path)

        convert_to_owaspdc(str(inp_path), str(out_path))
        content = out_path.read_text()
        assert "<packageUrl" in content
        assert "<filePath" in content
        ET.fromstring(content)

    def test_none_notes_handled(self, tmp_path):
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
        inp_path = tmp_path / "input.yaml"
        out_path = tmp_path / "output.xml"
        write_yaml(data, inp_path)

        convert_to_owaspdc(str(inp_path), str(out_path))
        content = out_path.read_text()
        assert "None" not in content.split("<notes>")[1].split("</notes>")[0]
        ET.fromstring(content)

    def test_invalid_input_raises_valueerror(self, tmp_path):
        inp_path = tmp_path / "input.yaml"
        out_path = tmp_path / "output.xml"
        inp_path.write_text("")

        with pytest.raises(ValueError):
            convert_to_owaspdc(str(inp_path), str(out_path))

    def test_valid_xml_output(self, tmp_path):
        """Generated XML must be parseable."""
        real_yaml = Path(__file__).parent.parent / "suppressions" / "suppressions.yaml"
        if not real_yaml.exists():
            pytest.skip("Canonical YAML not available")

        out_path = tmp_path / "output.xml"
        convert_to_owaspdc(str(real_yaml), str(out_path))
        content = out_path.read_text()
        ET.fromstring(content)


class TestValidation:
    """Tests for the canonical YAML schema validator (validate.py).

    The validator runs in CI on every push to suppressions/ and checks for structural
    errors (missing fields, invalid regex, duplicate IDs) and warnings (expired dates).
    """
    def test_empty_file(self, tmp_path):
        from validate import validate

        path = tmp_path / "input.yaml"
        path.write_text("")

        errors, warnings = validate(str(path))
        assert len(errors) > 0
        assert any("empty" in e.lower() for e in errors)

    def test_invalid_regex(self, tmp_path):
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
        path = tmp_path / "input.yaml"
        write_yaml(data, path)

        errors, warnings = validate(str(path))
        assert any("regex" in e.lower() for e in errors)

    def test_duplicate_ids(self, tmp_path):
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
        path = tmp_path / "input.yaml"
        write_yaml(data, path)

        errors, warnings = validate(str(path))
        assert any("duplicate" in e.lower() for e in errors)

    def test_expired_until_warning(self, tmp_path):
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
        path = tmp_path / "input.yaml"
        write_yaml(data, path)

        errors, warnings = validate(str(path))
        assert len(errors) == 0
        assert any("expired" in w.lower() for w in warnings)

    def test_non_string_regex_reports_error(self, tmp_path):
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
        path = tmp_path / "input.yaml"
        write_yaml(data, path)

        errors, warnings = validate(str(path))
        assert any("string" in e.lower() for e in errors)

    def test_non_string_until_reports_error(self, tmp_path):
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
        path = tmp_path / "input.yaml"
        write_yaml(data, path)

        errors, warnings = validate(str(path))
        assert any("string" in e.lower() for e in errors)

    def test_datetime_date_until_accepted(self, tmp_path):
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
        path = tmp_path / "input.yaml"
        write_yaml(data, path)

        errors, warnings = validate(str(path))
        assert not any("until" in e.lower() for e in errors), f"Unexpected errors: {errors}"

    def test_non_dict_entry_reports_error(self, tmp_path):
        from validate import validate

        data = {
            "version": "1.0",
            "suppressions": ["CVE-2024-00001"],
        }
        path = tmp_path / "input.yaml"
        write_yaml(data, path)

        errors, warnings = validate(str(path))
        assert any("mapping" in e.lower() for e in errors)

    def test_null_match_and_suppress_handled(self, tmp_path):
        """Validator must not crash when match or suppress is explicitly null."""
        from validate import validate

        data = {
            "version": "1.0",
            "suppressions": [
                {
                    "id": "null-blocks",
                    "type": "cve-triage",
                    "notes": "Test",
                    "match": None,
                    "suppress": None,
                },
            ],
        }
        path = tmp_path / "input.yaml"
        write_yaml(data, path)

        errors, warnings = validate(str(path))
        assert any("package-url" in e or "file-path" in e for e in errors)
        assert any("suppress" in e.lower() for e in errors)

    def test_non_list_suppressions_reports_error(self, tmp_path):
        from validate import validate

        data = {
            "version": "1.0",
            "suppressions": "none",
        }
        path = tmp_path / "input.yaml"
        write_yaml(data, path)

        errors, warnings = validate(str(path))
        assert any("list" in e.lower() for e in errors)

    def test_valid_real_file(self):
        from validate import validate

        real_yaml = Path(__file__).parent.parent / "suppressions" / "suppressions.yaml"
        if not real_yaml.exists():
            pytest.skip("Canonical YAML not available")

        errors, warnings = validate(str(real_yaml))
        assert len(errors) == 0
