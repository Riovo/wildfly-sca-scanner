#!/usr/bin/env python3
"""Tests for the scan-time PURL resolver (resolve_suppressions.py).

Tests all regex pattern types that appear in the real suppression file:
  - Exact group/artifact (fast path, no scan data needed)
  - Wildcard artifact (e.g. org.wildfly.core/.*)
  - Negative lookahead (e.g. netty (?!netty-codec-http3))
  - Character class (e.g. cxf[^/]*)
  - Alternation (e.g. (relaxng-datatype|rngom))
  - Version-specific (e.g. httpcore@4\\.*)

Also covers edge cases (empty scan, no matches, invalid input, PURLs with qualifiers)
and integration against the real canonical YAML with synthetic Trivy JSON.
"""

import datetime
import json
import tempfile
from pathlib import Path

import pytest
import yaml

from resolve_suppressions import resolve, _extract_purls, _resolve_pattern, _strip_version


def _make_trivy_json(purls):
    """Build minimal Trivy JSON with the given PURLs in the Packages list.

    Mirrors the structure of `trivy rootfs --format json` output, with only the
    fields that _extract_purls reads.
    """
    return {
        "Results": [
            {
                "Packages": [
                    {"Identifier": {"PURL": p}} for p in purls
                ],
                "Vulnerabilities": [],
            }
        ]
    }


def _make_yaml(suppressions):
    """Wrap suppression dicts in the canonical YAML structure."""
    return {"version": "1.0", "suppressions": suppressions}


def _run_resolve(yaml_data, trivy_json):
    """Write inputs to temp files, run resolve(), return parsed .trivyignore.yaml output."""
    with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False) as yf:
        yaml.dump(yaml_data, yf, default_flow_style=False, sort_keys=False)
        yaml_path = yf.name
    with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as jf:
        json.dump(trivy_json, jf)
        json_path = jf.name
    with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False) as of:
        out_path = of.name

    try:
        resolve(yaml_path, json_path, out_path)
        with open(out_path) as f:
            return yaml.safe_load(f)
    finally:
        Path(yaml_path).unlink(missing_ok=True)
        Path(json_path).unlink(missing_ok=True)
        Path(out_path).unlink(missing_ok=True)


class TestStripVersion:
    def test_strips_version(self):
        assert _strip_version("pkg:maven/com.example/lib@1.2.3") == "pkg:maven/com.example/lib"

    def test_no_version(self):
        assert _strip_version("pkg:maven/com.example/lib") == "pkg:maven/com.example/lib"


class TestExtractPurls:
    def test_extracts_from_packages(self):
        data = _make_trivy_json([
            "pkg:maven/org.wildfly/wildfly-ee@41.0.1.Final",
            "pkg:maven/io.netty/netty-buffer@4.1.133.Final",
        ])
        purls = _extract_purls(data)
        assert "pkg:maven/org.wildfly/wildfly-ee@41.0.1.Final" in purls
        assert "pkg:maven/io.netty/netty-buffer@4.1.133.Final" in purls

    def test_extracts_from_vulnerabilities(self):
        data = {
            "Results": [{
                "Packages": [],
                "Vulnerabilities": [
                    {"PkgIdentifier": {"PURL": "pkg:maven/com.example/vuln@1.0"}},
                ],
            }]
        }
        purls = _extract_purls(data)
        assert "pkg:maven/com.example/vuln@1.0" in purls

    def test_deduplicates(self):
        data = {
            "Results": [{
                "Packages": [{"Identifier": {"PURL": "pkg:maven/a/b@1.0"}}],
                "Vulnerabilities": [{"PkgIdentifier": {"PURL": "pkg:maven/a/b@1.0"}}],
            }]
        }
        purls = _extract_purls(data)
        assert len(purls) == 1

    def test_empty_results(self):
        assert _extract_purls({}) == set()
        assert _extract_purls({"Results": []}) == set()


class TestResolvePattern:
    """Test regex matching against discovered PURLs — the core of scan-time resolution."""
    def test_wildcard_artifact(self):
        purls = {
            "pkg:maven/org.wildfly.core/wildfly-controller@26.0.0.Final",
            "pkg:maven/org.wildfly.core/wildfly-server@26.0.0.Final",
            "pkg:maven/org.wildfly/wildfly-ee@41.0.1.Final",
        }
        matched = _resolve_pattern(r"^pkg:maven/org\.wildfly\.core/.*@.*$", purls)
        assert matched == [
            "pkg:maven/org.wildfly.core/wildfly-controller",
            "pkg:maven/org.wildfly.core/wildfly-server",
        ]

    def test_negative_lookahead(self):
        purls = {
            "pkg:maven/io.netty/netty-buffer@4.1.133.Final",
            "pkg:maven/io.netty/netty-codec-http@4.1.133.Final",
            "pkg:maven/io.netty/netty-codec-http3@4.2.0.Final",
        }
        matched = _resolve_pattern(
            r"^pkg:maven/io\.netty/(?!netty-codec-http3).*@.*$", purls
        )
        assert "pkg:maven/io.netty/netty-buffer" in matched
        assert "pkg:maven/io.netty/netty-codec-http" in matched
        assert "pkg:maven/io.netty/netty-codec-http3" not in matched

    def test_character_class(self):
        purls = {
            "pkg:maven/org.apache.cxf/cxf-core@4.0.11",
            "pkg:maven/org.apache.cxf.services/cxf-services-sts-core@4.0.11",
        }
        matched = _resolve_pattern(r"^pkg:maven/org\.apache\.cxf[^/]*/.*@.*$", purls)
        assert "pkg:maven/org.apache.cxf/cxf-core" in matched
        assert "pkg:maven/org.apache.cxf.services/cxf-services-sts-core" in matched

    def test_alternation(self):
        purls = {
            "pkg:maven/com.sun.xml.bind.external/relaxng-datatype@4.0.8",
            "pkg:maven/com.sun.xml.bind.external/rngom@4.0.8",
            "pkg:maven/com.sun.xml.bind.external/other-lib@4.0.8",
        }
        matched = _resolve_pattern(
            r"^pkg:maven/com\.sun\.xml\.bind\.external/(relaxng-datatype|rngom)@.*$", purls
        )
        assert "pkg:maven/com.sun.xml.bind.external/relaxng-datatype" in matched
        assert "pkg:maven/com.sun.xml.bind.external/rngom" in matched
        assert "pkg:maven/com.sun.xml.bind.external/other-lib" not in matched

    def test_version_specific_pattern(self):
        purls = {
            "pkg:maven/org.apache.httpcomponents/httpcore@4.4.16",
            "pkg:maven/org.apache.httpcomponents/httpcore-nio@4.4.16",
            "pkg:maven/org.apache.httpcomponents/httpcore@5.2.1",
        }
        matched = _resolve_pattern(
            r"^pkg:maven/org\.apache\.httpcomponents/httpcore(-nio)?@4\..*$", purls
        )
        assert "pkg:maven/org.apache.httpcomponents/httpcore" in matched
        assert "pkg:maven/org.apache.httpcomponents/httpcore-nio" in matched
        assert len(matched) == 2

    def test_no_matches(self):
        purls = {"pkg:maven/com.example/something@1.0"}
        matched = _resolve_pattern(r"^pkg:maven/org\.wildfly/.*@.*$", purls)
        assert matched == []

    def test_invalid_regex(self):
        matched = _resolve_pattern("[unclosed", {"pkg:maven/a/b@1.0"})
        assert matched == []


class TestStripVersionEdgeCases:
    def test_purl_with_qualifier(self):
        assert _strip_version("pkg:maven/com.example/lib@1.0?type=pom") == "pkg:maven/com.example/lib"

    def test_purl_with_subpath(self):
        assert _strip_version("pkg:maven/com.example/lib@1.0#sub/path") == "pkg:maven/com.example/lib"


class TestResolveEndToEnd:
    """End-to-end tests: canonical YAML + Trivy JSON → resolved .trivyignore.yaml."""
    def test_exact_match_passthrough(self):
        data = _make_yaml([{
            "id": "exact-test",
            "type": "cve-triage",
            "notes": "Exact",
            "match": {"package-url": r"^pkg:maven/com\.h2database/h2@.*$"},
            "suppress": {"cves": ["CVE-2018-14335"]},
            "until": "2027-03-26",
        }])
        trivy = _make_trivy_json(["pkg:maven/com.h2database/h2@2.2.224"])
        result = _run_resolve(data, trivy)
        assert len(result["vulnerabilities"]) == 1
        entry = result["vulnerabilities"][0]
        assert entry["id"] == "CVE-2018-14335"
        assert entry["purls"] == ["pkg:maven/com.h2database/h2"]
        assert entry["expired_at"] == datetime.date(2027, 3, 26)

    def test_wildcard_resolved(self):
        data = _make_yaml([{
            "id": "wildcard-test",
            "type": "cve-triage",
            "notes": "Wildcard",
            "match": {"package-url": r"^pkg:maven/org\.wildfly\.core/.*@.*$"},
            "suppress": {"cves": ["CVE-2025-23368"]},
        }])
        trivy = _make_trivy_json([
            "pkg:maven/org.wildfly.core/wildfly-controller@26.0.0.Final",
            "pkg:maven/org.wildfly.core/wildfly-server@26.0.0.Final",
            "pkg:maven/org.wildfly/wildfly-ee@41.0.1.Final",
        ])
        result = _run_resolve(data, trivy)
        assert len(result["vulnerabilities"]) == 1
        entry = result["vulnerabilities"][0]
        assert entry["id"] == "CVE-2025-23368"
        assert "pkg:maven/org.wildfly.core/wildfly-controller" in entry["purls"]
        assert "pkg:maven/org.wildfly.core/wildfly-server" in entry["purls"]
        assert "pkg:maven/org.wildfly/wildfly-ee" not in entry["purls"]

    def test_negative_lookahead_resolved(self):
        data = _make_yaml([{
            "id": "lookahead-test",
            "type": "cve-triage",
            "notes": "Netty",
            "match": {"package-url": r"^pkg:maven/io\.netty/(?!netty-codec-http3).*@.*$"},
            "suppress": {"cves": ["CVE-2026-42582"]},
        }])
        trivy = _make_trivy_json([
            "pkg:maven/io.netty/netty-buffer@4.1.133.Final",
            "pkg:maven/io.netty/netty-codec-http@4.1.133.Final",
        ])
        result = _run_resolve(data, trivy)
        assert len(result["vulnerabilities"]) == 1
        entry = result["vulnerabilities"][0]
        assert "pkg:maven/io.netty/netty-buffer" in entry["purls"]
        assert "pkg:maven/io.netty/netty-codec-http" in entry["purls"]

    def test_character_class_resolved(self):
        data = _make_yaml([{
            "id": "cxf-test",
            "type": "cve-triage",
            "notes": "CXF",
            "match": {"package-url": r"^pkg:maven/org\.apache\.cxf[^/]*/.*@.*$"},
            "suppress": {"cves": ["CVE-2026-44930"]},
        }])
        trivy = _make_trivy_json([
            "pkg:maven/org.apache.cxf/cxf-core@4.0.11",
            "pkg:maven/org.apache.cxf.services/cxf-services-sts-core@4.0.11",
        ])
        result = _run_resolve(data, trivy)
        assert len(result["vulnerabilities"]) == 1
        assert len(result["vulnerabilities"][0]["purls"]) == 2

    def test_no_match_skipped(self):
        data = _make_yaml([{
            "id": "absent-test",
            "type": "cve-triage",
            "notes": "Not in scan",
            "match": {"package-url": r"^pkg:maven/org\.nonexistent/.*@.*$"},
            "suppress": {"cves": ["CVE-2024-99999"]},
        }])
        trivy = _make_trivy_json(["pkg:maven/com.example/lib@1.0"])
        result = _run_resolve(data, trivy)
        assert result["vulnerabilities"] == []

    def test_cpe_only_skipped(self):
        data = _make_yaml([{
            "id": "cpe-test",
            "type": "cpe-correction",
            "notes": "CPE only",
            "match": {"package-url": r"^pkg:maven/com\.example/lib@.*$"},
            "suppress": {"cpes": ["cpe:/a:example:product"]},
        }])
        trivy = _make_trivy_json(["pkg:maven/com.example/lib@1.0"])
        result = _run_resolve(data, trivy)
        assert result["vulnerabilities"] == []

    def test_filepath_only_skipped(self):
        data = _make_yaml([{
            "id": "filepath-test",
            "type": "cve-triage",
            "notes": "File path",
            "match": {"file-path": r"^.*/jboss-client\.jar$"},
            "suppress": {"cves": ["CVE-2026-42582"]},
        }])
        trivy = _make_trivy_json([])
        result = _run_resolve(data, trivy)
        assert result["vulnerabilities"] == []

    def test_multiple_cves_expanded(self):
        data = _make_yaml([{
            "id": "multi-cve",
            "type": "cve-triage",
            "notes": "Multiple CVEs",
            "match": {"package-url": r"^pkg:maven/org\.wildfly/.*@.*$"},
            "suppress": {"cves": ["CVE-2022-0866", "CVE-2025-23368"]},
        }])
        trivy = _make_trivy_json(["pkg:maven/org.wildfly/wildfly-ee@41.0.1.Final"])
        result = _run_resolve(data, trivy)
        assert len(result["vulnerabilities"]) == 2
        ids = {v["id"] for v in result["vulnerabilities"]}
        assert ids == {"CVE-2022-0866", "CVE-2025-23368"}
        for entry in result["vulnerabilities"]:
            assert entry["purls"] == ["pkg:maven/org.wildfly/wildfly-ee"]

    def test_expired_at_is_date_object(self):
        data = _make_yaml([{
            "id": "date-test",
            "type": "cve-triage",
            "notes": "Date check",
            "match": {"package-url": r"^pkg:maven/com\.example/lib@.*$"},
            "suppress": {"cves": ["CVE-2024-00001"]},
            "until": "2027-06-15",
        }])
        trivy = _make_trivy_json(["pkg:maven/com.example/lib@1.0"])
        result = _run_resolve(data, trivy)
        val = result["vulnerabilities"][0]["expired_at"]
        assert isinstance(val, datetime.date)
        assert val == datetime.date(2027, 6, 15)

    def test_empty_scan_results(self):
        data = _make_yaml([{
            "id": "wildcard-test",
            "type": "cve-triage",
            "notes": "Wildcard",
            "match": {"package-url": r"^pkg:maven/org\.wildfly/.*@.*$"},
            "suppress": {"cves": ["CVE-2022-0866"]},
        }])
        trivy = _make_trivy_json([])
        result = _run_resolve(data, trivy)
        assert result["vulnerabilities"] == []

    def test_no_global_suppressions_in_output(self):
        """The resolved output must never have entries without purls."""
        data = _make_yaml([
            {
                "id": "exact",
                "type": "cve-triage",
                "notes": "Exact",
                "match": {"package-url": r"^pkg:maven/com\.h2database/h2@.*$"},
                "suppress": {"cves": ["CVE-2018-14335"]},
            },
            {
                "id": "wildcard",
                "type": "cve-triage",
                "notes": "Wildcard",
                "match": {"package-url": r"^pkg:maven/org\.wildfly\.core/.*@.*$"},
                "suppress": {"cves": ["CVE-2025-23368"]},
            },
            {
                "id": "absent",
                "type": "cve-triage",
                "notes": "Absent",
                "match": {"package-url": r"^pkg:maven/org\.nonexistent/.*@.*$"},
                "suppress": {"cves": ["CVE-9999-9999"]},
            },
        ])
        trivy = _make_trivy_json([
            "pkg:maven/com.h2database/h2@2.2.224",
            "pkg:maven/org.wildfly.core/wildfly-controller@26.0.0.Final",
        ])
        result = _run_resolve(data, trivy)
        for entry in result["vulnerabilities"]:
            assert "purls" in entry, f"Entry {entry['id']} has no purls — would be a global suppression"
            assert len(entry["purls"]) > 0

    def test_version_specific_matching(self):
        """Patterns with version constraints should only match appropriate versions."""
        data = _make_yaml([{
            "id": "httpcore-test",
            "type": "cve-triage",
            "notes": "Version 4.x only",
            "match": {"package-url": r"^pkg:maven/org\.apache\.httpcomponents/httpcore(-nio)?@4\..*$"},
            "suppress": {"cves": ["CVE-2026-54399"]},
        }])
        trivy = _make_trivy_json([
            "pkg:maven/org.apache.httpcomponents/httpcore@4.4.16",
            "pkg:maven/org.apache.httpcomponents/httpcore-nio@4.4.16",
            "pkg:maven/org.apache.httpcomponents/httpcore@5.2.1",
        ])
        result = _run_resolve(data, trivy)
        assert len(result["vulnerabilities"]) == 1
        purls = result["vulnerabilities"][0]["purls"]
        assert "pkg:maven/org.apache.httpcomponents/httpcore" in purls
        assert "pkg:maven/org.apache.httpcomponents/httpcore-nio" in purls
        assert len(purls) == 2

    def test_invalid_yaml_raises(self):
        with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False) as yf:
            yf.write("")
            yaml_path = yf.name
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as jf:
            json.dump(_make_trivy_json([]), jf)
            json_path = jf.name
        with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False) as of:
            out_path = of.name
        try:
            with pytest.raises(ValueError):
                resolve(yaml_path, json_path, out_path)
        finally:
            Path(yaml_path).unlink(missing_ok=True)
            Path(json_path).unlink(missing_ok=True)
            Path(out_path).unlink(missing_ok=True)


class TestRealDataResolution:
    """Integration test against the real canonical YAML with synthetic Trivy JSON.

    Uses PURLs that match the real wildcard suppression patterns (org.wildfly.core,
    io.netty, org.apache.cxf, etc.) to verify that no global suppressions leak through
    the resolver — every output entry must have a purls list.
    """

    REAL_YAML = Path(__file__).parent.parent / "suppressions" / "suppressions.yaml"

    def test_all_entries_have_purls(self):
        if not self.REAL_YAML.exists():
            pytest.skip("Real canonical YAML not available")

        trivy = _make_trivy_json([
            "pkg:maven/org.apache.directory.server/apacheds-interceptors-admin@2.0.0.AM26",
            "pkg:maven/org.eclipse.jgit/org.eclipse.jgit@6.10.1.202505221210-r",
            "pkg:maven/org.wildfly/wildfly-ee@41.0.1.Final",
            "pkg:maven/org.wildfly/jipijapa-hibernate6@41.0.1.Final",
            "pkg:maven/org.elasticsearch.client/elasticsearch-rest-client@8.15.4",
            "pkg:maven/org.wildfly.core/wildfly-controller@26.0.0.Final",
            "pkg:maven/org.wildfly.core/wildfly-server@26.0.0.Final",
            "pkg:maven/com.sun.xml.bind.external/relaxng-datatype@4.0.8",
            "pkg:maven/com.sun.xml.bind.external/rngom@4.0.8",
            "pkg:maven/io.netty/netty-buffer@4.1.133.Final",
            "pkg:maven/io.netty/netty-codec-http@4.1.133.Final",
            "pkg:maven/io.netty/netty-transport@4.1.133.Final",
            "pkg:maven/org.apache.cxf/cxf-core@4.0.11",
            "pkg:maven/org.apache.cxf.services/cxf-services-sts-core@4.0.11",
            "pkg:maven/org.apache.httpcomponents/httpcore@4.4.16",
            "pkg:maven/org.apache.httpcomponents/httpcore-nio@4.4.16",
        ])

        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as jf:
            json.dump(trivy, jf)
            json_path = jf.name
        with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False) as of:
            out_path = of.name

        try:
            resolve(str(self.REAL_YAML), json_path, out_path)
            with open(out_path) as f:
                result = yaml.safe_load(f)

            for entry in result["vulnerabilities"]:
                assert "purls" in entry, (
                    f"Entry {entry['id']} has no purls — global suppression leaked through"
                )
                assert len(entry["purls"]) > 0
        finally:
            Path(json_path).unlink(missing_ok=True)
            Path(out_path).unlink(missing_ok=True)
