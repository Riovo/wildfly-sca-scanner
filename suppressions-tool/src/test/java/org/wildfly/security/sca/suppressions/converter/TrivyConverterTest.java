package org.wildfly.security.sca.suppressions.converter;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class TrivyConverterTest {

    @TempDir
    Path tempDir;

    private Path writeYaml(String content) throws IOException {
        Path file = tempDir.resolve("input.yaml");
        Files.writeString(file, content);
        return file;
    }

    @SuppressWarnings("unchecked")
    private List<Map<String, Object>> convertAndRead(String yaml) throws IOException {
        Path input = writeYaml(yaml);
        Path output = tempDir.resolve("output.yaml");
        new TrivyConverter().convert(input, output);
        Map<String, Object> data = new Yaml(new SafeConstructor(new LoaderOptions())).load(Files.readString(output));
        return (List<Map<String, Object>>) data.get("vulnerabilities");
    }

    @Test
    void testCpeOnlySkipped() throws IOException {
        List<Map<String, Object>> entries = convertAndRead("""
                suppressions:
                  - id: cpe-only
                    type: cpe-correction
                    notes: Test
                    match:
                      package-url: '^pkg:maven/com\\.example/lib@.*$'
                    suppress:
                      cpes:
                        - "cpe:/a:example:product"
                """);
        assertThat(entries).isEmpty();
    }

    @Test
    void testFilePathOnlySkipped() throws IOException {
        List<Map<String, Object>> entries = convertAndRead("""
                suppressions:
                  - id: filepath-only
                    type: cve-triage
                    notes: Test
                    match:
                      file-path: '^.*/lib\\.jar$'
                    suppress:
                      cves:
                        - CVE-2024-00001
                """);
        assertThat(entries).isEmpty();
    }

    @Test
    void testCveTriageConverted() throws IOException {
        List<Map<String, Object>> entries = convertAndRead("""
                suppressions:
                  - id: exact
                    type: cve-triage
                    notes: Test
                    match:
                      package-url: '^pkg:maven/com\\.example/lib@.*$'
                    suppress:
                      cves:
                        - CVE-2024-00001
                """);
        assertThat(entries).hasSize(1);
        assertThat(entries.get(0).get("id")).isEqualTo("CVE-2024-00001");
        assertThat(entries.get(0)).containsKey("purls");
    }

    @Test
    void testVulnerabilityNamesConverted() throws IOException {
        List<Map<String, Object>> entries = convertAndRead("""
                suppressions:
                  - id: vulnname
                    type: cve-triage
                    notes: Test
                    match:
                      package-url: '^pkg:maven/com\\.example/lib@.*$'
                    suppress:
                      vulnerability-names:
                        - CVE-2024-00001
                """);
        assertThat(entries).hasSize(1);
        assertThat(entries.get(0).get("id")).isEqualTo("CVE-2024-00001");
    }

    @Test
    void testMultipleCvesExpanded() throws IOException {
        List<Map<String, Object>> entries = convertAndRead("""
                suppressions:
                  - id: multi
                    type: cve-triage
                    notes: Test
                    match:
                      package-url: '^pkg:maven/com\\.example/lib@.*$'
                    suppress:
                      cves:
                        - CVE-2024-00001
                        - CVE-2024-00002
                        - CVE-2024-00003
                """);
        assertThat(entries).hasSize(3);
    }

    @Test
    void testEmptySuppressions() throws IOException {
        List<Map<String, Object>> entries = convertAndRead("""
                suppressions: []
                """);
        assertThat(entries).isEmpty();
    }

    @Test
    void testNoMatchFieldsSkipped() throws IOException {
        List<Map<String, Object>> entries = convertAndRead("""
                suppressions:
                  - id: no-match
                    type: cve-triage
                    notes: Test
                    match: {}
                    suppress:
                      cves:
                        - CVE-2024-00001
                """);
        assertThat(entries).isEmpty();
    }

    @Test
    void testBothMatchFieldsUsesPurl() throws IOException {
        List<Map<String, Object>> entries = convertAndRead("""
                suppressions:
                  - id: both
                    type: cve-triage
                    notes: Test
                    match:
                      package-url: '^pkg:maven/com\\.example/lib@.*$'
                      file-path: '^.*/lib\\.jar$'
                    suppress:
                      cves:
                        - CVE-2024-00001
                """);
        assertThat(entries).hasSize(1);
        assertThat(entries.get(0)).containsKey("purls");
    }

    @Test
    void testWildcardBecomesGlobal() throws IOException {
        List<Map<String, Object>> entries = convertAndRead("""
                suppressions:
                  - id: wildcard
                    type: cve-triage
                    notes: Test
                    match:
                      package-url: '^pkg:maven/org\\.wildfly\\.core/.*@.*$'
                    suppress:
                      cves:
                        - CVE-2024-00001
                """);
        assertThat(entries).hasSize(1);
        assertThat(entries.get(0)).doesNotContainKey("purls");
        assertThat((String) entries.get(0).get("statement")).contains("pattern");
    }

    @Test
    void testNegativeLookaheadSkipped() throws IOException {
        List<Map<String, Object>> entries = convertAndRead("""
                suppressions:
                  - id: lookahead
                    type: cve-triage
                    notes: Test
                    match:
                      package-url: '^pkg:maven/io\\.netty/(?!netty-codec-http3).*@.*$'
                    suppress:
                      cves:
                        - CVE-2024-00001
                """);
        assertThat(entries).isEmpty();
    }

    @Test
    void testInvalidInputRaisesError() throws IOException {
        Path input = writeYaml("invalid: true");
        Path output = tempDir.resolve("output.yaml");
        assertThatThrownBy(() -> new TrivyConverter().convert(input, output))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void testDateFormattedAsBareDateOnly() throws IOException {
        Path input = writeYaml("""
                suppressions:
                  - id: date-format
                    type: cve-triage
                    notes: Test date format
                    until: "2027-10-30"
                    match:
                      package-url: '^pkg:maven/com\\.example/lib@.*$'
                    suppress:
                      cves:
                        - CVE-2024-00001
                """);
        Path output = tempDir.resolve("output.yaml");
        new TrivyConverter().convert(input, output);
        String content = Files.readString(output);
        assertThat(content).contains("expired_at: 2027-10-30");
        assertThat(content).doesNotContain("T00:00:00");
    }
}
