package org.wildfly.security.sca.suppressions.resolver;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.yaml.snakeyaml.Yaml;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class SuppressionResolverTest {

    @TempDir
    Path tempDir;

    private Path writeYaml(String content) throws IOException {
        Path file = tempDir.resolve("suppressions.yaml");
        Files.writeString(file, content);
        return file;
    }

    private Path writeJson(Object data) throws IOException {
        Path file = tempDir.resolve("trivy.json");
        new ObjectMapper().writeValue(file.toFile(), data);
        return file;
    }

    @SuppressWarnings("unchecked")
    private List<Map<String, Object>> resolveAndRead(String yaml, Object json) throws IOException {
        Path yamlPath = writeYaml(yaml);
        Path jsonPath = writeJson(json);
        Path output = tempDir.resolve("resolved.yaml");
        new SuppressionResolver().resolve(yamlPath, jsonPath, output);
        Map<String, Object> data = new Yaml().load(Files.readString(output));
        return (List<Map<String, Object>>) data.get("vulnerabilities");
    }

    private Map<String, Object> trivyJson(String... purls) {
        List<Map<String, Object>> packages = new java.util.ArrayList<>();
        for (String purl : purls) {
            packages.add(Map.of("Identifier", Map.of("PURL", purl)));
        }
        return Map.of("Results", List.of(Map.of("Packages", packages)));
    }

    @Nested
    class StripVersion {
        @Test
        void testStripsVersion() {
            assertThat(SuppressionResolver.stripVersion("pkg:maven/g/a@1.0"))
                    .isEqualTo("pkg:maven/g/a");
        }

        @Test
        void testNoVersion() {
            assertThat(SuppressionResolver.stripVersion("pkg:maven/g/a"))
                    .isEqualTo("pkg:maven/g/a");
        }
    }

    @Nested
    class ExtractPurls {

        private static final ObjectMapper MAPPER = new ObjectMapper();

        private JsonNode toJsonNode(Object data) throws IOException {
            return MAPPER.valueToTree(data);
        }

        @Test
        void testFromPackages() throws IOException {
            JsonNode node = toJsonNode(trivyJson("pkg:maven/org.example/lib@1.0"));
            Set<String> purls = SuppressionResolver.extractPurls(node);
            assertThat(purls).contains("pkg:maven/org.example/lib@1.0");
        }

        @Test
        void testFromVulnerabilities() throws IOException {
            JsonNode node = toJsonNode(Map.of("Results", List.of(Map.of(
                    "Vulnerabilities", List.of(Map.of(
                            "PkgIdentifier", Map.of("PURL", "pkg:maven/org.example/lib@1.0")))))));
            Set<String> purls = SuppressionResolver.extractPurls(node);
            assertThat(purls).contains("pkg:maven/org.example/lib@1.0");
        }

        @Test
        void testDeduplicates() throws IOException {
            JsonNode node = toJsonNode(Map.of("Results", List.of(Map.of(
                    "Packages", List.of(
                            Map.of("Identifier", Map.of("PURL", "pkg:maven/g/a@1.0"))),
                    "Vulnerabilities", List.of(
                            Map.of("PkgIdentifier", Map.of("PURL", "pkg:maven/g/a@1.0")))))));
            Set<String> purls = SuppressionResolver.extractPurls(node);
            assertThat(purls).hasSize(1);
        }

        @Test
        void testEmptyResults() throws IOException {
            JsonNode node = toJsonNode(Map.of("Results", List.of()));
            Set<String> purls = SuppressionResolver.extractPurls(node);
            assertThat(purls).isEmpty();
        }
    }

    @Nested
    class ResolvePattern {
        @Test
        void testWildcardArtifact() {
            Set<String> purls = Set.of("pkg:maven/org.example/lib@1.0", "pkg:maven/org.example/other@2.0");
            List<String> matched = SuppressionResolver.resolvePattern(
                    "^pkg:maven/org\\.example/.*@.*$", purls);
            assertThat(matched).containsExactly("pkg:maven/org.example/lib", "pkg:maven/org.example/other");
        }

        @Test
        void testNegativeLookahead() {
            Set<String> purls = Set.of(
                    "pkg:maven/io.netty/netty-common@4.1.0",
                    "pkg:maven/io.netty/netty-codec-http3@0.0.1");
            List<String> matched = SuppressionResolver.resolvePattern(
                    "^pkg:maven/io\\.netty/(?!netty-codec-http3).*@.*$", purls);
            assertThat(matched).containsExactly("pkg:maven/io.netty/netty-common");
        }

        @Test
        void testCharacterClass() {
            Set<String> purls = Set.of("pkg:maven/org.example/lib@1.0");
            List<String> matched = SuppressionResolver.resolvePattern(
                    "^pkg:maven/org\\.example/[a-z]+@.*$", purls);
            assertThat(matched).containsExactly("pkg:maven/org.example/lib");
        }

        @Test
        void testAlternation() {
            Set<String> purls = Set.of(
                    "pkg:maven/org.example/alpha@1.0",
                    "pkg:maven/org.example/beta@1.0",
                    "pkg:maven/org.example/gamma@1.0");
            List<String> matched = SuppressionResolver.resolvePattern(
                    "^pkg:maven/org\\.example/(alpha|beta)@.*$", purls);
            assertThat(matched).containsExactly("pkg:maven/org.example/alpha", "pkg:maven/org.example/beta");
        }

        @Test
        void testVersionSpecific() {
            Set<String> purls = Set.of(
                    "pkg:maven/org.example/lib@4.1.0",
                    "pkg:maven/org.example/lib@5.0.0");
            List<String> matched = SuppressionResolver.resolvePattern(
                    "^pkg:maven/org\\.example/lib@4\\..*$", purls);
            assertThat(matched).containsExactly("pkg:maven/org.example/lib");
        }

        @Test
        void testNoMatches() {
            Set<String> purls = Set.of("pkg:maven/org.other/lib@1.0");
            List<String> matched = SuppressionResolver.resolvePattern(
                    "^pkg:maven/org\\.example/.*@.*$", purls);
            assertThat(matched).isEmpty();
        }

        @Test
        void testInvalidRegex() {
            List<String> matched = SuppressionResolver.resolvePattern("[invalid", Set.of("anything"));
            assertThat(matched).isEmpty();
        }
    }

    @Nested
    class EndToEnd {
        @Test
        void testExactMatchPassthrough() throws IOException {
            List<Map<String, Object>> entries = resolveAndRead("""
                    suppressions:
                      - id: exact
                        type: cve-triage
                        notes: Test
                        match:
                          package-url: '^pkg:maven/com\\.example/lib@.*$'
                        suppress:
                          cves:
                            - CVE-2024-00001
                    """, trivyJson("pkg:maven/com.example/lib@1.0"));
            assertThat(entries).hasSize(1);
            assertThat(entries.get(0)).containsKey("purls");
        }

        @Test
        void testWildcardResolved() throws IOException {
            List<Map<String, Object>> entries = resolveAndRead("""
                    suppressions:
                      - id: wildcard
                        type: cve-triage
                        notes: Test
                        match:
                          package-url: '^pkg:maven/org\\.example/.*@.*$'
                        suppress:
                          cves:
                            - CVE-2024-00001
                    """, trivyJson("pkg:maven/org.example/lib@1.0", "pkg:maven/org.example/other@2.0"));
            assertThat(entries).hasSize(1);
            @SuppressWarnings("unchecked")
            List<String> purls = (List<String>) entries.get(0).get("purls");
            assertThat(purls).contains("pkg:maven/org.example/lib", "pkg:maven/org.example/other");
        }

        @Test
        void testNegativeLookaheadResolved() throws IOException {
            List<Map<String, Object>> entries = resolveAndRead("""
                    suppressions:
                      - id: lookahead
                        type: cve-triage
                        notes: Test
                        match:
                          package-url: '^pkg:maven/io\\.netty/(?!netty-codec-http3).*@.*$'
                        suppress:
                          cves:
                            - CVE-2024-00001
                    """, trivyJson(
                    "pkg:maven/io.netty/netty-common@4.1.0",
                    "pkg:maven/io.netty/netty-codec-http3@0.0.1"));
            assertThat(entries).hasSize(1);
            @SuppressWarnings("unchecked")
            List<String> purls = (List<String>) entries.get(0).get("purls");
            assertThat(purls).containsExactly("pkg:maven/io.netty/netty-common");
        }

        @Test
        void testNoMatchSkipped() throws IOException {
            List<Map<String, Object>> entries = resolveAndRead("""
                    suppressions:
                      - id: no-match
                        type: cve-triage
                        notes: Test
                        match:
                          package-url: '^pkg:maven/org\\.absent/.*@.*$'
                        suppress:
                          cves:
                            - CVE-2024-00001
                    """, trivyJson("pkg:maven/org.example/lib@1.0"));
            assertThat(entries).isEmpty();
        }

        @Test
        void testCpeOnlySkipped() throws IOException {
            List<Map<String, Object>> entries = resolveAndRead("""
                    suppressions:
                      - id: cpe-only
                        type: cpe-correction
                        notes: Test
                        match:
                          package-url: '^pkg:maven/com\\.example/lib@.*$'
                        suppress:
                          cpes:
                            - "cpe:/a:example:product"
                    """, trivyJson("pkg:maven/com.example/lib@1.0"));
            assertThat(entries).isEmpty();
        }

        @Test
        void testFilePathOnlySkipped() throws IOException {
            List<Map<String, Object>> entries = resolveAndRead("""
                    suppressions:
                      - id: filepath
                        type: cve-triage
                        notes: Test
                        match:
                          file-path: '^.*/lib\\.jar$'
                        suppress:
                          cves:
                            - CVE-2024-00001
                    """, trivyJson("pkg:maven/com.example/lib@1.0"));
            assertThat(entries).isEmpty();
        }

        @Test
        void testMultipleCvesExpanded() throws IOException {
            List<Map<String, Object>> entries = resolveAndRead("""
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
                    """, trivyJson("pkg:maven/com.example/lib@1.0"));
            assertThat(entries).hasSize(2);
        }

        @Test
        void testExpiredAtIsDate() throws IOException {
            List<Map<String, Object>> entries = resolveAndRead("""
                    suppressions:
                      - id: dated
                        type: cve-triage
                        notes: Test
                        until: "2027-03-26"
                        match:
                          package-url: '^pkg:maven/com\\.example/lib@.*$'
                        suppress:
                          cves:
                            - CVE-2024-00001
                    """, trivyJson("pkg:maven/com.example/lib@1.0"));
            assertThat(entries).hasSize(1);
            assertThat(entries.get(0).get("expired_at")).isInstanceOf(Date.class);
        }

        @Test
        void testEmptyScan() throws IOException {
            List<Map<String, Object>> entries = resolveAndRead("""
                    suppressions:
                      - id: empty
                        type: cve-triage
                        notes: Test
                        match:
                          package-url: '^pkg:maven/org\\.example/.*@.*$'
                        suppress:
                          cves:
                            - CVE-2024-00001
                    """, Map.of("Results", List.of()));
            assertThat(entries).isEmpty();
        }

        @Test
        @SuppressWarnings("unchecked")
        void testNoGlobalSuppressions() throws IOException {
            List<Map<String, Object>> entries = resolveAndRead("""
                    suppressions:
                      - id: exact
                        type: cve-triage
                        notes: Test
                        match:
                          package-url: '^pkg:maven/com\\.example/lib@.*$'
                        suppress:
                          cves:
                            - CVE-2024-00001
                      - id: wildcard
                        type: cve-triage
                        notes: Test
                        match:
                          package-url: '^pkg:maven/org\\.example/.*@.*$'
                        suppress:
                          cves:
                            - CVE-2024-00002
                    """, trivyJson(
                    "pkg:maven/com.example/lib@1.0",
                    "pkg:maven/org.example/foo@2.0"));
            for (Map<String, Object> entry : entries) {
                assertThat(entry).containsKey("purls");
                assertThat((List<String>) entry.get("purls")).isNotEmpty();
            }
        }
    }
}
