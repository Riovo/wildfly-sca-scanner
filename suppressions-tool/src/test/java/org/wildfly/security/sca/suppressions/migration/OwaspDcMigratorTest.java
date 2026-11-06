package org.wildfly.security.sca.suppressions.migration;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.yaml.snakeyaml.Yaml;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class OwaspDcMigratorTest {

    private static final String NS = "https://jeremylong.github.io/DependencyCheck/dependency-suppression.1.3.xsd";

    @TempDir
    Path tempDir;

    private String wrapXml(String inner) {
        return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
               "<suppressions xmlns=\"" + NS + "\">" + inner + "</suppressions>";
    }

    @SuppressWarnings("unchecked")
    private List<Map<String, Object>> migrateXml(String innerXml) throws IOException {
        Path input = tempDir.resolve("input.xml");
        Files.writeString(input, wrapXml(innerXml));
        Path output = tempDir.resolve("output.yaml");
        new OwaspDcMigrator().migrate(input, output);
        Map<String, Object> data = new Yaml().load(Files.readString(output));
        return (List<Map<String, Object>>) data.get("suppressions");
    }

    @Nested
    class ParseSuppress {

        @Test
        void testCpeCorrection() throws IOException {
            List<Map<String, Object>> entries = migrateXml("""
                    <suppress>
                        <notes><![CDATA[Test CPE correction]]></notes>
                        <packageUrl regex="true">^pkg:maven/io\\.grpc/grpc-api@.*$</packageUrl>
                        <cpe>cpe:/a:grpc:grpc</cpe>
                    </suppress>""");
            assertThat(entries).hasSize(1);
            assertThat(entries.get(0).get("type")).isEqualTo("cpe-correction");
            @SuppressWarnings("unchecked")
            Map<String, Object> suppress = (Map<String, Object>) entries.get(0).get("suppress");
            assertThat(suppress.get("cpes")).isEqualTo(List.of("cpe:/a:grpc:grpc"));
            assertThat(suppress).doesNotContainKey("cves");
        }

        @Test
        void testCveTriageWithUntil() throws IOException {
            List<Map<String, Object>> entries = migrateXml("""
                    <suppress until="2027-03-26">
                        <notes><![CDATA[Disputed by h2database]]></notes>
                        <packageUrl regex="true">^pkg:maven/com\\.h2database/h2@.*$</packageUrl>
                        <vulnerabilityName>CVE-2018-14335</vulnerabilityName>
                    </suppress>""");
            assertThat(entries.get(0).get("type")).isEqualTo("cve-triage");
            assertThat(entries.get(0).get("until")).isEqualTo("2027-03-26");
            @SuppressWarnings("unchecked")
            Map<String, Object> suppress = (Map<String, Object>) entries.get(0).get("suppress");
            assertThat(suppress.get("vulnerability-names")).isEqualTo(List.of("CVE-2018-14335"));
        }

        @Test
        void testCveWithCveElement() throws IOException {
            List<Map<String, Object>> entries = migrateXml("""
                    <suppress until="2026-03-11">
                        <notes><![CDATA[Test]]></notes>
                        <packageUrl regex="true">^pkg:maven/org\\.apache/test@.*$</packageUrl>
                        <cve>CVE-2010-1151</cve>
                    </suppress>""");
            @SuppressWarnings("unchecked")
            Map<String, Object> suppress = (Map<String, Object>) entries.get(0).get("suppress");
            assertThat(suppress.get("cves")).isEqualTo(List.of("CVE-2010-1151"));
        }

        @Test
        void testMultipleCves() throws IOException {
            List<Map<String, Object>> entries = migrateXml("""
                    <suppress until="2027-05-01">
                        <notes><![CDATA[Multiple CVEs]]></notes>
                        <packageUrl regex="true">^pkg:maven/org\\.example/lib@.*$</packageUrl>
                        <cve>CVE-2026-34478</cve>
                        <cve>CVE-2026-34480</cve>
                        <cve>CVE-2026-34481</cve>
                    </suppress>""");
            @SuppressWarnings("unchecked")
            Map<String, Object> suppress = (Map<String, Object>) entries.get(0).get("suppress");
            @SuppressWarnings("unchecked")
            List<String> cves = (List<String>) suppress.get("cves");
            assertThat(cves).hasSize(3);
            assertThat(cves).contains("CVE-2026-34478", "CVE-2026-34481");
        }

        @Test
        void testMixedCveAndVulnerabilityName() throws IOException {
            List<Map<String, Object>> entries = migrateXml("""
                    <suppress>
                        <notes><![CDATA[Mixed elements]]></notes>
                        <packageUrl regex="true">^pkg:maven/org\\.example/lib@.*$</packageUrl>
                        <cve>CVE-2024-00001</cve>
                        <vulnerabilityName>CVE-2024-00002</vulnerabilityName>
                    </suppress>""");
            @SuppressWarnings("unchecked")
            Map<String, Object> suppress = (Map<String, Object>) entries.get(0).get("suppress");
            assertThat(suppress.get("cves")).isEqualTo(List.of("CVE-2024-00001"));
            assertThat(suppress.get("vulnerability-names")).isEqualTo(List.of("CVE-2024-00002"));
        }

        @Test
        void testFilePathMatching() throws IOException {
            List<Map<String, Object>> entries = migrateXml("""
                    <suppress until="2027-05-20">
                        <notes><![CDATA[Shaded jar]]></notes>
                        <filePath regex="true">^.*/wildfly/bin/client/jboss-client\\.jar$</filePath>
                        <cve>CVE-2026-42582</cve>
                    </suppress>""");
            @SuppressWarnings("unchecked")
            Map<String, Object> match = (Map<String, Object>) entries.get(0).get("match");
            assertThat(match.get("file-path")).isEqualTo("^.*/wildfly/bin/client/jboss-client\\.jar$");
            assertThat(match).doesNotContainKey("package-url");
        }

        @Test
        void testNegativeLookaheadRegex() throws IOException {
            List<Map<String, Object>> entries = migrateXml("""
                    <suppress until="2027-05-20">
                        <notes><![CDATA[Negative lookahead]]></notes>
                        <packageUrl regex="true">^pkg:maven/io\\.netty/(?!netty-codec-http3).*@.*$</packageUrl>
                        <cve>CVE-2026-42582</cve>
                    </suppress>""");
            @SuppressWarnings("unchecked")
            Map<String, Object> match = (Map<String, Object>) entries.get(0).get("match");
            assertThat((String) match.get("package-url")).contains("(?!netty-codec-http3)");
        }

        @Test
        void testReferencesExtractedFromNotes() throws IOException {
            List<Map<String, Object>> entries = migrateXml("""
                    <suppress>
                        <notes><![CDATA[
                        Test note
                        https://github.com/example/issue/1
                        https://github.com/example/advisory/2
                        ]]></notes>
                        <packageUrl regex="true">^pkg:maven/org\\.example/lib@.*$</packageUrl>
                        <cve>CVE-2024-00001</cve>
                    </suppress>""");
            @SuppressWarnings("unchecked")
            List<String> refs = (List<String>) entries.get(0).get("references");
            assertThat(refs).hasSize(2);
            assertThat(refs).contains("https://github.com/example/issue/1");
        }

        @Test
        void testMultipleCpes() throws IOException {
            List<Map<String, Object>> entries = migrateXml("""
                    <suppress>
                        <notes><![CDATA[Multiple CPEs]]></notes>
                        <packageUrl regex="true">^pkg:maven/org\\.example/lib@.*$</packageUrl>
                        <cpe>cpe:/a:redhat:wildfly</cpe>
                        <cpe>cpe:/a:redhat:jboss_enterprise_application_platform</cpe>
                        <cpe>cpe:/a:netapp:active_iq_unified_manager</cpe>
                    </suppress>""");
            @SuppressWarnings("unchecked")
            Map<String, Object> suppress = (Map<String, Object>) entries.get(0).get("suppress");
            @SuppressWarnings("unchecked")
            List<String> cpes = (List<String>) suppress.get("cpes");
            assertThat(cpes).hasSize(3);
        }
    }

    @Nested
    class DeduplicateIds {

        @Test
        void testDuplicatesGetSuffix() throws IOException {
            List<Map<String, Object>> entries = migrateXml("""
                    <suppress>
                        <notes><![CDATA[First]]></notes>
                        <packageUrl regex="true">^pkg:maven/org\\.example/lib@.*$</packageUrl>
                        <cpe>cpe:/a:example:one</cpe>
                    </suppress>
                    <suppress>
                        <notes><![CDATA[Second]]></notes>
                        <packageUrl regex="true">^pkg:maven/org\\.example/lib@.*$</packageUrl>
                        <cpe>cpe:/a:example:two</cpe>
                    </suppress>""");
            Set<String> ids = new HashSet<>();
            for (Map<String, Object> e : entries) {
                ids.add((String) e.get("id"));
            }
            assertThat(ids).hasSize(entries.size());
        }
    }

    @Nested
    class FullMigration {

        @Test
        @SuppressWarnings("unchecked")
        void testMigrateRealFile() throws IOException {
            Path realXml = Path.of(System.getProperty("user.dir"))
                    .getParent().resolve("owasp-suppressions/owasp-suppressions.xml");
            assumeTrue(Files.exists(realXml), "Real owasp-suppressions.xml not found");

            Path output = tempDir.resolve("migrated.yaml");
            new OwaspDcMigrator().migrate(realXml, output);

            Map<String, Object> data = new Yaml().load(Files.readString(output));
            List<Map<String, Object>> suppressions = (List<Map<String, Object>>) data.get("suppressions");

            assertThat(suppressions).hasSize(59);

            long cpeCount = suppressions.stream()
                    .filter(s -> "cpe-correction".equals(s.get("type")))
                    .count();
            long cveCount = suppressions.stream()
                    .filter(s -> "cve-triage".equals(s.get("type")))
                    .count();
            assertThat(cpeCount).isEqualTo(31);
            assertThat(cveCount).isEqualTo(28);

            Set<String> ids = new HashSet<>();
            for (Map<String, Object> s : suppressions) {
                assertThat(ids.add((String) s.get("id")))
                        .as("Duplicate ID: " + s.get("id"))
                        .isTrue();
            }

            boolean hasNegativeLookahead = suppressions.stream()
                    .anyMatch(s -> {
                        Map<String, Object> match = (Map<String, Object>) s.get("match");
                        String purl = match != null ? (String) match.get("package-url") : null;
                        return purl != null && purl.contains("(?!");
                    });
            assertThat(hasNegativeLookahead).isTrue();
        }
    }
}
