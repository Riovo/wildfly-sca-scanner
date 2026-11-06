package org.wildfly.security.sca.suppressions.model;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.LocalDate;
import java.time.ZoneId;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class SuppressionTest {

    @Nested
    class ToDict {

        @Test
        void testMinimalCpeCorrection() {
            Suppression s = new Suppression("test-cpe", "cpe-correction", "Test note");
            s.setPackageUrl("^pkg:maven/com\\.example/lib@.*$");
            s.setCpes(List.of("cpe:/a:example:product"));

            Map<String, Object> d = s.toDict();
            assertThat(d.get("id")).isEqualTo("test-cpe");
            assertThat(d.get("type")).isEqualTo("cpe-correction");

            @SuppressWarnings("unchecked")
            Map<String, Object> match = (Map<String, Object>) d.get("match");
            assertThat(match.get("package-url")).isEqualTo("^pkg:maven/com\\.example/lib@.*$");

            @SuppressWarnings("unchecked")
            Map<String, Object> suppress = (Map<String, Object>) d.get("suppress");
            assertThat(suppress.get("cpes")).isEqualTo(List.of("cpe:/a:example:product"));
            assertThat(suppress).doesNotContainKey("cves");

            assertThat(d).doesNotContainKey("until");
            assertThat(d).doesNotContainKey("references");
        }

        @Test
        void testFullCveTriage() {
            Suppression s = new Suppression("test-cve", "cve-triage", "Disputed");
            s.setPackageUrl("^pkg:maven/com\\.h2database/h2@.*$");
            s.setCves(List.of("CVE-2018-14335"));
            s.setUntil("2027-03-26");
            s.setReferences(List.of("https://github.com/h2database/h2database/issues/1294"));

            Map<String, Object> d = s.toDict();
            assertThat(d.get("until")).isEqualTo("2027-03-26");
            assertThat(d.get("references")).isEqualTo(List.of("https://github.com/h2database/h2database/issues/1294"));

            @SuppressWarnings("unchecked")
            Map<String, Object> suppress = (Map<String, Object>) d.get("suppress");
            assertThat(suppress.get("cves")).isEqualTo(List.of("CVE-2018-14335"));
        }

        @Test
        void testFilePathMatch() {
            Suppression s = new Suppression("test-filepath", "cpe-correction", "Uber-JAR");
            s.setFilePath("^.*/wildfly/bin/client/jboss-client\\.jar$");
            s.setCpes(List.of("cpe:/a:redhat:wildfly"));

            Map<String, Object> d = s.toDict();
            @SuppressWarnings("unchecked")
            Map<String, Object> match = (Map<String, Object>) d.get("match");
            assertThat(match).doesNotContainKey("package-url");
            assertThat(match.get("file-path")).isEqualTo("^.*/wildfly/bin/client/jboss-client\\.jar$");
        }

        @Test
        void testBothMatchTypes() {
            Suppression s = new Suppression("test-both", "cve-triage", "Both match types");
            s.setPackageUrl("^pkg:maven/com\\.example/lib@.*$");
            s.setFilePath("^.*/lib\\.jar$");
            s.setCves(List.of("CVE-2024-00001"));

            Map<String, Object> d = s.toDict();
            @SuppressWarnings("unchecked")
            Map<String, Object> match = (Map<String, Object>) d.get("match");
            assertThat(match).containsKey("package-url");
            assertThat(match).containsKey("file-path");
        }

        @Test
        void testMultipleCvesAndCpes() {
            Suppression s = new Suppression("test-multi", "cve-triage", "Multiple");
            s.setPackageUrl("^pkg:maven/com\\.example/lib@.*$");
            s.setCves(List.of("CVE-2024-00001", "CVE-2024-00002", "CVE-2024-00003"));
            s.setCpes(List.of("cpe:/a:example:one", "cpe:/a:example:two"));

            Map<String, Object> d = s.toDict();
            @SuppressWarnings("unchecked")
            Map<String, Object> suppress = (Map<String, Object>) d.get("suppress");
            assertThat((List<?>) suppress.get("cves")).hasSize(3);
            assertThat((List<?>) suppress.get("cpes")).hasSize(2);
        }

        @Test
        void testEmptyListsOmitted() {
            Suppression s = new Suppression("test-empty", "cpe-correction", "No CVEs");
            s.setPackageUrl("^pkg:maven/com\\.example/lib@.*$");
            s.setCpes(List.of("cpe:/a:example:product"));

            Map<String, Object> d = s.toDict();
            @SuppressWarnings("unchecked")
            Map<String, Object> suppress = (Map<String, Object>) d.get("suppress");
            assertThat(suppress).doesNotContainKey("cves");
        }
    }

    @Nested
    class FromDict {

        @Test
        void testRoundTrip() {
            Suppression original = new Suppression("round-trip", "cve-triage", "Test round trip");
            original.setPackageUrl("^pkg:maven/io\\.netty/(?!netty-codec-http3).*@.*$");
            original.setCves(List.of("CVE-2026-42582"));
            original.setUntil("2027-05-20");
            original.setReferences(List.of("https://example.com/issue/66"));

            Map<String, Object> d = original.toDict();
            Suppression restored = Suppression.fromDict(d);

            assertThat(restored.getId()).isEqualTo(original.getId());
            assertThat(restored.getType()).isEqualTo(original.getType());
            assertThat(restored.getNotes()).isEqualTo(original.getNotes());
            assertThat(restored.getPackageUrl()).isEqualTo(original.getPackageUrl());
            assertThat(restored.getFilePath()).isEqualTo(original.getFilePath());
            assertThat(restored.getCves()).isEqualTo(original.getCves());
            assertThat(restored.getCpes()).isEqualTo(original.getCpes());
            assertThat(restored.getUntil()).isEqualTo(original.getUntil());
            assertThat(restored.getReferences()).isEqualTo(original.getReferences());
        }

        @Test
        void testMissingOptionalFields() {
            Map<String, Object> d = new HashMap<>();
            d.put("id", "minimal");
            d.put("type", "cpe-correction");
            d.put("notes", "Minimal entry");
            d.put("match", Map.of("package-url", "^pkg:maven/com\\.example/lib@.*$"));
            d.put("suppress", Map.of("cpes", List.of("cpe:/a:example:product")));

            Suppression s = Suppression.fromDict(d);
            assertThat(s.getUntil()).isNull();
            assertThat(s.getReferences()).isEmpty();
            assertThat(s.getCves()).isEmpty();
            assertThat(s.getFilePath()).isNull();
        }

        @Test
        void testNegativeLookaheadRegexPreserved() {
            String regex = "^pkg:maven/io\\.netty/(?!netty-codec-http3).*@.*$";
            Map<String, Object> d = new HashMap<>();
            d.put("id", "netty-lookahead");
            d.put("type", "cve-triage");
            d.put("notes", "Negative lookahead test");
            d.put("match", Map.of("package-url", regex));
            d.put("suppress", Map.of("cves", List.of("CVE-2026-42582")));

            Suppression s = Suppression.fromDict(d);
            assertThat(s.getPackageUrl()).isEqualTo(regex);

            Map<String, Object> d2 = s.toDict();
            @SuppressWarnings("unchecked")
            Map<String, Object> match = (Map<String, Object>) d2.get("match");
            assertThat(match.get("package-url")).isEqualTo(regex);
        }

        @Test
        void testNoneMatchAndSuppressHandled() {
            Map<String, Object> d = new HashMap<>();
            d.put("id", "null-blocks");
            d.put("type", "cve-triage");
            d.put("notes", "Test");
            d.put("match", null);
            d.put("suppress", null);

            Suppression s = Suppression.fromDict(d);
            assertThat(s.getPackageUrl()).isNull();
            assertThat(s.getFilePath()).isNull();
            assertThat(s.getCves()).isEmpty();
            assertThat(s.getCpes()).isEmpty();
        }

        @Test
        void testNullListValuesInSuppressHandled() {
            Map<String, Object> suppress = new HashMap<>();
            suppress.put("cves", null);
            suppress.put("cpes", null);
            suppress.put("vulnerability-names", null);

            Map<String, Object> d = new HashMap<>();
            d.put("id", "null-lists");
            d.put("type", "cve-triage");
            d.put("notes", "Test");
            d.put("match", Map.of("package-url", "^pkg:maven/com\\.example/lib@.*$"));
            d.put("suppress", suppress);
            d.put("references", null);

            Suppression s = Suppression.fromDict(d);
            assertThat(s.getCves()).isEmpty();
            assertThat(s.getCpes()).isEmpty();
            assertThat(s.getVulnerabilityNames()).isEmpty();
            assertThat(s.getReferences()).isEmpty();
        }

        @Test
        void testDateUntilCoercedToString() {
            LocalDate ld = LocalDate.of(2027, 3, 26);
            Date javaDate = Date.from(ld.atStartOfDay(ZoneId.of("UTC")).toInstant());

            Map<String, Object> d = new HashMap<>();
            d.put("id", "date-coerce");
            d.put("type", "cve-triage");
            d.put("notes", "Test");
            d.put("match", Map.of("package-url", "^pkg:maven/a/b@.*$"));
            d.put("suppress", Map.of("cves", List.of("CVE-2024-00001")));
            d.put("until", javaDate);

            Suppression s = Suppression.fromDict(d);
            assertThat(s.getUntil()).isEqualTo("2027-03-26");
            assertThat(s.getUntil()).isInstanceOf(String.class);
        }
    }
}
