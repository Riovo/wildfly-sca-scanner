package org.wildfly.security.sca.suppressions.validator;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class SuppressionValidatorTest {

    @TempDir
    Path tempDir;

    private Path writeYaml(String content) throws IOException {
        Path file = tempDir.resolve("test.yaml");
        Files.writeString(file, content);
        return file;
    }

    @Test
    void testEmptyFile() throws IOException {
        Path file = writeYaml("");
        ValidationResult result = new SuppressionValidator().validate(file);
        assertThat(result.hasErrors()).isTrue();
    }

    @Test
    void testInvalidRegex() throws IOException {
        Path file = writeYaml("""
                suppressions:
                  - id: bad-regex
                    type: cpe-correction
                    notes: Test
                    match:
                      package-url: "[invalid"
                    suppress:
                      cpes:
                        - "cpe:/a:example:product"
                """);
        ValidationResult result = new SuppressionValidator().validate(file);
        assertThat(result.hasErrors()).isTrue();
        assertThat(result.errors()).anyMatch(e -> e.contains("regex"));
    }

    @Test
    void testDuplicateIds() throws IOException {
        Path file = writeYaml("""
                suppressions:
                  - id: dup
                    type: cpe-correction
                    notes: First
                    match:
                      package-url: "^pkg:maven/a/b@.*$"
                    suppress:
                      cpes:
                        - "cpe:/a:example:one"
                  - id: dup
                    type: cpe-correction
                    notes: Second
                    match:
                      package-url: "^pkg:maven/a/c@.*$"
                    suppress:
                      cpes:
                        - "cpe:/a:example:two"
                """);
        ValidationResult result = new SuppressionValidator().validate(file);
        assertThat(result.hasErrors()).isTrue();
        assertThat(result.errors()).anyMatch(e -> e.toLowerCase().contains("duplicate"));
    }

    @Test
    void testExpiredUntil() throws IOException {
        Path file = writeYaml("""
                version: '1.0'
                suppressions:
                  - id: expired
                    type: cve-triage
                    notes: Test
                    until: "2020-01-01"
                    match:
                      package-url: "^pkg:maven/a/b@.*$"
                    suppress:
                      cves:
                        - CVE-2024-00001
                """);
        ValidationResult result = new SuppressionValidator().validate(file);
        assertThat(result.hasErrors()).isFalse();
        assertThat(result.warnings()).anyMatch(w -> w.contains("expired"));
    }

    @Test
    void testNonStringRegex() throws IOException {
        Path file = writeYaml("""
                suppressions:
                  - id: int-regex
                    type: cpe-correction
                    notes: Test
                    match:
                      package-url: 12345
                    suppress:
                      cpes:
                        - "cpe:/a:example:product"
                """);
        ValidationResult result = new SuppressionValidator().validate(file);
        assertThat(result.hasErrors()).isTrue();
    }

    @Test
    void testNonStringUntil() throws IOException {
        Path file = writeYaml("""
                suppressions:
                  - id: int-until
                    type: cve-triage
                    notes: Test
                    until: 12345
                    match:
                      package-url: "^pkg:maven/a/b@.*$"
                    suppress:
                      cves:
                        - CVE-2024-00001
                """);
        ValidationResult result = new SuppressionValidator().validate(file);
        assertThat(result.hasErrors()).isTrue();
    }

    @Test
    void testDateUntilAccepted() throws IOException {
        // SnakeYAML parses unquoted 2027-03-26 as java.util.Date
        Path file = writeYaml("""
                suppressions:
                  - id: date-until
                    type: cve-triage
                    notes: Test
                    until: 2027-03-26
                    match:
                      package-url: "^pkg:maven/a/b@.*$"
                    suppress:
                      cves:
                        - CVE-2024-00001
                """);
        ValidationResult result = new SuppressionValidator().validate(file);
        assertThat(result.errors().stream().filter(e -> e.contains("until")).toList()).isEmpty();
    }

    @Test
    void testNonDictEntry() throws IOException {
        Path file = writeYaml("""
                suppressions:
                  - "not a dict"
                """);
        ValidationResult result = new SuppressionValidator().validate(file);
        assertThat(result.hasErrors()).isTrue();
        assertThat(result.errors()).anyMatch(e -> e.contains("mapping"));
    }

    @Test
    void testNullMatchAndSuppress() throws IOException {
        Path file = writeYaml("""
                suppressions:
                  - id: null-blocks
                    type: cve-triage
                    notes: Test
                    match:
                    suppress:
                """);
        ValidationResult result = new SuppressionValidator().validate(file);
        assertThat(result.hasErrors()).isTrue();
    }

    @Test
    void testNonListSuppressions() throws IOException {
        Path file = writeYaml("""
                suppressions: "not a list"
                """);
        ValidationResult result = new SuppressionValidator().validate(file);
        assertThat(result.hasErrors()).isTrue();
    }

    @Test
    void testValidRealFile() {
        Path realFile = Path.of(System.getProperty("user.dir"))
                .getParent().resolve("suppressions/suppressions.yaml");
        assumeTrue(Files.exists(realFile), "Real suppressions.yaml not found");

        ValidationResult result = new SuppressionValidator().validate(realFile);
        assertThat(result.hasErrors()).isFalse();
    }
}
