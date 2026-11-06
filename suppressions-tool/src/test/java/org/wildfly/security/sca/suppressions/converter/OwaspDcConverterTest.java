package org.wildfly.security.sca.suppressions.converter;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.xml.parsers.DocumentBuilderFactory;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class OwaspDcConverterTest {

    @TempDir
    Path tempDir;

    private Path writeYaml(String content) throws IOException {
        Path file = tempDir.resolve("input.yaml");
        Files.writeString(file, content);
        return file;
    }

    private String convertAndRead(String yaml) throws IOException {
        Path input = writeYaml(yaml);
        Path output = tempDir.resolve("output.xml");
        new OwaspDcConverter().convert(input, output);
        return Files.readString(output);
    }

    @Test
    void testCdataWrapping() throws IOException {
        String xml = convertAndRead("""
                suppressions:
                  - id: cdata
                    type: cpe-correction
                    notes: "Test CDATA note"
                    match:
                      package-url: "^pkg:maven/a/b@.*$"
                    suppress:
                      cpes:
                        - "cpe:/a:example:product"
                """);
        assertThat(xml).contains("<![CDATA[");
        assertThat(xml).contains("Test CDATA note");
    }

    @Test
    void testVulnerabilityNamePreserved() throws IOException {
        String xml = convertAndRead("""
                suppressions:
                  - id: vulnname
                    type: cve-triage
                    notes: Test
                    match:
                      package-url: "^pkg:maven/a/b@.*$"
                    suppress:
                      vulnerability-names:
                        - CVE-2024-00001
                """);
        assertThat(xml).contains("<vulnerabilityName>CVE-2024-00001</vulnerabilityName>");
    }

    @Test
    void testUntilAttribute() throws IOException {
        String xml = convertAndRead("""
                suppressions:
                  - id: until
                    type: cve-triage
                    notes: Test
                    until: "2027-03-26"
                    match:
                      package-url: "^pkg:maven/a/b@.*$"
                    suppress:
                      cves:
                        - CVE-2024-00001
                """);
        assertThat(xml).contains("until=\"2027-03-26\"");
    }

    @Test
    void testCdataInjectionEscaped() throws IOException {
        String xml = convertAndRead("""
                suppressions:
                  - id: cdata-inject
                    type: cpe-correction
                    notes: "Injection test ]]> end"
                    match:
                      package-url: "^pkg:maven/a/b@.*$"
                    suppress:
                      cpes:
                        - "cpe:/a:example:product"
                """);
        assertThat(xml).doesNotContain("Injection test ]]> end");
        assertThat(xml).contains("]]]]><![CDATA[>");
    }

    @Test
    void testBothMatchFieldsPreserved() throws IOException {
        String xml = convertAndRead("""
                suppressions:
                  - id: both
                    type: cve-triage
                    notes: Test
                    match:
                      package-url: "^pkg:maven/a/b@.*$"
                      file-path: '^.*/lib\\.jar$'
                    suppress:
                      cves:
                        - CVE-2024-00001
                """);
        assertThat(xml).contains("<packageUrl regex=\"true\">");
        assertThat(xml).contains("<filePath regex=\"true\">");
    }

    @Test
    void testNullNotesHandled() throws IOException {
        String xml = convertAndRead("""
                suppressions:
                  - id: null-notes
                    type: cpe-correction
                    notes: ""
                    match:
                      package-url: "^pkg:maven/a/b@.*$"
                    suppress:
                      cpes:
                        - "cpe:/a:example:product"
                """);
        assertThat(xml).contains("<notes>");
    }

    @Test
    void testInvalidInputRaisesError() throws IOException {
        Path input = writeYaml("invalid: true");
        Path output = tempDir.resolve("output.xml");
        assertThatThrownBy(() -> new OwaspDcConverter().convert(input, output))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void testValidXmlOutput() throws Exception {
        Path realFile = Path.of(System.getProperty("user.dir"))
                .getParent().resolve("suppressions/suppressions.yaml");
        assumeTrue(Files.exists(realFile), "Real suppressions.yaml not found");

        Path output = tempDir.resolve("output.xml");
        new OwaspDcConverter().convert(realFile, output);

        DocumentBuilderFactory.newInstance()
                .newDocumentBuilder()
                .parse(output.toFile());
    }
}
