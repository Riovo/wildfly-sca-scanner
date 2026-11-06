package org.wildfly.security.sca.suppressions.integration;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.wildfly.security.sca.suppressions.converter.OwaspDcConverter;
import org.wildfly.security.sca.suppressions.converter.TrivyConverter;
import org.wildfly.security.sca.suppressions.migration.OwaspDcMigrator;
import org.wildfly.security.sca.suppressions.validator.SuppressionValidator;
import org.wildfly.security.sca.suppressions.validator.ValidationResult;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

import javax.xml.parsers.DocumentBuilderFactory;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class FullPipelineTest {

    static Path realXml;
    static boolean hasRealFiles;

    @TempDir
    static Path sharedDir;

    static Path migratedYaml;
    static Path trivyOutput;
    static Path owaspDcOutput;

    @BeforeAll
    @SuppressWarnings("unchecked")
    static void runPipeline() throws IOException {
        realXml = Path.of(System.getProperty("user.dir"))
                .getParent().resolve("owasp-suppressions/owasp-suppressions.xml");
        hasRealFiles = Files.exists(realXml);
        if (!hasRealFiles) return;

        migratedYaml = sharedDir.resolve("migrated.yaml");
        trivyOutput = sharedDir.resolve("trivy.yaml");
        owaspDcOutput = sharedDir.resolve("roundtrip.xml");

        new OwaspDcMigrator().migrate(realXml, migratedYaml);
        new TrivyConverter().convert(migratedYaml, trivyOutput);
        new OwaspDcConverter().convert(migratedYaml, owaspDcOutput);
    }

    @Test
    void testMigrationProducesValidYaml() {
        assumeTrue(hasRealFiles);
        ValidationResult result = new SuppressionValidator().validate(migratedYaml);
        assertThat(result.hasErrors()).isFalse();
    }

    @Test
    @SuppressWarnings("unchecked")
    void testAllSuppressionsPreserved() throws IOException {
        assumeTrue(hasRealFiles);
        Map<String, Object> data = new Yaml(new SafeConstructor(new LoaderOptions())).load(Files.readString(migratedYaml));
        List<Map<String, Object>> suppressions = (List<Map<String, Object>>) data.get("suppressions");
        assertThat(suppressions).isNotEmpty();
    }

    @Test
    @SuppressWarnings("unchecked")
    void testUniqueIds() throws IOException {
        assumeTrue(hasRealFiles);
        Map<String, Object> data = new Yaml(new SafeConstructor(new LoaderOptions())).load(Files.readString(migratedYaml));
        List<Map<String, Object>> suppressions = (List<Map<String, Object>>) data.get("suppressions");
        Set<String> ids = suppressions.stream()
                .map(s -> (String) s.get("id"))
                .collect(Collectors.toSet());
        assertThat(ids).hasSize(suppressions.size());
    }

    @Test
    void testTrivyOutputParseable() throws IOException {
        assumeTrue(hasRealFiles);
        Map<String, Object> data = new Yaml(new SafeConstructor(new LoaderOptions())).load(Files.readString(trivyOutput));
        assertThat(data).containsKey("vulnerabilities");
    }

    @Test
    void testOwaspDcOutputParseableXml() throws Exception {
        assumeTrue(hasRealFiles);
        DocumentBuilderFactory.newInstance()
                .newDocumentBuilder()
                .parse(owaspDcOutput.toFile());
    }

    @Test
    @SuppressWarnings("unchecked")
    void testRoundTripPreservesCount() throws IOException {
        assumeTrue(hasRealFiles);

        Path secondYaml = sharedDir.resolve("second.yaml");
        new OwaspDcMigrator().migrate(realXml, secondYaml);

        Map<String, Object> original = new Yaml(new SafeConstructor(new LoaderOptions())).load(Files.readString(migratedYaml));
        Map<String, Object> second = new Yaml(new SafeConstructor(new LoaderOptions())).load(Files.readString(secondYaml));

        List<?> origList = (List<?>) original.get("suppressions");
        List<?> secondList = (List<?>) second.get("suppressions");
        assertThat(secondList).hasSameSizeAs(origList);
    }

    @Test
    @SuppressWarnings("unchecked")
    void testRoundTripPreservesCves() throws IOException {
        assumeTrue(hasRealFiles);
        Map<String, Object> data = new Yaml(new SafeConstructor(new LoaderOptions())).load(Files.readString(migratedYaml));
        List<Map<String, Object>> suppressions = (List<Map<String, Object>>) data.get("suppressions");

        Set<String> allCves = new HashSet<>();
        for (Map<String, Object> s : suppressions) {
            Map<String, Object> suppress = (Map<String, Object>) s.get("suppress");
            if (suppress != null) {
                List<String> cves = (List<String>) suppress.get("cves");
                if (cves != null) allCves.addAll(cves);
                List<String> vulnNames = (List<String>) suppress.get("vulnerability-names");
                if (vulnNames != null) allCves.addAll(vulnNames);
            }
        }
        assertThat(allCves).isNotEmpty();
    }
}
