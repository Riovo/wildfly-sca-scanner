package org.wildfly.security.sca.suppressions.drift;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.wildfly.security.sca.suppressions.migration.OwaspDcMigrator;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class DriftCheckerTest {

    @TempDir
    Path tempDir;

    @Test
    void testNoDrift() throws IOException {
        Path realXml = Path.of(System.getProperty("user.dir"))
                .getParent().resolve("owasp-suppressions/owasp-suppressions.xml");
        assumeTrue(Files.exists(realXml), "Real owasp-suppressions.xml not found");

        Path migrated = tempDir.resolve("migrated.yaml");
        new OwaspDcMigrator().migrate(realXml, migrated);

        boolean drifted = new DriftChecker().checkDrift(realXml, migrated);
        assertThat(drifted).isFalse();
    }

    @Test
    void testDriftDetected() throws IOException {
        Path realXml = Path.of(System.getProperty("user.dir"))
                .getParent().resolve("owasp-suppressions/owasp-suppressions.xml");
        assumeTrue(Files.exists(realXml), "Real owasp-suppressions.xml not found");

        Path migrated = tempDir.resolve("migrated.yaml");
        new OwaspDcMigrator().migrate(realXml, migrated);

        String content = Files.readString(migrated);
        content += "- id: extra-entry\n"
                + "  type: cve-triage\n"
                + "  notes: Extra\n"
                + "  match:\n"
                + "    package-url: '^pkg:maven/a/b@.*$'\n"
                + "  suppress:\n"
                + "    cves:\n"
                + "    - CVE-9999-00001\n";
        Path modified = tempDir.resolve("modified.yaml");
        Files.writeString(modified, content);

        boolean drifted = new DriftChecker().checkDrift(realXml, modified);
        assertThat(drifted).isTrue();
    }
}
