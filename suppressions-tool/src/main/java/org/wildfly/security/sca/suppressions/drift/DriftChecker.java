package org.wildfly.security.sca.suppressions.drift;

import org.wildfly.security.sca.suppressions.converter.OwaspDcConverter;
import org.wildfly.security.sca.suppressions.migration.OwaspDcMigrator;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

public final class DriftChecker {

    public boolean checkDrift(Path originalXmlPath, Path canonicalYamlPath) {
        Path tmpDir = null;
        try {
            tmpDir = Files.createTempDirectory("drift-check");
            Path fromXmlPath = tmpDir.resolve("from-xml.yaml");
            Path fromYamlXmlPath = tmpDir.resolve("from-yaml.xml");
            Path fromYamlRtPath = tmpDir.resolve("from-yaml-rt.yaml");

            OwaspDcMigrator migrator = new OwaspDcMigrator();
            OwaspDcConverter converter = new OwaspDcConverter();

            migrator.migrate(originalXmlPath, fromXmlPath);
            converter.convert(canonicalYamlPath, fromYamlXmlPath);
            migrator.migrate(fromYamlXmlPath, fromYamlRtPath);

            List<List<String>> fromXml = extractSignatures(fromXmlPath);
            List<List<String>> fromYaml = extractSignatures(fromYamlRtPath);

            if (!fromXml.equals(fromYaml)) {
                System.err.println("ERROR: owasp-suppressions.xml has drifted from suppressions.yaml " +
                        "— edit the canonical YAML and regenerate");
                return true;
            }
            return false;
        } catch (IOException e) {
            throw new IllegalArgumentException("Drift check failed: " + e.getMessage(), e);
        } finally {
            if (tmpDir != null) {
                cleanUp(tmpDir);
            }
        }
    }

    @SuppressWarnings("unchecked")
    List<List<String>> extractSignatures(Path yamlPath) {
        Map<String, Object> data;
        try (InputStream in = Files.newInputStream(yamlPath)) {
            data = new Yaml(new SafeConstructor(new LoaderOptions())).load(in);
        } catch (IOException e) {
            throw new IllegalArgumentException("Cannot read YAML: " + yamlPath, e);
        }

        if (data == null || !data.containsKey("suppressions")) {
            throw new IllegalArgumentException("YAML is empty or has no 'suppressions' key: " + yamlPath);
        }
        List<Map<String, Object>> entries = (List<Map<String, Object>>) data.get("suppressions");
        if (entries == null) {
            throw new IllegalArgumentException("'suppressions' value is null: " + yamlPath);
        }
        List<List<String>> signatures = new ArrayList<>();

        for (Map<String, Object> s : entries) {
            Map<String, Object> suppress = s.get("suppress") instanceof Map<?, ?> m
                    ? (Map<String, Object>) m : Collections.emptyMap();
            Map<String, Object> match = s.get("match") instanceof Map<?, ?> m
                    ? (Map<String, Object>) m : Collections.emptyMap();

            List<String> sig = new ArrayList<>();
            sig.add(stringOr(s.get("id")));
            sig.add(stringOr(s.get("type")));
            sig.add(sortedListStr(suppress.get("cves")));
            sig.add(sortedListStr(suppress.get("vulnerability-names")));
            sig.add(sortedListStr(suppress.get("cpes")));
            sig.add(stringOr(s.get("until")));
            sig.add(stringOr(match.get("package-url")));
            sig.add(stringOr(match.get("file-path")));

            signatures.add(sig);
        }

        signatures.sort((a, b) -> {
            for (int i = 0; i < a.size(); i++) {
                int cmp = a.get(i).compareTo(b.get(i));
                if (cmp != 0) return cmp;
            }
            return 0;
        });

        return signatures;
    }

    @SuppressWarnings("unchecked")
    private String sortedListStr(Object value) {
        if (value instanceof List<?> list) {
            List<String> sorted = new ArrayList<>((List<String>) list);
            Collections.sort(sorted);
            return sorted.toString();
        }
        return "[]";
    }

    private String stringOr(Object value) {
        if (value instanceof java.util.Date d) {
            return d.toInstant().atZone(java.time.ZoneId.of("UTC")).toLocalDate().toString();
        }
        return value != null ? value.toString() : "";
    }

    private void cleanUp(Path dir) {
        try (Stream<Path> walk = Files.walk(dir)) {
            walk.sorted(Comparator.reverseOrder())
                    .forEach(p -> {
                        try { Files.deleteIfExists(p); } catch (IOException ignored) {}
                    });
        } catch (IOException ignored) {}
    }
}
