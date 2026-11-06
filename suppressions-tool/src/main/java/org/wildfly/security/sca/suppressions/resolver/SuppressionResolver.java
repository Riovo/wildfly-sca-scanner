package org.wildfly.security.sca.suppressions.resolver;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.wildfly.security.sca.suppressions.model.PurlUtils;
import org.wildfly.security.sca.suppressions.model.Suppression;
import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.Yaml;

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDate;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

public final class SuppressionResolver {

    public void resolve(Path canonicalYamlPath, Path trivyJsonPath, Path outputPath) {
        Map<String, Object> data = loadYaml(canonicalYamlPath);
        if (data == null || !data.containsKey("suppressions")) {
            throw new IllegalArgumentException(canonicalYamlPath + " is empty or missing 'suppressions' key");
        }

        JsonNode trivyJson = loadJson(trivyJsonPath);
        Set<String> discoveredPurls = extractPurls(trivyJson);

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> rawSuppressions = (List<Map<String, Object>>) data.get("suppressions");
        List<Suppression> suppressions = rawSuppressions.stream()
                .map(Suppression::fromDict)
                .toList();

        int resolvedCount = 0;
        int exactCount = 0;
        int skippedCpe = 0;
        int skippedFilepath = 0;
        int skippedNoMatch = 0;
        List<Map<String, Object>> trivyEntries = new ArrayList<>();

        for (Suppression s : suppressions) {
            List<String> allCveIds = s.getAllCveIds();

            if ("cpe-correction".equals(s.getType()) && allCveIds.isEmpty()) {
                skippedCpe++;
                continue;
            }

            if (allCveIds.isEmpty()) {
                System.err.println("  WARNING: Skipping " + s.getId() + " — no CVEs or vulnerability-names to suppress.");
                continue;
            }

            if (s.getPackageUrl() == null) {
                if (s.getFilePath() != null) {
                    skippedFilepath++;
                    System.err.println("  WARNING: Skipping " + s.getId() +
                            " — filePath-based match cannot be resolved to PURLs.");
                } else {
                    System.err.println("  WARNING: Skipping " + s.getId() +
                            " — no package-url or file-path match defined.");
                }
                continue;
            }

            Matcher m = PurlUtils.SIMPLE_PURL_RE.matcher(s.getPackageUrl());
            if (m.matches()) {
                String purl = PurlUtils.purlFromSimpleMatch(m);
                exactCount++;

                for (String cve : allCveIds) {
                    Map<String, Object> entry = new LinkedHashMap<>();
                    entry.put("id", cve);
                    entry.put("purls", List.of(purl));
                    if (s.getUntil() != null) {
                        entry.put("expired_at", toDate(PurlUtils.parseUntilDate(s.getUntil(), s.getId())));
                    }
                    String statement = buildStatement(null, s);
                    if (statement != null) {
                        entry.put("statement", statement);
                    }
                    trivyEntries.add(entry);
                }
                continue;
            }

            List<String> matchedPurls = resolvePattern(s.getPackageUrl(), discoveredPurls);
            if (matchedPurls.isEmpty()) {
                skippedNoMatch++;
                System.err.println("  INFO: Skipping " + s.getId() + " — pattern " +
                        s.getPackageUrl() + " matched no packages in this scan.");
                continue;
            }

            resolvedCount++;
            for (String cve : allCveIds) {
                Map<String, Object> entry = new LinkedHashMap<>();
                entry.put("id", cve);
                entry.put("purls", matchedPurls);
                if (s.getUntil() != null) {
                    entry.put("expired_at", toDate(PurlUtils.parseUntilDate(s.getUntil(), s.getId())));
                }
                entry.put("statement", buildStatement("Resolved from pattern: " + s.getPackageUrl(), s));
                trivyEntries.add(entry);
            }
        }

        Map<String, Object> trivyData = new LinkedHashMap<>();
        trivyData.put("vulnerabilities", trivyEntries);

        writeOutput(outputPath, trivyData);

        System.out.println("Resolved " + trivyEntries.size() + " CVE suppression entries");
        System.out.println("  " + exactCount + " exact-match entries (pass-through)");
        System.out.println("  " + resolvedCount + " wildcard/complex patterns resolved against " +
                discoveredPurls.size() + " discovered PURLs");
        if (skippedCpe > 0) {
            System.out.println("  " + skippedCpe + " CPE-only corrections skipped (not applicable to Trivy)");
        }
        if (skippedFilepath > 0) {
            System.out.println("  " + skippedFilepath + " filePath-only entries skipped");
        }
        if (skippedNoMatch > 0) {
            System.out.println("  " + skippedNoMatch + " patterns matched no packages in this scan");
        }
        System.out.println("Output: " + outputPath);
    }

    static String stripVersion(String purl) {
        int at = purl.indexOf('@');
        return at != -1 ? purl.substring(0, at) : purl;
    }

    static Set<String> extractPurls(JsonNode trivyJson) {
        Set<String> purls = new HashSet<>();
        JsonNode results = trivyJson.path("Results");
        if (results.isArray()) {
            for (JsonNode result : results) {
                JsonNode packages = result.path("Packages");
                if (packages.isArray()) {
                    for (JsonNode pkg : packages) {
                        String purl = pkg.path("Identifier").path("PURL").asText("");
                        if (!purl.isEmpty()) purls.add(purl);
                    }
                }
                JsonNode vulns = result.path("Vulnerabilities");
                if (vulns.isArray()) {
                    for (JsonNode vuln : vulns) {
                        String purl = vuln.path("PkgIdentifier").path("PURL").asText("");
                        if (!purl.isEmpty()) purls.add(purl);
                    }
                }
            }
        }
        return purls;
    }

    static List<String> resolvePattern(String pattern, Set<String> discoveredPurls) {
        Pattern compiled;
        try {
            compiled = Pattern.compile(pattern);
        } catch (PatternSyntaxException e) {
            return List.of();
        }

        Set<String> matched = new TreeSet<>();
        for (String purl : discoveredPurls) {
            if (compiled.matcher(purl).matches()) {
                matched.add(stripVersion(purl));
            }
        }
        return new ArrayList<>(matched);
    }

    private String buildStatement(String prefix, Suppression s) {
        List<String> parts = new ArrayList<>();
        if (prefix != null) parts.add(prefix);
        if (s.getNotes() != null && !s.getNotes().isEmpty()) {
            parts.add(s.getNotes().strip().split("\n")[0].strip());
        }
        if (s.getReferences() != null && !s.getReferences().isEmpty()) {
            parts.add(s.getReferences().get(0));
        }
        return parts.isEmpty() ? null : String.join(" | ", parts);
    }

    // Trivy's Go YAML parser rejects quoted date strings
    private static Date toDate(LocalDate ld) {
        return Date.from(ld.atStartOfDay(ZoneId.of("UTC")).toInstant());
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> loadYaml(Path path) {
        try (InputStream in = Files.newInputStream(path)) {
            return new Yaml().load(in);
        } catch (IOException e) {
            throw new IllegalArgumentException("Cannot read YAML: " + path, e);
        }
    }

    private JsonNode loadJson(Path path) {
        try {
            return new ObjectMapper().readTree(path.toFile());
        } catch (IOException e) {
            throw new IllegalArgumentException("Cannot read JSON: " + path, e);
        }
    }

    private void writeOutput(Path outputPath, Map<String, Object> data) {
        try {
            Files.createDirectories(outputPath.getParent());
            try (BufferedWriter w = Files.newBufferedWriter(outputPath, StandardCharsets.UTF_8)) {
                w.write("# Resolved .trivyignore.yaml — generated at scan time from canonical YAML + Trivy scan.\n");
                w.write("# All entries have exact PURLs; no global suppressions.\n\n");

                DumperOptions opts = new DumperOptions();
                opts.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
                opts.setWidth(120);
                new Yaml(opts).dump(data, w);
            }
        } catch (IOException e) {
            throw new IllegalArgumentException("Cannot write output: " + outputPath, e);
        }
    }
}
