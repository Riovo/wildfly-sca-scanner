package org.wildfly.security.sca.suppressions.converter;

import org.wildfly.security.sca.suppressions.model.PurlUtils;
import org.wildfly.security.sca.suppressions.model.Suppression;
import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.nodes.Node;
import org.yaml.snakeyaml.nodes.Tag;
import org.yaml.snakeyaml.representer.Represent;
import org.yaml.snakeyaml.representer.Representer;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDate;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TimeZone;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class TrivyConverter {

    private static final Pattern GROUP_RE = Pattern.compile(
            "^\\^?pkg:maven/([a-zA-Z0-9_.\\\\-]+)/"
    );

    public void convert(Path inputPath, Path outputPath) {
        Map<String, Object> data = loadYaml(inputPath);
        List<Suppression> suppressions = loadSuppressions(data);

        int skippedCpe = 0;
        int skippedFilepath = 0;
        int skippedComplex = 0;
        int globalSuppress = 0;
        List<Map<String, Object>> entries = new ArrayList<>();

        for (Suppression s : suppressions) {
            List<String> allCveIds = s.getAllCveIds();

            if (s.getType().equals("cpe-correction") && allCveIds.isEmpty()) {
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
                            " — filePath-based match has no packageUrl equivalent. CVEs " + allCveIds +
                            " would be globally suppressed without a PURL filter, which is unsafe.");
                } else {
                    System.err.println("  WARNING: Skipping " + s.getId() +
                            " — no packageUrl or filePath match. CVEs " + allCveIds +
                            " would be globally suppressed, which is unsafe.");
                }
                continue;
            }

            RegexResult result = regexToPurl(s.getPackageUrl());
            if (result.purl == null) {
                skippedComplex++;
                System.err.println("  WARNING: Skipping " + s.getId() +
                        " — complex regex pattern cannot be converted to PURL: " + s.getPackageUrl());
                continue;
            }

            for (String cve : allCveIds) {
                Map<String, Object> entry = new LinkedHashMap<>();
                entry.put("id", cve);

                if (result.isExact) {
                    entry.put("purls", List.of(result.purl));
                } else {
                    globalSuppress++;
                    entry.put("statement", "Triaged globally (original pattern: " + s.getPackageUrl() + ")");
                }

                if (s.getUntil() != null) {
                    LocalDate ld = PurlUtils.parseUntilDate(s.getUntil(), s.getId());
                    // SnakeYAML serializes java.util.Date as unquoted YAML dates;
                    // Trivy's Go YAML parser rejects quoted date strings.
                    entry.put("expired_at", Date.from(ld.atStartOfDay(ZoneId.of("UTC")).toInstant()));
                }

                if (!entry.containsKey("statement")) {
                    List<String> parts = new ArrayList<>();
                    if (s.getNotes() != null && !s.getNotes().isBlank()) {
                        parts.add(s.getNotes().strip().split("\n")[0].strip());
                    }
                    if (s.getReferences() != null && !s.getReferences().isEmpty()) {
                        parts.add(s.getReferences().get(0));
                    }
                    if (!parts.isEmpty()) {
                        entry.put("statement", String.join(" | ", parts));
                    }
                }

                entries.add(entry);
            }
        }

        Map<String, Object> trivyData = new LinkedHashMap<>();
        trivyData.put("vulnerabilities", entries);

        writeOutput(outputPath, trivyData);

        System.out.println("Converted " + entries.size() + " CVE suppressions to Trivy format");
        if (globalSuppress > 0) {
            System.out.println("  " + globalSuppress + " entries are global (wildcard pattern, no PURL filter)");
        }
        System.out.println("Skipped " + skippedCpe + " CPE-only corrections (not applicable to Trivy)");
        if (skippedFilepath > 0) {
            System.out.println("Skipped " + skippedFilepath + " filePath-only suppressions (no safe Trivy equivalent)");
        }
        if (skippedComplex > 0) {
            System.out.println("Skipped " + skippedComplex + " complex regex patterns (cannot convert to PURL)");
        }
        System.out.println("Output: " + outputPath);
    }

    static RegexResult regexToPurl(String pattern) {
        Matcher m = PurlUtils.SIMPLE_PURL_RE.matcher(pattern);
        if (m.matches()) {
            return new RegexResult(PurlUtils.purlFromSimpleMatch(m), true);
        }

        Matcher groupMatch = GROUP_RE.matcher(pattern);
        if (groupMatch.find()) {
            String group = groupMatch.group(1).replace("\\.", ".").replace("\\-", "-");
            if (pattern.contains("(?") || pattern.contains("[")) {
                return new RegexResult(null, false);
            }
            return new RegexResult("pkg:maven/" + group, false);
        }

        return new RegexResult(null, false);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> loadYaml(Path path) {
        try (BufferedReader reader = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
            Map<String, Object> data = new Yaml().load(reader);
            if (data == null || !data.containsKey("suppressions")) {
                throw new IllegalArgumentException(path + " is empty or missing 'suppressions' key");
            }
            return data;
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    @SuppressWarnings("unchecked")
    private static List<Suppression> loadSuppressions(Map<String, Object> data) {
        List<Map<String, Object>> raw = (List<Map<String, Object>>) data.get("suppressions");
        return raw.stream().map(Suppression::fromDict).toList();
    }

    private static void writeOutput(Path path, Map<String, Object> data) {
        try {
            Files.createDirectories(path.getParent());
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }

        DumperOptions opts = new DumperOptions();
        opts.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
        opts.setWidth(120);

        try (BufferedWriter writer = Files.newBufferedWriter(path, StandardCharsets.UTF_8)) {
            writer.write("# WARNING: Some entries lack purls (global CVE suppressions from wildcard patterns).\n");
            writer.write("# The scan workflow generates a resolved version with exact PURLs — do not use this file directly.\n\n");
            new Yaml(new DateOnlyRepresenter(opts), opts).dump(data, writer);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public static final class DateOnlyRepresenter extends Representer {
        public DateOnlyRepresenter(DumperOptions options) {
            super(options);
            this.representers.put(Date.class, new RepresentDateOnly());
        }

        private class RepresentDateOnly implements Represent {
            @Override
            public Node representData(Object data) {
                Calendar cal = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
                cal.setTime((Date) data);
                String formatted = String.format("%04d-%02d-%02d",
                        cal.get(Calendar.YEAR),
                        cal.get(Calendar.MONTH) + 1,
                        cal.get(Calendar.DAY_OF_MONTH));
                return representScalar(Tag.TIMESTAMP, formatted);
            }
        }
    }

    record RegexResult(String purl, boolean isExact) {}
}
