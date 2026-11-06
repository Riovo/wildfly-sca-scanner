package org.wildfly.security.sca.suppressions.validator;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDate;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import org.yaml.snakeyaml.Yaml;

public final class SuppressionValidator {

    private static final Pattern CVE_PATTERN = Pattern.compile("^CVE-\\d{4}-\\d{4,}$");

    @SuppressWarnings("unchecked")
    public ValidationResult validate(Path inputPath) {
        List<String> errors = new ArrayList<>();
        List<String> warnings = new ArrayList<>();

        Object data;
        try (BufferedReader reader = Files.newBufferedReader(inputPath, StandardCharsets.UTF_8)) {
            data = new Yaml().load(reader);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }

        if (data == null) {
            errors.add("File is empty or not valid YAML");
            return new ValidationResult(errors, warnings);
        }
        if (!(data instanceof Map<?, ?> top)) {
            errors.add("Expected YAML mapping at top level, got " + data.getClass().getSimpleName());
            return new ValidationResult(errors, warnings);
        }

        if (!top.containsKey("version")) {
            errors.add("Missing 'version' field");
        }
        if (!top.containsKey("suppressions")) {
            errors.add("Missing 'suppressions' field");
            return new ValidationResult(errors, warnings);
        }
        if (!(top.get("suppressions") instanceof List<?> suppressions)) {
            errors.add("'suppressions' must be a list, got " + top.get("suppressions").getClass().getSimpleName());
            return new ValidationResult(errors, warnings);
        }

        Set<String> seenIds = new HashSet<>();
        String today = LocalDate.now().toString();

        for (int i = 0; i < suppressions.size(); i++) {
            String prefix = "suppression[" + i + "]";
            Object raw = suppressions.get(i);

            if (!(raw instanceof Map<?, ?> entry)) {
                errors.add(prefix + ": expected a mapping, got " + (raw == null ? "null" : raw.getClass().getSimpleName()));
                continue;
            }

            for (String field : List.of("id", "type", "notes")) {
                if (!entry.containsKey(field)) {
                    errors.add(prefix + ": missing required field '" + field + "'");
                }
            }

            String supId = entry.get("id") instanceof String s ? s : "<unnamed-" + i + ">";

            if (seenIds.contains(supId)) {
                errors.add(prefix + " (" + supId + "): duplicate ID");
            }
            seenIds.add(supId);

            String supType = entry.get("type") instanceof String s ? s : "";
            if (!supType.equals("cpe-correction") && !supType.equals("cve-triage")) {
                errors.add(prefix + " (" + supId + "): invalid type '" + supType + "' (expected 'cpe-correction' or 'cve-triage')");
            }

            Map<?, ?> match = entry.get("match") instanceof Map<?, ?> m ? m : Map.of();
            if (match.get("package-url") == null && match.get("file-path") == null) {
                errors.add(prefix + " (" + supId + "): must have at least one of 'package-url' or 'file-path' in match");
            }

            for (String key : List.of("package-url", "file-path")) {
                Object pattern = match.get(key);
                if (pattern != null) {
                    if (!(pattern instanceof String patStr)) {
                        errors.add(prefix + " (" + supId + "): match." + key + " must be a string, got " + pattern.getClass().getSimpleName());
                        continue;
                    }
                    try {
                        Pattern.compile(patStr);
                    } catch (PatternSyntaxException e) {
                        errors.add(prefix + " (" + supId + "): invalid regex in match." + key + ": " + e.getDescription());
                    }
                }
            }

            Map<?, ?> suppress = entry.get("suppress") instanceof Map<?, ?> m ? m : Map.of();
            boolean hasCves = suppress.get("cves") instanceof List<?> l && !l.isEmpty();
            boolean hasCpes = suppress.get("cpes") instanceof List<?> l && !l.isEmpty();
            boolean hasVulnNames = suppress.get("vulnerability-names") instanceof List<?> l && !l.isEmpty();
            if (!hasCves && !hasCpes && !hasVulnNames) {
                errors.add(prefix + " (" + supId + "): must suppress at least one CVE, vulnerability-name, or CPE");
            }

            List<String> allCveIds = new ArrayList<>();
            if (suppress.get("cves") instanceof List<?> cves) {
                for (Object c : cves) {
                    if (c instanceof String s) allCveIds.add(s);
                }
            }
            if (suppress.get("vulnerability-names") instanceof List<?> vns) {
                for (Object v : vns) {
                    if (v instanceof String s) allCveIds.add(s);
                }
            }
            for (String cve : allCveIds) {
                if (!CVE_PATTERN.matcher(cve).matches()) {
                    warnings.add(prefix + " (" + supId + "): CVE '" + cve + "' doesn't match expected format CVE-YYYY-NNNNN");
                }
            }

            Object until = entry.get("until");
            String untilStr = null;
            if (until != null) {
                if (until instanceof Date d) {
                    untilStr = d.toInstant().atZone(java.time.ZoneId.of("UTC")).toLocalDate().toString();
                } else if (until instanceof String s) {
                    untilStr = s;
                } else {
                    errors.add(prefix + " (" + supId + "): 'until' must be a date string (YYYY-MM-DD), got " + until.getClass().getSimpleName());
                }
            }
            if (untilStr != null) {
                if (untilStr.length() != 10 || untilStr.charAt(4) != '-' || untilStr.charAt(7) != '-') {
                    errors.add(prefix + " (" + supId + "): invalid 'until' date format: " + untilStr + " (expected YYYY-MM-DD)");
                    untilStr = null;
                }
            }
            if (untilStr != null) {
                try {
                    LocalDate.parse(untilStr);
                    if (untilStr.compareTo(today) < 0) {
                        warnings.add(prefix + " (" + supId + "): 'until' date " + untilStr + " has expired — re-evaluate this suppression");
                    }
                } catch (DateTimeParseException e) {
                    errors.add(prefix + " (" + supId + "): invalid 'until' date format: " + untilStr + " (expected YYYY-MM-DD)");
                }
            }

            if (supType.equals("cpe-correction") && until != null) {
                warnings.add(prefix + " (" + supId + "): CPE corrections typically don't need 'until' dates");
            }
        }

        return new ValidationResult(errors, warnings);
    }
}
