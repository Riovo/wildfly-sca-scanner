package org.wildfly.security.sca.suppressions.migration;

import org.wildfly.security.sca.suppressions.model.Suppression;
import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.Yaml;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

public final class OwaspDcMigrator {

    private static final String NS = "https://jeremylong.github.io/DependencyCheck/dependency-suppression.1.3.xsd";

    public void migrate(Path inputPath, Path outputPath) {
        Document doc = parseXml(inputPath);
        NodeList elements = doc.getElementsByTagNameNS(NS, "suppress");

        List<Suppression> suppressions = new ArrayList<>();
        for (int i = 0; i < elements.getLength(); i++) {
            suppressions.add(parseSuppressElement((Element) elements.item(i)));
        }

        deduplicateIds(suppressions);

        List<Suppression> cpeCorrections = suppressions.stream()
                .filter(s -> "cpe-correction".equals(s.getType())).toList();
        List<Suppression> cveTriages = suppressions.stream()
                .filter(s -> "cve-triage".equals(s.getType())).toList();

        String today = LocalDate.now().toString();
        List<Suppression> expired = cveTriages.stream()
                .filter(s -> s.getUntil() != null && s.getUntil().compareTo(today) < 0).toList();
        if (!expired.isEmpty()) {
            System.out.println("\nWARNING: " + expired.size() + " suppression(s) have expired 'until' dates:");
            for (Suppression s : expired) {
                System.out.println("  - " + s.getId() + ": until=" + s.getUntil() +
                        " (" + String.join(", ", s.getAllVulnerabilityIds()) + ")");
            }
            System.out.println();
        }

        List<Suppression> ordered = new ArrayList<>(cpeCorrections);
        ordered.addAll(cveTriages);

        Map<String, Object> data = new LinkedHashMap<>();
        data.put("version", "1.0");
        data.put("suppressions", ordered.stream().map(Suppression::toDict).toList());

        writeOutput(outputPath, data);

        System.out.println("Migrated " + suppressions.size() + " suppressions:");
        System.out.println("  - " + cpeCorrections.size() + " CPE corrections (permanent)");
        System.out.println("  - " + cveTriages.size() + " CVE triages");
        System.out.println("Output: " + outputPath);
    }

    static Suppression parseSuppressElement(Element elem) {
        String until = elem.getAttribute("until");
        if (until.isEmpty()) until = null;

        String notes = textContent(elem, "notes");
        String packageUrl = textContent(elem, "packageUrl");
        String filePath = textContent(elem, "filePath");

        List<String> cves = allTextContents(elem, "cve");
        List<String> vulnerabilityNames = allTextContents(elem, "vulnerabilityName");
        List<String> cpes = allTextContents(elem, "cpe");

        String type = (!cves.isEmpty() || !vulnerabilityNames.isEmpty()) ? "cve-triage" : "cpe-correction";

        Suppression s = new Suppression("", type, notes != null ? notes : "");
        s.setPackageUrl(packageUrl);
        s.setFilePath(filePath);
        s.setCves(cves);
        s.setCpes(cpes);
        s.setUntil(until);
        s.setVulnerabilityNames(vulnerabilityNames);

        List<String> references = new ArrayList<>();
        if (notes != null) {
            for (String line : notes.split("\n")) {
                line = line.strip();
                if (line.startsWith("http://") || line.startsWith("https://")) {
                    references.add(line);
                }
            }
        }
        s.setReferences(references);
        s.setId(extractId(s));

        return s;
    }

    static String extractId(Suppression s) {
        String artifact;
        if (s.getPackageUrl() != null) {
            Matcher m = Pattern.compile("pkg:maven/([^@]+)@").matcher(s.getPackageUrl());
            if (m.find()) {
                artifact = m.group(1).replace("/", "-").replace("\\.", ".").replace("\\-", "-");
                artifact = artifact.replaceAll("[\\\\().*+?^$\\[\\]{}|]", "");
            } else {
                artifact = slugify(s.getPackageUrl().substring(0, Math.min(40, s.getPackageUrl().length())));
            }
        } else if (s.getFilePath() != null) {
            Matcher m = Pattern.compile("([a-zA-Z0-9_-]+)\\.jar").matcher(s.getFilePath());
            artifact = m.find() ? m.group(1) : slugify(s.getFilePath().substring(0, Math.min(40, s.getFilePath().length())));
        } else {
            artifact = "unknown";
        }

        List<String> allCveIds = s.getAllVulnerabilityIds();
        if (!s.getCpes().isEmpty() && allCveIds.isEmpty()) {
            String cpePart = s.getCpes().get(0);
            String[] parts = cpePart.split(":");
            cpePart = parts[parts.length - 1];
            return slugify("cpe-" + artifact + "-" + cpePart);
        } else if (!allCveIds.isEmpty()) {
            return slugify(artifact + "-" + allCveIds.get(0).toLowerCase());
        } else {
            return slugify("suppress-" + artifact);
        }
    }

    static void deduplicateIds(List<Suppression> suppressions) {
        Map<String, Integer> seen = new HashMap<>();
        Set<String> allIds = new HashSet<>();
        for (Suppression s : suppressions) {
            allIds.add(s.getId());
        }

        for (Suppression s : suppressions) {
            if (seen.containsKey(s.getId())) {
                int counter = seen.get(s.getId()) + 1;
                seen.put(s.getId(), counter);
                String newId = s.getId() + "-" + counter;
                while (allIds.contains(newId)) {
                    counter++;
                    seen.put(s.getId(), counter);
                    newId = s.getId() + "-" + counter;
                }
                s.setId(newId);
                allIds.add(newId);
            } else {
                seen.put(s.getId(), 1);
            }
        }
    }

    static String slugify(String text) {
        text = text.toLowerCase();
        text = text.replaceAll("[^a-z0-9]+", "-");
        text = text.replaceAll("^-|-$", "");
        if (text.length() > 60) text = text.substring(0, 60);
        return text;
    }

    private static String textContent(Element parent, String localName) {
        NodeList nodes = parent.getElementsByTagNameNS(NS, localName);
        if (nodes.getLength() == 0) return null;
        String text = nodes.item(0).getTextContent();
        return text != null ? text.strip() : null;
    }

    private static List<String> allTextContents(Element parent, String localName) {
        NodeList nodes = parent.getElementsByTagNameNS(NS, localName);
        List<String> result = new ArrayList<>();
        for (int i = 0; i < nodes.getLength(); i++) {
            String text = nodes.item(i).getTextContent();
            if (text != null && !text.isBlank()) {
                result.add(text.strip());
            }
        }
        return result;
    }

    private Document parseXml(Path path) {
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(true);
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            DocumentBuilder builder = factory.newDocumentBuilder();
            return builder.parse(path.toFile());
        } catch (Exception e) {
            throw new IllegalArgumentException("Cannot parse XML: " + path, e);
        }
    }

    private void writeOutput(Path outputPath, Map<String, Object> data) {
        try {
            Path parent = outputPath.toAbsolutePath().getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            try (BufferedWriter w = Files.newBufferedWriter(outputPath, StandardCharsets.UTF_8)) {
                w.write("# Canonical vulnerability suppression rules\n");
                w.write("# Source of truth — scanner-specific formats are generated from this file.\n");
                w.write("# Migrated from owasp-suppressions/owasp-suppressions.xml\n\n");

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
