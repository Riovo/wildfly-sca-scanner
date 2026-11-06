package org.wildfly.security.sca.suppressions.converter;

import org.wildfly.security.sca.suppressions.model.Suppression;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public final class OwaspDcConverter {

    static final String NS = "https://jeremylong.github.io/DependencyCheck/dependency-suppression.1.3.xsd";

    public void convert(Path inputPath, Path outputPath) {
        List<Suppression> suppressions = loadSuppressions(inputPath);

        List<Suppression> cpeCorrections = new ArrayList<>();
        List<Suppression> cveTriages = new ArrayList<>();
        for (Suppression s : suppressions) {
            if ("cpe-correction".equals(s.getType())) {
                cpeCorrections.add(s);
            } else {
                cveTriages.add(s);
            }
        }

        StringBuilder sb = new StringBuilder();
        sb.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        sb.append("<suppressions xmlns=\"").append(NS).append("\">\n");
        sb.append("   <!-- CPE Suppressions -->\n");
        sb.append("   <!-- Sometimes the mapping from GAV to CPE creates a bad match, this section suppresses those matches. -->\n");

        for (Suppression s : cpeCorrections) {
            buildSuppressXml(sb, s);
        }

        sb.append("\n");
        sb.append("   <!-- CVE Suppressions -->\n");
        sb.append("\n");

        for (Suppression s : cveTriages) {
            buildSuppressXml(sb, s);
        }

        sb.append("</suppressions>\n");

        try {
            Path parent = outputPath.toAbsolutePath().getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            Files.writeString(outputPath, sb.toString(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }

        System.out.println("Converted " + suppressions.size() + " suppressions to OWASP DC XML");
        System.out.println("  - " + cpeCorrections.size() + " CPE corrections");
        System.out.println("  - " + cveTriages.size() + " CVE triages");
        System.out.println("Output: " + outputPath);
    }

    private static void buildSuppressXml(StringBuilder sb, Suppression s) {
        String attr = "";
        if (s.getUntil() != null) {
            attr = " until=\"" + escapeXml(s.getUntil()) + "\"";
        }

        sb.append("   <suppress").append(attr).append(">\n");

        String notes = escapeCdata(s.getNotes() != null ? s.getNotes() : "");
        sb.append("      <notes><![CDATA[\n      ").append(notes).append("\n      ]]></notes>\n");

        if (s.getPackageUrl() != null) {
            sb.append("      <packageUrl regex=\"true\">").append(escapeXml(s.getPackageUrl())).append("</packageUrl>\n");
        }
        if (s.getFilePath() != null) {
            sb.append("      <filePath regex=\"true\">").append(escapeXml(s.getFilePath())).append("</filePath>\n");
        }

        for (String cve : s.getCves()) {
            sb.append("      <cve>").append(escapeXml(cve)).append("</cve>\n");
        }
        for (String vn : s.getVulnerabilityNames()) {
            sb.append("      <vulnerabilityName>").append(escapeXml(vn)).append("</vulnerabilityName>\n");
        }
        for (String cpe : s.getCpes()) {
            sb.append("      <cpe>").append(escapeXml(cpe)).append("</cpe>\n");
        }

        sb.append("   </suppress>\n");
    }

    static String escapeXml(String text) {
        return text
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;");
    }

    static String escapeCdata(String text) {
        return text.replace("]]>", "]]]]><![CDATA[>");
    }

    @SuppressWarnings("unchecked")
    private static List<Suppression> loadSuppressions(Path path) {
        try (BufferedReader reader = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
            Map<String, Object> data = new Yaml(new SafeConstructor(new LoaderOptions())).load(reader);
            if (data == null || !data.containsKey("suppressions")) {
                throw new IllegalArgumentException(path + " is empty or missing 'suppressions' key");
            }
            List<Map<String, Object>> raw = (List<Map<String, Object>>) data.get("suppressions");
            return raw.stream().map(Suppression::fromDict).toList();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
