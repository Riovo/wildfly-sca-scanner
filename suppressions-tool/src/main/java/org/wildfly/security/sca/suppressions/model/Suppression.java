package org.wildfly.security.sca.suppressions.model;

import java.time.LocalDate;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class Suppression {

    private String id;
    private String type;
    private String notes;
    private String packageUrl;
    private String filePath;
    private List<String> cves;
    private List<String> cpes;
    private String until;
    private List<String> references;
    private List<String> vulnerabilityNames;

    public Suppression(String id, String type, String notes) {
        this.id = id;
        this.type = type;
        this.notes = notes;
        this.cves = new ArrayList<>();
        this.cpes = new ArrayList<>();
        this.references = new ArrayList<>();
        this.vulnerabilityNames = new ArrayList<>();
    }

    @SuppressWarnings("unchecked")
    public static Suppression fromDict(Map<String, Object> d) {
        Suppression s = new Suppression(
                stringOr(d.get("id"), ""),
                stringOr(d.get("type"), ""),
                stringOr(d.get("notes"), "")
        );

        Map<String, Object> match = d.get("match") instanceof Map<?, ?> m
                ? (Map<String, Object>) m : Collections.emptyMap();
        Map<String, Object> suppress = d.get("suppress") instanceof Map<?, ?> m
                ? (Map<String, Object>) m : Collections.emptyMap();

        s.packageUrl = (String) match.get("package-url");
        s.filePath = (String) match.get("file-path");
        s.cves = listOrEmpty(suppress.get("cves"));
        s.cpes = listOrEmpty(suppress.get("cpes"));
        s.vulnerabilityNames = listOrEmpty(suppress.get("vulnerability-names"));
        s.references = listOrEmpty(d.get("references"));

        Object until = d.get("until");
        if (until instanceof Date date) {
            s.until = date.toInstant().atZone(ZoneId.of("UTC")).toLocalDate().toString();
        } else if (until instanceof LocalDate ld) {
            s.until = ld.toString();
        } else if (until != null) {
            s.until = until.toString();
        }

        return s;
    }

    public Map<String, Object> toDict() {
        Map<String, Object> d = new LinkedHashMap<>();
        d.put("id", id);
        d.put("type", type);
        d.put("notes", notes);

        Map<String, Object> match = new LinkedHashMap<>();
        if (packageUrl != null) match.put("package-url", packageUrl);
        if (filePath != null) match.put("file-path", filePath);
        d.put("match", match);

        Map<String, Object> suppress = new LinkedHashMap<>();
        if (cves != null && !cves.isEmpty()) suppress.put("cves", cves);
        if (cpes != null && !cpes.isEmpty()) suppress.put("cpes", cpes);
        if (vulnerabilityNames != null && !vulnerabilityNames.isEmpty()) {
            suppress.put("vulnerability-names", vulnerabilityNames);
        }
        d.put("suppress", suppress);

        if (until != null) d.put("until", until);
        if (references != null && !references.isEmpty()) d.put("references", references);

        return d;
    }

    @SuppressWarnings("unchecked")
    private static List<String> listOrEmpty(Object value) {
        if (value instanceof List<?> list) {
            return new ArrayList<>((List<String>) list);
        }
        return new ArrayList<>();
    }

    private static String stringOr(Object value, String fallback) {
        return value instanceof String s ? s : fallback;
    }

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    public String getType() { return type; }
    public String getNotes() { return notes; }
    public String getPackageUrl() { return packageUrl; }
    public void setPackageUrl(String packageUrl) { this.packageUrl = packageUrl; }
    public String getFilePath() { return filePath; }
    public void setFilePath(String filePath) { this.filePath = filePath; }
    public List<String> getCves() { return cves; }
    public void setCves(List<String> cves) { this.cves = cves; }
    public List<String> getCpes() { return cpes; }
    public void setCpes(List<String> cpes) { this.cpes = cpes; }
    public String getUntil() { return until; }
    public void setUntil(String until) { this.until = until; }
    public List<String> getReferences() { return references; }
    public void setReferences(List<String> references) { this.references = references; }
    public List<String> getVulnerabilityNames() { return vulnerabilityNames; }
    public void setVulnerabilityNames(List<String> vulnerabilityNames) { this.vulnerabilityNames = vulnerabilityNames; }

    public List<String> getAllVulnerabilityIds() {
        List<String> all = new ArrayList<>(cves);
        all.addAll(vulnerabilityNames);
        return all;
    }
}
