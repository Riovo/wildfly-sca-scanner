package org.wildfly.security.sca.suppressions.model;

import java.time.LocalDate;
import java.time.format.DateTimeParseException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class PurlUtils {

    public static final Pattern SIMPLE_PURL_RE = Pattern.compile(
            "^\\^?pkg:maven/([a-zA-Z0-9_.\\\\-]+)/([a-zA-Z0-9_.\\\\-]+)@\\.\\*\\$?$"
    );

    private PurlUtils() {}

    public static String purlFromSimpleMatch(Matcher m) {
        String group = m.group(1).replace("\\.", ".").replace("\\-", "-");
        String artifact = m.group(2).replace("\\.", ".").replace("\\-", "-");
        return "pkg:maven/" + group + "/" + artifact;
    }

    public static LocalDate parseUntilDate(String untilStr, String suppressionId) {
        try {
            return LocalDate.parse(untilStr);
        } catch (DateTimeParseException e) {
            throw new IllegalArgumentException(
                    "Suppression '" + suppressionId + "': invalid until date '" + untilStr + "': " + e.getMessage(), e);
        }
    }
}
