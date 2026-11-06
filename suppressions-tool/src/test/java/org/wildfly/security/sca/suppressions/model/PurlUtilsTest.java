package org.wildfly.security.sca.suppressions.model;

import org.junit.jupiter.api.Test;

import java.time.LocalDate;
import java.util.regex.Matcher;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PurlUtilsTest {

    @Test
    void testSimplePatternMatches() {
        Matcher m = PurlUtils.SIMPLE_PURL_RE.matcher("^pkg:maven/com\\.example/lib@.*$");
        assertThat(m.matches()).isTrue();
        assertThat(PurlUtils.purlFromSimpleMatch(m)).isEqualTo("pkg:maven/com.example/lib");
    }

    @Test
    void testEscapedHyphenUnescaped() {
        Matcher m = PurlUtils.SIMPLE_PURL_RE.matcher("^pkg:maven/com\\.example/my\\-lib@.*$");
        assertThat(m.matches()).isTrue();
        assertThat(PurlUtils.purlFromSimpleMatch(m)).isEqualTo("pkg:maven/com.example/my-lib");
    }

    @Test
    void testWildcardArtifactDoesNotMatch() {
        Matcher m = PurlUtils.SIMPLE_PURL_RE.matcher("^pkg:maven/org\\.wildfly\\.core/.*@.*$");
        assertThat(m.matches()).isFalse();
    }

    @Test
    void testNegativeLookaheadDoesNotMatch() {
        Matcher m = PurlUtils.SIMPLE_PURL_RE.matcher(
                "^pkg:maven/io\\.netty/(?!netty-codec-http3).*@.*$");
        assertThat(m.matches()).isFalse();
    }

    @Test
    void testParseValidDate() {
        LocalDate d = PurlUtils.parseUntilDate("2027-03-26", "test-id");
        assertThat(d).isEqualTo(LocalDate.of(2027, 3, 26));
    }

    @Test
    void testParseInvalidDate() {
        assertThatThrownBy(() -> PurlUtils.parseUntilDate("not-a-date", "test-id"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("test-id");
    }
}
