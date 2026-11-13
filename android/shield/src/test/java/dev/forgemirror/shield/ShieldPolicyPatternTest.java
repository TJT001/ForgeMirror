package dev.forgemirror.shield;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import java.util.Arrays;
import java.util.List;

public final class ShieldPolicyPatternTest {
    private static List<java.util.regex.Pattern> patterns(String... values) {
        java.util.List<java.util.regex.Pattern> result = new java.util.ArrayList<>();
        for (String value : values) {
            result.add(ShieldPolicy.compilePattern(value));
        }
        return result;
    }

    @Test
    public void excludeWinsOverEncryptRule() {
        List<java.util.regex.Pattern> rules = patterns(
                "files/**/*.txt", "databases/*");
        List<java.util.regex.Pattern> excludes = patterns(
                "databases/*", "cache/**");
        assertTrue(ShieldPolicy.matches(rules, excludes, "files/harness.txt"));
        assertFalse(ShieldPolicy.matches(rules, excludes, "databases/harness.db"));
        assertFalse(ShieldPolicy.matches(rules, excludes, "cache/entry"));
        assertFalse(ShieldPolicy.matches(rules, excludes, "files/harness.dat"));
    }

    @Test
    public void globstarMatchesZeroOrMoreSegments() {
        assertTrue(ShieldPolicy.compilePattern("files/**/*.txt")
                .matcher("files/harness.txt").matches());
        assertTrue(ShieldPolicy.compilePattern("files/**/*.txt")
                .matcher("files/a/b/harness.txt").matches());
        assertFalse(ShieldPolicy.compilePattern("files/**/*.txt")
                .matcher("files/harness.dat").matches());
    }

    @Test
    public void singleStarStaysInOneSegment() {
        assertTrue(ShieldPolicy.compilePattern("shared_prefs/*.xml")
                .matcher("shared_prefs/user.xml").matches());
        assertFalse(ShieldPolicy.compilePattern("shared_prefs/*.xml")
                .matcher("shared_prefs/a/user.xml").matches());
        assertFalse(ShieldPolicy.compilePattern("files/*.txt")
                .matcher("files/a/b.txt").matches());
    }

    @Test
    public void trailingGlobstarMatchesWholeTree() {
        assertTrue(ShieldPolicy.compilePattern("cache/**")
                .matcher("cache/entry").matches());
        assertTrue(ShieldPolicy.compilePattern("cache/**")
                .matcher("cache/a/b").matches());
        assertFalse(ShieldPolicy.compilePattern("cache/**")
                .matcher("cache").matches());
    }

    @Test
    public void questionMarkMatchesOneCharacter() {
        assertTrue(ShieldPolicy.compilePattern("files/a?.dat")
                .matcher("files/a1.dat").matches());
        assertFalse(ShieldPolicy.compilePattern("files/a?.dat")
                .matcher("files/a12.dat").matches());
        assertFalse(ShieldPolicy.compilePattern("files/a?.dat")
                .matcher("files/a/b.dat").matches());
    }
}
