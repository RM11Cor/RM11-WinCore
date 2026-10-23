package com.rm11.autocore.diagnostics;

import java.util.regex.Pattern;

/** Bounded, conservative scrubber for reports the user chooses to export. */
public final class DiagnosticSanitizer {
    private static final Pattern SENSITIVE = Pattern.compile(
            "(?i)(\\b(?:authorization|password|passwd|token|secret|cookie|api[_-]?key|pairing[_-]?code)\\b\\s*[:=]\\s*)[^\\s\\r\\n]+");
    private static final Pattern SHARED_STORAGE = Pattern.compile(
            "(?i)(?:/storage/emulated/[0-9]+|/sdcard)/[^\\s\\\"'<>]+");
    private static final Pattern EMAIL = Pattern.compile(
            "(?i)\\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,}\\b");

    private DiagnosticSanitizer() {}

    public static String scrub(String text, int limit) {
        if (text == null) return "";
        final int cap = Math.max(0, Math.min(limit, 200000));
        String value = text.length() > cap ? text.substring(0, cap) + "\n[CAPTURE TRUNCATED]" : text;
        value = SENSITIVE.matcher(value).replaceAll("$1[REDACTED]");
        value = SHARED_STORAGE.matcher(value).replaceAll("[REDACTED_STORAGE_PATH]");
        return EMAIL.matcher(value).replaceAll("[REDACTED_EMAIL]");
    }

    public static String shortLabel(String value) {
        return scrub(value, 80).replace('\n', '_').replace('\r', '_')
                .replace('\t', '_').replace('/', '_').replace('\\', '_');
    }
}
