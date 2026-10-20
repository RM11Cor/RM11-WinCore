package com.rm11.autocore;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Parses imported Termux test evidence as untrusted text; never executes it. */
public final class RuntimeReportReader {
    private RuntimeReportReader() { }
    private static final Pattern ROW = Pattern.compile(
            "^\\[(\\d{2})/10\\] (PASS|FAIL|NOT_CONFIGURED) \u2014 (.*)$");
    public static final class Result {
        public final int passed, failed, notConfigured;
        public final String summary;
        private Result(int pass, int fail, int absent, String display) {
            passed=pass; failed=fail; notConfigured=absent; summary=display;
        }
    }
    public static Result read(String source) {
        if (source == null || source.length() > 65536 || !source.contains(
                "RM11-WinCore v2.4.13 Windows ten-check diagnostic"))
            throw new IllegalArgumentException("unknown report/version");
        String[] rows = new String[10];
        int pass=0, fail=0, missing=0;
        for (String line : source.split("\\r?\\n")) {
            Matcher m = ROW.matcher(line.trim());
            if (!m.matches()) continue;
            int idx=Integer.parseInt(m.group(1));
            if (idx < 1 || idx > 10 || rows[idx-1] != null)
                throw new IllegalArgumentException("invalid or duplicate test row");
            rows[idx-1]=line.trim();
            switch(m.group(2)) {
                case "PASS": pass++; break;
                case "FAIL": fail++; break;
                default: missing++; break;
            }
        }
        if(pass+fail+missing != 10) throw new IllegalArgumentException("incomplete ten-check report");
        StringBuilder summary = new StringBuilder("RM11 Windows Runtime — تقرير من Termux\n")
                .append("PASS: ").append(pass).append("   FAIL: ").append(fail)
                .append("   NOT_CONFIGURED: ").append(missing)
                .append("\nهذه أدلة من Ubuntu/Termux، وليست تشغيل Wine داخل APK.\n");
        for (String row : rows) summary.append('\n').append(row);
        return new Result(pass,fail,missing,summary.toString());
    }
}
