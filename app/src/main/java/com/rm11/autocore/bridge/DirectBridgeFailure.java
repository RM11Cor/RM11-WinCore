package com.rm11.autocore.bridge;

import java.util.Locale;

/**
 * Read-only classification of observed Wine diagnostic evidence.
 * A detected symptom is NOT a verified root cause.
 * This class intentionally does not depend on Android APIs.
 */
public final class DirectBridgeFailure {
    private DirectBridgeFailure() {}

    public static final class Finding {
        public final String code;
        public final String summary;
        public final String evidence;
        public final boolean rootCauseConfirmed;

        private Finding(String code, String summary, String evidence) {
            this.code = code;
            this.summary = summary;
            this.evidence = evidence;
            this.rootCauseConfirmed = false;
        }
    }

    private static Finding finding(String code, String summary, String log, String marker) {
        int at = log.toLowerCase(Locale.ROOT).indexOf(marker.toLowerCase(Locale.ROOT));
        String evidence = at < 0 ? "(no excerpt)" : log.substring(
                Math.max(0, at - 100), Math.min(log.length(), at + marker.length() + 170));
        return new Finding(code, summary, evidence.replace('\n', ' ').replace('\r', ' '));
    }

    public static Finding analyze(String report) {
        String log = report == null ? "" : report;
        String lower = log.toLowerCase(Locale.ROOT);
        if (lower.contains("pass_win32_execution") && lower.contains("rm11_win32_exe_executed_ok")) {
            return finding("WIN32_SMOKE_PASSED",
                    "Bundled Win32 smoke test reported success; games are not verified.",
                    log, "PASS_WIN32_EXECUTION");
        }
        if (lower.contains("fexcore_forced_assert_hlt1_confirmed")) {
            return finding("FEXCORE_FORCED_ASSERT_TRAP",
                    "FEX-2609 deliberately executed HLT #1 inside ForcedAssert. The assertion caller/condition is NOT identified; capture SEH context before attempting repairs.",
                    log, "FEXCORE_FORCED_ASSERT_HLT1_CONFIRMED");
        }
        if (lower.contains("run_wineboot failed to start wineboot")) {
            return finding("WINEBOOT_CHILD_START_FAILED",
                    "Wine tried to start wineboot but its child launch failed. Check child loader, ABI, imagefs paths and missing modules; none is proven to be the root cause.",
                    log, "run_wineboot failed to start wineboot");
        }
        if (lower.contains("failed to load") && (lower.contains("locale.nls") || lower.contains("l_intl.nls"))) {
            return finding("WINE_NLS_LOAD_FAILED",
                    "Wine could not read required NLS data; verify native .so redirect and ImageFs NLS paths.",
                    log, "failed to load");
        }
        if (lower.contains("recvmsg: connection reset by peer")) {
            return finding("WINESERVER_IPC_RESET",
                    "Wine client IPC connection reset; inspect WineServer exit and IPC paths.",
                    log, "recvmsg: Connection reset by peer");
        }
        if (lower.contains("result: wine_timeout")) {
            return finding("WINE_TIMEOUT", "Wine smoke operation exceeded its bounded timeout.",
                    log, "RESULT: WINE_TIMEOUT");
        }
        if (lower.contains("result: precheck_or_process_error")) {
            return finding("PRECHECK_FAILED",
                    "A local precheck or process launch failed before Win32 execution was established.",
                    log, "RESULT: PRECHECK_OR_PROCESS_ERROR");
        }
        if (lower.contains("result: not_passed")) {
            return finding("WIN32_SMOKE_NOT_PASSED",
                    "Smoke test did not establish Win32 process success. Read captured logs for details.",
                    log, "RESULT: NOT_PASSED");
        }
        return new Finding("NO_CLASSIFIED_WINE_RESULT",
                "No decisive smoke result was found; this does not imply that Wine works.", "");
    }
}
