package com.rm11.autocore.bridge;

import org.junit.Test;
import static org.junit.Assert.*;

public final class DirectBridgeFailureTest {
    @Test public void winebootFailureTakesPrecedenceOverDebugNoise() {
        String log = "RM11_NLS_REDIRECT_ACTIVE\n0024:trace:process:NtCreateUserProcess wineboot.exe\n"
            + "0024:err:environ:run_wineboot failed to start wineboot 1\n"
            + "RESULT: NOT_PASSED\nServer at client exit: ALIVE";
        DirectBridgeFailure.Finding f = DirectBridgeFailure.analyze(log);
        assertEquals("WINEBOOT_CHILD_START_FAILED", f.code);
        assertFalse(f.rootCauseConfirmed);
        assertTrue(f.evidence.contains("wineboot"));
    }

    @Test public void prioritizesPinnedFexAssertionOverWinebootFailure() {
        String report = "RM11_FEX_ASSERT_ANALYSIS_V264\\nstatus=FEXCORE_FORCED_ASSERT_HLT1_CONFIRMED\\n"
                + "0024:err:environ:run_wineboot failed to start wineboot 1";
        DirectBridgeFailure.Finding f = DirectBridgeFailure.analyze(report);
        assertEquals("FEXCORE_FORCED_ASSERT_TRAP", f.code);
        assertFalse(f.rootCauseConfirmed);
    }

    @Test public void recognizesOldNlsFailure() {
        DirectBridgeFailure.Finding f = DirectBridgeFailure.analyze(
            "err:environ:read_nls_file failed to load /data/app/lib/../../share/wine/nls/locale.nls");
        assertEquals("WINE_NLS_LOAD_FAILED", f.code);
    }

    @Test public void recognizesIpcReset() {
        assertEquals("WINESERVER_IPC_RESET",
            DirectBridgeFailure.analyze("wine client error:0: recvmsg: Connection reset by peer").code);
    }

    @Test public void successRequiresBothEvidenceMarkers() {
        assertEquals("WIN32_SMOKE_PASSED",
            DirectBridgeFailure.analyze("RESULT: PASS_WIN32_EXECUTION\nRM11_WIN32_EXE_EXECUTED_OK").code);
        assertNotEquals("WIN32_SMOKE_PASSED",
            DirectBridgeFailure.analyze("RESULT: PASS_WIN32_EXECUTION").code);
    }

    @Test public void unknownDoesNotPretendSuccess() {
        DirectBridgeFailure.Finding f = DirectBridgeFailure.analyze("a lot of trace lines");
        assertEquals("NO_CLASSIFIED_WINE_RESULT", f.code);
        assertFalse(f.rootCauseConfirmed);
    }
}
