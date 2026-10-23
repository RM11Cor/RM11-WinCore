package com.rm11.autocore.runtime;

import org.junit.Test;
import static org.junit.Assert.*;

public final class WineChildLifecycleAnalyzerTest {
    @Test public void provesOnlyCorrelatedWinebootNtExit() {
        String trace="0024:trace:process:NtCreateUserProcess L\"C:\\windows\\system32\\wineboot.exe\" image ... pid 0028 tid 002c handles\n"
                +"002c:trace:process:NtTerminateProcess handle 0x0, exit_code 0, process_exiting 0.\n"
                +"0024:trace:process:NtTerminateProcess handle 0x0, exit_code 42, process_exiting 0.\n";
        String report=WineChildLifecycleAnalyzer.report(trace);
        assertTrue(report.contains("Wineboot NT exit-zero observed: YES"));
        assertTrue(report.contains("Full independent Android child waitpid: NOT VERIFIED"));
    }
    @Test public void ignoresMainProcessExitAndMissingChildExit() {
        String trace="0024:trace:process:NtCreateUserProcess wineboot.exe pid 0028 tid 002c\n"
                +"0024:trace:process:NtTerminateProcess handle 0x0, exit_code 0, process_exiting 0.\n";
        assertTrue(WineChildLifecycleAnalyzer.report(trace).contains("WINEBOOT_CHILD_EXIT: NOT_OBSERVED"));
    }
    @Test public void neverGuessesIfNoCreationTrace() {
        assertTrue(WineChildLifecycleAnalyzer.report("Wine exit: 42").contains("CREATION_NOT_CAPTURED"));
    }
}
