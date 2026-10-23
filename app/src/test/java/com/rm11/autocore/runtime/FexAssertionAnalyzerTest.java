package com.rm11.autocore.runtime;

import org.junit.Test;
import static org.junit.Assert.*;

public final class FexAssertionAnalyzerTest {
    private static final String LOG =
            "0024:trace:module:map_image_into_view mapping PE file L\"\\\\??\\\\C:\\\\windows\\\\system32\\\\libarm64ecfex.dll\" at 0x7ffea70000-0x7ffee3d000\n"
            + "0024:err:seh:NtRaiseException Unhandled exception code c000001d flags 0 addr 0x7ffebefacc\n";

    @Test public void recognizesPinnedFexTrapAtExactRva() {
        FexAssertionAnalyzer.Finding v = FexAssertionAnalyzer.inspect(LOG);
        assertEquals("FEXCORE_FORCED_ASSERT_HLT1_CONFIRMED", v.status);
        assertEquals(0x17faccl, v.rva);
        assertTrue(v.summary().contains("assertion_condition_identified=false"));
    }
    @Test public void distinguishesOtherInstructionAddresses() {
        FexAssertionAnalyzer.Finding v = FexAssertionAnalyzer.inspect(
                LOG.replace("0x7ffebefacc","0x7ffebefa00"));
        assertEquals("ILLEGAL_INSTRUCTION_INSIDE_FEX_DLL_OTHER_OFFSET",v.status);
    }
    @Test public void handlesNoCrashOrMissingMapWithoutGuessing() {
        assertEquals("NO_C000001D_IN_CAPTURE",FexAssertionAnalyzer.inspect("Wine exit: 0").status);
        assertEquals("CRASH_IMAGE_MAPPING_NOT_CAPTURED",
                FexAssertionAnalyzer.inspect("Unhandled exception code c000001d flags 0 addr 0x7ffebefacc").status);
    }
}
