package com.rm11.autocore.runtime;
import org.junit.Test;
import static org.junit.Assert.*;

public final class FontSandboxEvidenceTest {
    @Test public void namedVsAbsoluteAreDistinct(){
        String report="RM11_V445_SEPARATE_ANDROID_PROCESS=true\n"
                +"RM11_V445_BARE_SONAME=NOT_FOUND\n"
                +"RM11_V445_SIGNED_ABSOLUTE=SUCCESS\n";
        assertEquals("RM11_V445_ANDROID_LINKER_NAME_GAP_OBSERVED",
                FontSandboxEvidence.classify(report));
    }
    @Test public void bothAvailableStillDoesNotProveWineRendering(){
        assertEquals("RM11_V445_ANDROID_LINKER_BOTH_LOADERS_AVAILABLE",
                FontSandboxEvidence.classify(
                "RM11_V445_SEPARATE_ANDROID_PROCESS=true\n"
                +"RM11_V445_BARE_SONAME=SUCCESS\n"
                +"RM11_V445_SIGNED_ABSOLUTE=SUCCESS\n"));
    }
    @Test public void isolatedCrashOrNoReportIsIndeterminate(){
        assertEquals("RM11_V445_RESULT_INDETERMINATE",
                FontSandboxEvidence.classify(null));
        assertEquals("RM11_V445_RESULT_INDETERMINATE",
                FontSandboxEvidence.classify("RM11_V445_SIGNED_ABSOLUTE=SUCCESS"));
    }
    @Test public void signedDlopenErrorIsVisible(){
        assertEquals("RM11_V445_SIGNED_NATIVE_FREETYPE_DLOPEN_FAILED",
                FontSandboxEvidence.classify(
                "RM11_V445_SEPARATE_ANDROID_PROCESS=true\n"
                +"RM11_V445_SIGNED_ABSOLUTE=FAILED\n"));
    }
}
