package com.rm11.autocore.runtime;
import org.junit.Test;
import static org.junit.Assert.*;

/** Device proof cannot be promoted from a build, a single color, a
 * truncated trace or an unrelated old 300-frame test. */
public final class KernixDx11QualificationV49102Test {
    private static final String WIN64_COMPLETED=
        "RM11_V49029_STAGE=CREATE_D3D11_DEVICE_SWAPCHAIN HRESULT=0x00000000\n"
       +"RM11_V49029_STAGE=GET_BACK_BUFFER HRESULT=0x00000000\n"
       +"RM11_V49029_STAGE=CREATE_RENDER_TARGET HRESULT=0x00000000\n"
       +"KERNIX_V49101_RESULT_FRAMES=900 FAILED=0\n"
       +"KERNIX_V49101_FINAL_COMPLETE=1 STATUS=0\n";
    @Test public void successRequiresNative900AndTwoAndroidColors() {
        assertTrue(KernixEngineQualificationV49090.verifiedWin64Dx11Frames(
            WIN64_COMPLETED,0b0101));
    }
    @Test public void firstBlueFrameAloneNeverQualifies() {
        assertFalse(KernixEngineQualificationV49090.verifiedWin64Dx11Frames(
            WIN64_COMPLETED,1));
    }
    @Test public void old300OrIncompleteNativeOutputNeverQualifies() {
        assertFalse(KernixEngineQualificationV49090.verifiedWin64Dx11Frames(
            WIN64_COMPLETED.replace("900 FAILED=0","300 FAILED=0"),15));
        assertFalse(KernixEngineQualificationV49090.verifiedWin64Dx11Frames(
            WIN64_COMPLETED.replace("FINAL_COMPLETE=1","FINAL_COMPLETE=0"),15));
        assertFalse(KernixEngineQualificationV49090.verifiedWin64Dx11Frames(
            WIN64_COMPLETED.replace("FAILED=0","FAILED=1"),15));
    }
    @Test public void substringOrStaleUnrelatedTextMustNotQualify() {
        assertFalse(KernixEngineQualificationV49090.verifiedWin64Dx11Frames(
            "OLD_IGNORED_"+WIN64_COMPLETED,15));
        assertFalse(KernixEngineQualificationV49090.verifiedWin64Dx11Frames(
            WIN64_COMPLETED.replace("CREATE_RENDER_TARGET HRESULT=0x00000000",
                                      "CREATE_RENDER_TARGET HRESULT=0x80004005"),15));
    }
}
