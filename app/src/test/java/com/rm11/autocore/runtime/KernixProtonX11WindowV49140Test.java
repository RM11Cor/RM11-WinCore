package com.rm11.autocore.runtime;
import org.junit.Test;
import static org.junit.Assert.*;

/** Signed GUI path proof is distinct from DXVK/DX12 and game startup. */
public final class KernixProtonX11WindowV49140Test {
    private final String sha=
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    @Test public void peStageCannotEscapeSignedPrivatePrefix(){
        assertEquals("kernix-x11-gdi-0123456789abcdef01234567.exe",
            KernixProtonX11WindowV49140.fileName(sha));
        assertEquals("C:\\kernix-probes\\kernix-x11-gdi-0123456789abcdef01234567.exe",
            KernixProtonX11WindowV49140.command(sha));
        for(String bad:new String[]{"../outside", "ABC", "", null}){
            try{KernixProtonX11WindowV49140.fileName(bad);fail("accepted "+bad);}
            catch(IllegalArgumentException expected){}
        }
    }
    @Test public void guiSuccessRequiresExactSignedExeMarkersAndExit(){
        String log="KERNIX_P11_X11_GDI_WINDOW_CREATED\n"+
            "KERNIX_P11_X11_GDI_MAGENTA_PAINTED\n"+
            "KERNIX_P11_X11_GDI_CYAN_PAINTED\n"+
            "KERNIX_P11_X11_GDI_BOTH_COLORS=1\n";
        assertTrue(KernixProtonX11WindowV49140.guestPass(48,log));
        assertFalse(KernixProtonX11WindowV49140.guestPass(47,log));
        assertFalse(KernixProtonX11WindowV49140.guestPass(48,log
            .replace("GDI_BOTH_COLORS=1","GDI_BOTH_COLORS=0")));
        assertFalse(KernixProtonX11WindowV49140.guestPass(48,log
            .replace("GDI_WINDOW_CREATED","GDI_WINDOW_FAILED")));
        assertFalse(KernixProtonX11WindowV49140.guestPass(48,null));
    }
    @Test public void gdiProcessAloneCanNeverCertifyAndroidDisplay(){
        assertFalse(KernixProtonX11WindowV49140.completeWindowEvidence(true,true,true,false));
        assertFalse(KernixProtonX11WindowV49140.completeWindowEvidence(true,true,false,true));
        assertFalse(KernixProtonX11WindowV49140.completeWindowEvidence(true,false,true,true));
        assertFalse(KernixProtonX11WindowV49140.completeWindowEvidence(false,true,true,true));
        assertTrue(KernixProtonX11WindowV49140.completeWindowEvidence(true,true,true,true));
    }
    @Test public void isolatedGuiUsesConservativeSynchronization(){
        java.util.Map<String,String> env=new java.util.HashMap<>();
        env.put("WINENTSYNC","1");
        env.put("WINEESYNC","1");
        env.put("NTSYNC_SHM","/tmp/old-sync");
        env.put("PROTON_NO_KERNEL_NTSYNC","1");
        KernixProtonX11WindowV49140.disableExperimentalSync(env);
        assertEquals("1",env.get("PROTON_NO_NTSYNC"));
        assertEquals("0",env.get("WINENTSYNC"));
        assertEquals("0",env.get("WINEESYNC"));
        assertEquals("0",env.get("WINEFSYNC"));
        assertFalse(env.containsKey("NTSYNC_SHM"));
        assertFalse(env.containsKey("PROTON_NO_KERNEL_NTSYNC"));
    }
    @Test public void wineServerCrashCannotCountAsGdiSuccess(){
        assertTrue(KernixProtonX11WindowV49140.serverCrashed(
            "wineserver crashed, please enable coredumps"));
        assertFalse(KernixProtonX11WindowV49140.serverCrashed("wineserver is running"));
        assertEquals("WIN64_GDI_MAIN_NOT_REACHED",
            KernixProtonX11WindowV49140.gdiStage(
                "NtCreateUserProcess wineboot.exe --init"));
        assertEquals("P11_GDI_STAGE_CREATE_ENTER",
            KernixProtonX11WindowV49140.gdiStage(
                "P11_GDI_STAGE_MAIN_ENTER\nP11_GDI_STAGE_CREATE_ENTER"));
    }
    @Test public void missingAndroidContextCannotStoreX11Stage(){
        assertFalse(KernixEngineQualificationV49090.recordWin32X11VisibleFrame(
            null,true,true,true));
    }
}
