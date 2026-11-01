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
    @Test public void rc319GuestLogExplosionMustNotRepeat(){
        java.util.Map<String,String> env=new java.util.HashMap<>();
        env.put("WINEDEBUG","+process,+loaddll,+module");
        KernixProtonX11WindowV49140.quietGuiGuestLog(env);
        assertEquals("-all,err+all",env.get("WINEDEBUG"));
        assertFalse(env.get("WINEDEBUG").contains("warn+all"));
        assertFalse(env.get("WINEDEBUG").contains("+process"));
        assertFalse(env.get("WINEDEBUG").contains("+loaddll"));
        assertFalse(env.get("WINEDEBUG").contains("+module"));
        assertEquals("GUEST_LOG_LIMIT_4200000",
            KernixProtonX11WindowV49140.guiGuestLogVerdict(
                true,false,4200000L,true));
        assertEquals("WINDOWS_BOOTSTRAP_BEFORE_GDI_MAIN",
            KernixProtonX11WindowV49140.guiGuestLogVerdict(
                true,false,730L,false));
        assertEquals("GDI_MAIN_REACHED",
            KernixProtonX11WindowV49140.guiGuestLogVerdict(
                true,true,730L,false));
        assertEquals("SERVER_EXIT_DURING_GUEST",
            KernixProtonX11WindowV49140.guiGuestLogVerdict(
                false,false,730L,false));
    }
    @Test public void queueEvidenceScannerReadsOmittedMiddleWithoutAssumptions()
        throws Exception {
        java.nio.file.Path sample=java.nio.file.Files.createTempFile("p11-queue-",".txt");
        try{
            java.nio.file.Files.write(sample,(
                "boot\n"+new String(new char[25000]).replace('\0','X')+"\n"+
                "KERNIX_P11_QUEUE_CREATE_FAILED_AT_REQUEST desktop=00000000\n"+
                new String(new char[25000]).replace('\0','Y')+"\nstop").getBytes(
                    java.nio.charset.StandardCharsets.US_ASCII));
            assertEquals("PRESENT",KernixProtonX11WindowV49140.serverMarkerState(
                sample,"KERNIX_P11_QUEUE_CREATE_FAILED_AT_REQUEST"));
            assertEquals("ABSENT_IN_COMPLETE_LOG",
                KernixProtonX11WindowV49140.serverMarkerState(
                    sample,"KERNIX_P11_QUEUE_HANDLE_ALLOC_FAILED"));
            assertEquals("WIN64_GDI_MAIN_NOT_REACHED",
                KernixProtonX11WindowV49140.gdiStageFromFile(sample));
        }finally{java.nio.file.Files.deleteIfExists(sample);}
        assertEquals("UNAVAILABLE",KernixProtonX11WindowV49140.serverMarkerState(
            null,"KERNIX_P11_QUEUE_NO_THREAD_DESKTOP"));
    }
    @Test public void gdiMainStageInMiddleOfLongLogIsNotLost()throws Exception{
        java.nio.file.Path log=java.nio.file.Files.createTempFile("kernix-p11-long-",".log");
        try{
            java.nio.file.Files.write(log,(
                new String(new char[25000]).replace('\0','F')+"\n"+
                "P11_GDI_STAGE_MAIN_ENTER\n"+
                new String(new char[25000]).replace('\0','F')).getBytes(
                    java.nio.charset.StandardCharsets.US_ASCII));
            assertEquals("P11_GDI_STAGE_MAIN_ENTER",
                KernixProtonX11WindowV49140.gdiStageFromFile(log));
        }finally{java.nio.file.Files.deleteIfExists(log);}
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
    @Test public void prefixInitMustExitZeroWithLivePrivateServer(){
        assertTrue(KernixProtonX11WindowV49140.acceptedGuiInit(0,true));
        assertFalse(KernixProtonX11WindowV49140.acceptedGuiInit(0,false));
        assertFalse(KernixProtonX11WindowV49140.acceptedGuiInit(1,true));
        assertFalse(KernixProtonX11WindowV49140.acceptedGuiInit(127,true));
    }
    @Test public void missingAndroidContextCannotStoreX11Stage(){
        assertFalse(KernixEngineQualificationV49090.recordWin32X11VisibleFrame(
            null,true,true,true));
    }
}
