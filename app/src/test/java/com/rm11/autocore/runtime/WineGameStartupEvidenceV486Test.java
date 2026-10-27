package com.rm11.autocore.runtime;

import org.junit.Test;
import static org.junit.Assert.*;

public final class WineGameStartupEvidenceV486Test {
    @Test public void keepsFirstLinesAndSeparatesLauncherFromWineHandoff() {
        WineGameStartupEvidenceV486 e=new WineGameStartupEvidenceV486(
                "CarX Street Launcher.exe");
        e.accept("RM11_WINE_ENTRY_FOUND; handing over to Wine\n");
        e.accept("Wine cannot find the FreeType font library.\n");
        e.accept("009c:err:winediag:gnutls_process_attach failed to load libgnutls\n");
        for(int i=0;i<700;i++)e.accept("0010:warn:trace:repeat-"+i+"\n");
        String snapshot=e.snapshot();
        assertTrue(snapshot.contains("RM11_V486_WINE_LOADER_HANDOFF=true"));
        assertTrue(snapshot.contains("RM11_V486_FREETYPE_MISSING_WARNING=true"));
        assertTrue(snapshot.contains("RM11_V486_GNUTLS_MISSING_WARNING=true"));
        assertTrue(snapshot.contains("RM11_WINE_ENTRY_FOUND; handing over to Wine"));
        assertTrue(snapshot.contains("RM11_V486_SELECTED_PE_MENTIONED_IN_TRACE=false"));
        assertTrue(snapshot.contains("RM11_V486_SELECTED_PE_EXECUTING=UNVERIFIED"));
        assertFalse(snapshot.contains("repeat-0\n"));
    }
    @Test public void acceptsFragmentedProcessTraceAndFindsExeName() {
        WineGameStartupEvidenceV486 e=new WineGameStartupEvidenceV486(
                "CarX Street Launcher.exe");
        e.accept("009c:trace:process:NtCreateUserPro");
        e.accept("cess L\"CarX Street Launcher.exe\" pid 0044\n");
        String snapshot=e.snapshot();
        assertTrue(snapshot.contains("RM11_V486_SELECTED_PE_MENTIONED_IN_TRACE=true"));
        assertTrue(snapshot.contains("RM11_V486_WINE_PROCESS_CREATE_TRACE=true"));
        assertTrue(snapshot.contains("RM11_V486_FREETYPE_MISSING_WARNING=false"));
    }
}
