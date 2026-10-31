package com.rm11.autocore.diagnostics;
import static org.junit.Assert.*;
import org.junit.Test;
public class R4DiagnosticDownloadsV49078Test {
    @Test public void generalAndGameExportHaveDistinctSafeZipNames(){
        String general=R4DiagnosticDownloadsV49078.fileName(false,12345);
        String game=R4DiagnosticDownloadsV49078.fileName(true,12345);
        assertEquals("RM11-General-Diagnostics-12345.zip",general);
        assertEquals("RM11-Game-Diagnostics-12345.zip",game);
        assertFalse(game.contains("/"));
        assertFalse(game.contains(".."));
        assertEquals("Download/",R4DiagnosticDownloadsV49078.targetFolder());
    }
}
