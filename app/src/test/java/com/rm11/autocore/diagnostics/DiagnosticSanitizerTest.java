package com.rm11.autocore.diagnostics;

import org.junit.Test;
import static org.junit.Assert.*;

public final class DiagnosticSanitizerTest {
    @Test public void masksCredentialsAndEmails() {
        String source = "authorization: BearerABC\npassword=MyPass\naaa@example.com";
        String clean = DiagnosticSanitizer.scrub(source, 1000);
        assertFalse(clean.contains("BearerABC"));
        assertFalse(clean.contains("MyPass"));
        assertFalse(clean.contains("aaa@example.com"));
        assertTrue(clean.contains("[REDACTED]"));
    }
    @Test public void hidesExternalStoragePathAndBoundsLength() {
        String output = DiagnosticSanitizer.scrub("/storage/emulated/0/Downloads/private.zip", 100);
        assertEquals("[REDACTED_STORAGE_PATH]", output);
        String longData = "x".repeat(1500);
        assertTrue(DiagnosticSanitizer.scrub(longData, 200).length() < 250);
    }
    @Test public void preservesWineErrors() {
        String data = "0024:err:environ:run_wineboot failed to start wineboot 1\n";
        assertEquals(data, DiagnosticSanitizer.scrub(data, 2000));
    }
    @Test public void avoidsRawNewlinesInPaths() {
        assertEquals("x_y_z", DiagnosticSanitizer.shortLabel("x/y\nz"));
    }
}
