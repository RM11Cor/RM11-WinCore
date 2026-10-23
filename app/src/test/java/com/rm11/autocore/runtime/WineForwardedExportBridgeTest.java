package com.rm11.autocore.runtime;

import org.junit.Test;
import static org.junit.Assert.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;

public final class WineForwardedExportBridgeTest {
    private RuntimeLayout layout(Path base) throws Exception {
        Path files=base.resolve("files");
        Path libs=base.resolve("apk-libs");
        Files.createDirectories(libs);
        RuntimeLayout p=new RuntimeLayout(files,libs);
        Files.createDirectories(p.wineDllRoot.resolve("aarch64-windows"));
        Files.createDirectories(p.winePrefix.resolve("drive_c/windows/system32"));
        Files.write(p.winePrefixMarker(),"READY".getBytes(StandardCharsets.US_ASCII));
        return p;
    }
    private Path bundled(RuntimeLayout p) throws Exception {
        Path cryptbase=p.wineDllRoot.resolve("aarch64-windows/cryptbase.dll");
        byte[] data=new byte[12_000];
        data[0]='M';data[1]='Z';
        Files.write(cryptbase,data);
        return cryptbase;
    }
    @Test public void linksOnlyBundledWineForwarderAndKeepsSource() throws Exception {
        RuntimeLayout p=layout(Files.createTempDirectory("rm11-crypto-forward-"));
        Path original=bundled(p);
        String result=WineForwardedExportBridge.prepare(p);
        assertTrue(result,result.contains("cryptbase.dll: READY_NEW_TRUSTED_LINK"));
        Path alias=p.winePrefix.resolve("drive_c/windows/system32/cryptbase.dll");
        assertTrue(Files.isSymbolicLink(alias));
        assertEquals(original.toRealPath(),alias.toRealPath());
        assertTrue(WineForwardedExportBridge.prepare(p).contains("READY_EXISTING_TRUSTED_LINK"));
    }
    @Test public void preservesAnyExistingPrefixFile() throws Exception {
        RuntimeLayout p=layout(Files.createTempDirectory("rm11-crypto-existing-"));
        bundled(p);
        Path alias=p.winePrefix.resolve("drive_c/windows/system32/cryptbase.dll");
        Files.write(alias,new byte[]{2,4,6});
        assertTrue(WineForwardedExportBridge.prepare(p).contains("EXISTING_ENTRY_PRESERVED"));
        assertEquals(3L,Files.size(alias));
    }
    @Test public void failsClosedOnMissingAndNonPe() throws Exception {
        RuntimeLayout p=layout(Files.createTempDirectory("rm11-crypto-missing-"));
        assertTrue(WineForwardedExportBridge.prepare(p).contains("UNCHANGED_NoSuchFileException"));
        Path dll=p.wineDllRoot.resolve("aarch64-windows/cryptbase.dll");
        Files.write(dll,new byte[10000]);
        assertTrue(WineForwardedExportBridge.prepare(p).contains("NOT_PE"));
        assertFalse(Files.exists(p.winePrefix.resolve("drive_c/windows/system32/cryptbase.dll")));
    }
}
