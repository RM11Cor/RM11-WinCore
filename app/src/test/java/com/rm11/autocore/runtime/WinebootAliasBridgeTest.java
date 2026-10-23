package com.rm11.autocore.runtime;
import org.junit.Test;
import static org.junit.Assert.*;
import java.nio.file.Files;
import java.nio.file.Path;

public final class WinebootAliasBridgeTest {
    private RuntimeLayout layout(Path root) throws Exception {
        Path files=root.resolve("files");
        Path libs=root.resolve("lib");
        Files.createDirectories(libs);
        RuntimeLayout p=new RuntimeLayout(files, libs);
        Files.createDirectories(p.wineDllRoot.resolve("aarch64-windows"));
        Files.createDirectories(p.winePrefix.resolve("drive_c/windows/system32"));
        return p;
    }
    @Test public void linksTrustedWinebootWithoutCopyingAndIsIdempotent() throws Exception {
        RuntimeLayout p=layout(Files.createTempDirectory("rm11-wineboot-"));
        Path source=p.wineDllRoot.resolve("aarch64-windows/wineboot.exe");
        byte[] pe=new byte[18000];pe[0]='M';pe[1]='Z';
        Files.write(source,pe);
        assertEquals("WINEBOOT_ALIAS_CREATED",WinebootAliasBridge.prepare(p));
        Path alias=p.winePrefix.resolve("drive_c/windows/system32/wineboot.exe");
        assertTrue(Files.isSymbolicLink(alias));
        assertEquals(source.toRealPath(),alias.toRealPath());
        assertEquals("WINEBOOT_ALIAS_ALREADY_PRESENT",WinebootAliasBridge.prepare(p));
    }
    @Test public void neverOverwritesPreexistingPrefixFile() throws Exception {
        RuntimeLayout p=layout(Files.createTempDirectory("rm11-wineboot-old-"));
        Path source=p.wineDllRoot.resolve("aarch64-windows/wineboot.exe");
        byte[] pe=new byte[18000];pe[0]='M';pe[1]='Z';
        Files.write(source,pe);
        Path alias=p.winePrefix.resolve("drive_c/windows/system32/wineboot.exe");
        Files.write(alias,new byte[]{1,2,3});
        assertEquals("WINEBOOT_EXISTING_FILE_PRESERVED",WinebootAliasBridge.prepare(p));
        assertEquals(3,Files.size(alias));
    }
}
