package com.rm11.autocore.runtime;

import org.junit.Test;
import static org.junit.Assert.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;

public final class WineGuiImportBridgeTest {
    private RuntimeLayout create(Path root) throws Exception {
        Path app=root.resolve("files"), lib=root.resolve("apk-native");
        Files.createDirectories(lib);
        RuntimeLayout p=new RuntimeLayout(app,lib);
        Files.createDirectories(p.wineDllRoot.resolve("aarch64-windows"));
        Files.createDirectories(p.winePrefix.resolve("drive_c/windows/system32"));
        Files.write(p.winePrefixMarker(),"READY".getBytes(StandardCharsets.US_ASCII));
        return p;
    }
    private Path add(RuntimeLayout p,String name) throws Exception {
        byte[] pe=new byte[16000]; pe[0]='M';pe[1]='Z';
        Path path=p.wineDllRoot.resolve("aarch64-windows").resolve(name);
        Files.write(path,pe);
        return path;
    }

    @Test public void preparesThreeVerifiedGuiImports() throws Exception {
        RuntimeLayout p=create(Files.createTempDirectory("rm11-gui-imports"));
        for(String name:new String[]{"user32.dll","gdi32.dll","win32u.dll"}) add(p,name);
        String report=WineGuiImportBridge.prepare(p);
        for(String name:new String[]{"user32.dll","gdi32.dll","win32u.dll"}) {
            assertTrue(report,report.contains(name+": READY_NEW_SYMLINK"));
            Path link=p.winePrefix.resolve("drive_c/windows/system32").resolve(name);
            assertTrue(Files.isSymbolicLink(link));
            assertEquals(p.wineDllRoot.resolve("aarch64-windows").resolve(name).toRealPath(),
                    link.toRealPath());
        }
        assertTrue(WineGuiImportBridge.prepare(p).contains(
                "user32.dll: READY_EXISTING_TRUSTED_LINK"));
    }
    @Test public void preservesExistingPrefixFiles() throws Exception {
        RuntimeLayout p=create(Files.createTempDirectory("rm11-gui-preserve"));
        add(p,"user32.dll");
        Path existing=p.winePrefix.resolve("drive_c/windows/system32/user32.dll");
        Files.write(existing,new byte[]{3,4,5});
        String report=WineGuiImportBridge.prepare(p);
        assertTrue(report.contains("user32.dll: EXISTING_ENTRY_NOT_REPLACED"));
        assertEquals(3L,Files.size(existing));
    }
    @Test public void rejectsInvalidPeAndMissingModule() throws Exception {
        RuntimeLayout p=create(Files.createTempDirectory("rm11-gui-invalid"));
        Files.write(p.wineDllRoot.resolve("aarch64-windows/user32.dll"),new byte[12000]);
        String report=WineGuiImportBridge.prepare(p);
        assertTrue(report.contains("user32.dll: SOURCE_NOT_PE"));
        assertTrue(report.contains("gdi32.dll: UNMODIFIED_NoSuchFileException"));
        assertFalse(Files.exists(p.winePrefix.resolve("drive_c/windows/system32/user32.dll")));
    }
}
