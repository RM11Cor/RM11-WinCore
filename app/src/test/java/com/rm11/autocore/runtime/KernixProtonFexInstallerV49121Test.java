package com.rm11.autocore.runtime;
import static org.junit.Assert.*;
import org.junit.Test;

public class KernixProtonFexInstallerV49121Test {
    @Test public void acceptsOnlyNormalizedRuntimePaths(){
        assertTrue(KernixProtonFexInstallerV49121.safeZipEntry(
            "wine/lib/wine/aarch64-windows/ntdll.dll"));
        assertTrue(KernixProtonFexInstallerV49121.safeZipEntry(
            "wine/lib/wine/aarch64-unix/libarm64ecfex.so"));
        assertFalse(KernixProtonFexInstallerV49121.safeZipEntry(
            "wine/../../game/save.dat"));
        assertFalse(KernixProtonFexInstallerV49121.safeZipEntry(
            "/wine/etc/passwd"));
        assertFalse(KernixProtonFexInstallerV49121.safeZipEntry(
            "wine/bin/../bin/wine"));
        assertFalse(KernixProtonFexInstallerV49121.safeZipEntry(
            "wine\\lib\\wine\\ntdll.so"));
    }
    @Test public void zipInstallerKeepsProtonFilesInsideItsPrivateSlot()
            throws Exception{
        java.nio.file.Path dir=java.nio.file.Files.createTempDirectory("kernix-p11-unit");
        java.nio.file.Path archive=dir.resolve("runtime.zip");
        java.nio.file.Path stage=dir.resolve("stage");
        java.nio.file.Files.createDirectory(stage);
        String[] components={
            "lib/wine/aarch64-windows/libarm64ecfex.dll",
            "lib/wine/aarch64-windows/libwow64fex.dll",
            "lib/wine/aarch64-unix/libarm64ecfex.so",
            "lib/wine/aarch64-unix/libwow64fex.so",
            "lib/wine/aarch64-unix/ntdll.so",
            "lib/wine/aarch64-unix/winex11.so",
            "share/wine/wine.inf",
            "lib/wine/aarch64-windows/ntdll.dll",
            "prefix/system.reg",
            "prefix/user.reg",
            "prefix/userdef.reg",
            "prefix/drive_c/windows/system32/kernel32.dll"
        };
        try(java.util.zip.ZipOutputStream out=new java.util.zip.ZipOutputStream(
                java.nio.file.Files.newOutputStream(archive))){
            for(String item:components){
                out.putNextEntry(new java.util.zip.ZipEntry("wine/"+item));
                out.write(new byte[]{1,2,3,4,5});
                out.closeEntry();
            }
        }
        assertEquals(components.length,
            KernixProtonFexInstallerV49121.extractRuntimeZip(
                archive,stage,components.length));
        assertTrue(java.nio.file.Files.isRegularFile(
            stage.resolve("lib/wine/aarch64-unix/ntdll.so")));
        assertTrue(java.nio.file.Files.isSymbolicLink(
            stage.resolve("prefix/dosdevices/c:")));
        assertFalse(java.nio.file.Files.exists(
            stage.resolve("prefix/dosdevices/e:"),
            java.nio.file.LinkOption.NOFOLLOW_LINKS));
    }
    @Test public void zipInstallerRejectsTraversalBeforeTouchingGameTree()
            throws Exception{
        java.nio.file.Path dir=java.nio.file.Files.createTempDirectory("kernix-p11-slip");
        java.nio.file.Path archive=dir.resolve("unsafe.zip");
        java.nio.file.Path stage=dir.resolve("stage");
        java.nio.file.Files.createDirectory(stage);
        try(java.util.zip.ZipOutputStream out=new java.util.zip.ZipOutputStream(
                java.nio.file.Files.newOutputStream(archive))){
            out.putNextEntry(new java.util.zip.ZipEntry("wine/../game/save.dat"));
            out.write(new byte[]{42});
            out.closeEntry();
        }
        try{
            KernixProtonFexInstallerV49121.extractRuntimeZip(archive,stage,1);
            fail("must refuse path traversal");
        }catch(java.io.IOException expected){
            assertTrue(expected.getMessage().contains("UNSAFE"));
        }
        assertFalse(java.nio.file.Files.exists(dir.resolve("game/save.dat")));
    }
    @Test public void cannotActivateOrInstallIntoUnownedRoot(){
        assertEquals("proton-11.0-2-arm64ec-fex2610-pfx1",
            KernixProtonFexInstallerV49121.SLOT);
        assertEquals("/data/kernix/imagefs/opt/proton-11.0-2-arm64ec-fex2610",
            KernixProtonFexInstallerV49121.slotRoot(
                java.nio.file.Path.of("/data/kernix")).toString());
    }
}
