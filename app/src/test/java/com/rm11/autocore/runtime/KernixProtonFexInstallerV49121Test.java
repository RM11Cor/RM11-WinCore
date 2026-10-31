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
    @Test public void cannotActivateOrInstallIntoUnownedRoot(){
        assertEquals("proton-11.0-2-arm64ec-fex2610",
            KernixProtonFexInstallerV49121.SLOT);
        assertEquals("/data/kernix/imagefs/opt/proton-11.0-2-arm64ec-fex2610",
            KernixProtonFexInstallerV49121.slotRoot(
                java.nio.file.Path.of("/data/kernix")).toString());
    }
}
