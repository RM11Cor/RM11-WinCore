package com.rm11.autocore.runtime;

import static org.junit.Assert.*;
import org.junit.Test;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;

public final class KernixProtonNativeQualificationV49123Test {
    @Test public void exactOneEngineFamilyWithoutLegacyPrefix() throws Exception{
        Path base=Files.createTempDirectory("p11-slot-");
        Path nativeDir=base.resolve("native");
        Files.createDirectory(nativeDir);
        Path root=KernixProtonFexInstallerV49121.slotRoot(base);
        for(String p:new String[]{
            "lib/wine/aarch64-unix/ntdll.so",
            "lib/wine/aarch64-unix/libarm64ecfex.so",
            "lib/wine/aarch64-unix/libwow64fex.so",
            "lib/wine/aarch64-windows/libarm64ecfex.dll",
            "lib/wine/aarch64-windows/libwow64fex.dll",
            "share/wine/wine.inf",
            "prefix/system.reg","prefix/user.reg","prefix/userdef.reg"}){
            Path f=root.resolve(p);Files.createDirectories(f.getParent());
            Files.write(f,new byte[512]);
        }
        for(String name:new String[]{
            "libkernix_p11_loader.so","libkernix_p11_server.so",
            "libkernix_p11_fex64.so","libkernix_p11_fex32.so"}){
            Files.write(nativeDir.resolve(name),new byte[512]);
        }
        Files.createDirectories(root.resolve("prefix/drive_c/windows/system32"));
        Files.createDirectories(root.resolve("prefix/dosdevices"));
        Files.createSymbolicLink(root.resolve("prefix/dosdevices/c:"),Path.of("../drive_c"));
        KernixProtonNativeQualificationV49123.Plan plan=
            KernixProtonNativeQualificationV49123.buildPlan(base,nativeDir);
        assertEquals(root.resolve("prefix").toString(),plan.environment.get("WINEPREFIX"));
        assertEquals(nativeDir.resolve("libkernix_p11_server.so").toString(),
            plan.environment.get("WINESERVER"));
        assertTrue(plan.environment.get("LD_LIBRARY_PATH").startsWith(nativeDir.toString()));
        assertTrue(plan.environment.get("WINEDLLPATH").startsWith(root.toString()));
        assertFalse(plan.environment.get("WINEPREFIX").contains("home/xuser/.wine"));
        Path log=base.resolve("version.log");
        ProcessBuilder cmd=plan.versionCommand(false,log);
        assertEquals("--version",cmd.command().get(1));
        assertEquals(nativeDir.resolve("libkernix_p11_loader.so").toString(),
            cmd.command().get(0));
        assertFalse(cmd.environment().containsKey("VK_ICD_FILENAMES"));
        assertFalse(cmd.environment().containsKey("LD_PRELOAD"));
    }
    @Test public void rejectForeignDosdevicesSymlink() throws Exception{
        Path root=Files.createTempDirectory("p11-reject");
        Path nativeDir=root.resolve("native");Files.createDirectory(nativeDir);
        try{
            KernixProtonNativeQualificationV49123.buildPlan(root,nativeDir);
            fail("missing native files should block");
        }catch(java.io.IOException correct){
            assertTrue(correct.getMessage().startsWith("P11_COMPONENT_"));
        }
    }
}
