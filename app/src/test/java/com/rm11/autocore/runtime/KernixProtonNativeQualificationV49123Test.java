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
            "libkernix_p11_fex64.so","libkernix_p11_fex32.so",
            "librm11_wine_data_redirect.so",
            "librm11_freetype_core.so"}){
            Files.write(nativeDir.resolve(name),new byte[
                "librm11_freetype_core.so".equals(name)?2048:512]);
        }
        // The translator PE modules belong in the owned Windows prefix,
        // paired with signed APK native UnixLibs.
        for(String name:new String[]{"libarm64ecfex.dll","libwow64fex.dll"}){
            Path f=root.resolve("lib/wine/aarch64-windows").resolve(name);
            Files.createDirectories(f.getParent());
            byte[] pe=new byte[512];pe[0]='M';pe[1]='Z';
            Files.write(f,pe);
        }
        Path boot=root.resolve("lib/wine/aarch64-windows/wineboot.exe");
        Files.createDirectories(boot.getParent());
        byte[] exe=new byte[512];exe[0]='M';exe[1]='Z';
        Files.write(boot,exe);
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
        assertEquals(nativeDir.resolve("librm11_wine_data_redirect.so").toString(),
            cmd.environment().get("LD_PRELOAD"));
        assertEquals("1",cmd.environment().get("RM11_PROTON_RUNTIME_V49124"));
        // Critical: Wine 11 suppresses --version under WINELOADERNOEXEC.
        assertEquals("1",plan.environment.get("WINELOADERNOEXEC"));
        assertFalse(cmd.environment().containsKey("WINELOADERNOEXEC"));
        ProcessBuilder serverVersion=plan.versionCommand(true,log);
        assertFalse(serverVersion.environment().containsKey("WINELOADERNOEXEC"));
        try {
            plan.prefixBootCommand(log);
            fail("boot must reject immutable source prefix");
        } catch(java.io.IOException expected){
            assertTrue(expected.getMessage().startsWith("P11_"));
        }
        ProcessBuilder bootCmd=plan.withWritablePrefix(
            KernixProtonPrefixV49126.prepareDefault(base)).prefixBootCommand(log);
        assertEquals(3,bootCmd.command().size());
        assertEquals("C:\\windows\\system32\\wineboot.exe",
            bootCmd.command().get(1));
        assertEquals("--update",bootCmd.command().get(2));
        Path privateBoot=KernixProtonPrefixV49126.writableRoot(base)
            .resolve("drive_c/windows/system32/wineboot.exe");
        assertTrue(Files.isRegularFile(privateBoot,LinkOption.NOFOLLOW_LINKS));
        assertEquals(Files.size(boot),Files.size(privateBoot));
        assertEquals(boot.getFileSystem(),
            privateBoot.getFileSystem());
        assertEquals("1",bootCmd.environment().get("RM11_PROTON_RUNTIME_V49124"));
        assertEquals("1",bootCmd.environment().get("RM11_NATIVE_FREETYPE_DLOPEN_REDIRECT"));
        assertFalse(cmd.environment().containsKey("RM11_NATIVE_FREETYPE_DLOPEN_REDIRECT"));
        assertFalse("first Wineboot entry must not fake a re-exec",
            bootCmd.environment().containsKey("WINELOADERNOEXEC"));
        assertEquals(nativeDir.resolve("libkernix_p11_server.so").toString(),
            bootCmd.environment().get("WINESERVER"));
        assertFalse(bootCmd.environment().containsKey("RM11_WS2_UNIXLIB_REDIRECT"));
        assertFalse(bootCmd.environment().containsKey("DISPLAY"));
        // RC231 proved the WineServer ELF --version works, but not that
        // the live service can own this exact Proton prefix for Wineboot.
        Path serverLog=base.resolve("p11-wineserver-live.txt");
        ProcessBuilder live=plan.withWritablePrefix(
            KernixProtonPrefixV49126.prepareDefault(base))
            .prefixServerCommand(serverLog);
        assertEquals(nativeDir.resolve("libkernix_p11_server.so").toString(),
            live.command().get(0));
        assertEquals(java.util.Arrays.asList("-f","-p","-d0"),
            live.command().subList(1,live.command().size()));
        assertEquals(bootCmd.environment().get("WINEPREFIX"),
            live.environment().get("WINEPREFIX"));
        assertEquals(bootCmd.environment().get("WINESERVER"),
            live.environment().get("WINESERVER"));
        assertFalse(live.environment().containsKey("WINELOADERNOEXEC"));
        assertFalse(live.environment().containsKey("LD_PRELOAD"));
        assertFalse(live.environment().containsKey("DISPLAY"));
        assertFalse(live.environment().containsKey("RM11_CHILD_LOADER_BRIDGE"));
        assertFalse(live.environment().containsKey("RM11_NATIVE_FREETYPE_DLOPEN_REDIRECT"));
        Path machineId=base.resolve("local-machine-id");
        Files.write(machineId,("0123456789abcdef0123456789abcdef"+"\n")
            .getBytes(StandardCharsets.US_ASCII));
        ProcessBuilder identityBound=plan.withWritablePrefix(
            KernixProtonPrefixV49126.prepareDefault(base))
            .prefixServerWithIdentity(serverLog,machineId);
        assertEquals(machineId.toString(),
            identityBound.environment().get("RM11_P11_MACHINE_ID_FILE"));
        assertEquals(nativeDir.resolve("librm11_wine_data_redirect.so").toString(),
            identityBound.environment().get("LD_PRELOAD"));
        assertFalse(identityBound.environment().containsKey("WINELOADERNOEXEC"));
        assertFalse(identityBound.environment().containsKey("RM11_CHILD_LOADER_BRIDGE"));
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
