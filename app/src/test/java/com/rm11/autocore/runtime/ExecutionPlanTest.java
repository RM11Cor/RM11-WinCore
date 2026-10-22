package com.rm11.autocore.runtime;

import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.Arrays;

public final class ExecutionPlanTest {
    private static void f(Path p) throws Exception {
        Files.createDirectories(p.getParent()); Files.write(p, new byte[]{1,2,3});
    }
    private static void nativeElf(Path p) throws Exception {
        Files.createDirectories(p.getParent()); byte[] a = new byte[20];
        a[0]=0x7f; a[1]='E'; a[2]='L'; a[3]='F'; a[4]=2; a[5]=1; a[18]=(byte)183;
        Files.write(p, a);
    }
    private static void ok(boolean condition, String info) {if (!condition) throw new AssertionError(info);}
    public static void main(String[] args) throws Exception {
        Path base=Files.createTempDirectory("rm11-53-test-");
        RuntimeLayout p=new RuntimeLayout(base,base.resolve("apk-native"));
        for(String name:Arrays.asList("usr/bin", "usr/lib", "usr/share", "usr/tmp", "home/xuser/.wine/drive_c/windows/system32", "home/xuser/.wine/dosdevices"))
            Files.createDirectories(p.imageFs.resolve(name));
        for(Path path:Arrays.asList(p.wineNls,p.wineRoot.resolve("bin/wine"),p.wineRoot.resolve("bin/wineserver"),p.unixNtdll(),p.fexArm64ec(),p.fexWow64(),p.winePrefix.resolve("system.reg"),p.winePrefix.resolve("user.reg"),p.winePrefixMarker())) f(path);
        nativeElf(p.nativeWineLauncher); nativeElf(p.nativeWineServer); nativeElf(p.nativeNtdll);
        Path exe=base.resolve("rm11-win32-smoke-v2420.exe");f(exe);
        WineExecutionPlan plan=WineExecutionPlan.forBundledSmokeExe(p,exe);
        ok(plan.wineCommand.get(1).equals(exe.toString()),"EXE argument mismatch");
        ok(plan.wineCommand.get(0).equals(p.nativeWineLauncher.toString()),"wrong launcher");
        ok(plan.environment.get("WINESERVER").equals(p.nativeWineServer.toString()),"server mismatch");
        ok(plan.environment.get("WINEPREFIX").equals(p.winePrefix.toString()),"old prefix path");
        ok(plan.environment.get("HODLL").equals("libwow64fex.dll"),"FEX missing");
        ok(plan.environment.get("XDG_DATA_DIRS").equals(p.wineShare.toString()),"NLS data dir mismatch");
        ok(plan.environment.get("WINE_DATADIR").equals(p.wineShare.resolve("wine").toString()),"WINE_DATADIR mismatch");
        ok(plan.serverCommand.contains("-f"),"foreground server absent");
        boolean rejected=false;
        try { WineExecutionPlan.forBundledSmokeExe(p,base.resolve("another.exe")); }
        catch (java.io.IOException expected) {rejected=true;}
        ok(rejected,"arbitrary EXE must be blocked");
        Files.delete(p.winePrefixMarker());
        rejected=false;
        try { WineExecutionPlan.forBundledSmokeExe(p,exe); }
        catch (IllegalStateException | java.io.IOException expected) {rejected=true;}
        ok(rejected,"uncommitted prefix should be blocked");
        System.out.println("PASS: unified Wine/FEX layout, WineServer prefix, paths, native boundary, bundled EXE only");
    }
}
