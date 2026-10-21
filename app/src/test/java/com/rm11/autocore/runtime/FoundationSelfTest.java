package com.rm11.autocore.runtime;

import java.nio.file.*;
import java.util.Map;

/** Host-side deterministic preflight checks. Does NOT run Wine or Android. */
public final class FoundationSelfTest {
    private static void check(boolean v, String message) { if (!v) throw new AssertionError(message); }
    private static void stubAarch64(Path p) throws Exception {
        Files.createDirectories(p.getParent());
        byte[] h=new byte[20]; h[0]=0x7f; h[1]='E'; h[2]='L'; h[3]='F'; h[4]=2; h[5]=1; h[18]=(byte)183;
        Files.write(p,h);
    }
    private static void file(Path p) throws Exception { Files.createDirectories(p.getParent()); Files.write(p, new byte[]{1}); }
    public static void main(String[] args) throws Exception {
        Path temp=Files.createTempDirectory("rm11-host-check-");
        RuntimeLayout l=new RuntimeLayout(temp.resolve("files"), temp.resolve("native"));
        check(RuntimeAssessment.inspect(l).state()==RuntimeAssessment.State.BLOCKED, "Empty imagefs must block");
        for (String folder : new String[]{"usr/bin","usr/lib","usr/share","usr/tmp"})
            Files.createDirectories(l.imageFs.resolve(folder));
        file(l.wineNls);file(l.wineRoot.resolve("bin/wine"));file(l.wineRoot.resolve("bin/wineserver"));
        file(l.unixNtdll());file(l.fexArm64ec());file(l.fexWow64());
        stubAarch64(l.nativeWineLauncher);stubAarch64(l.nativeWineServer);stubAarch64(l.nativeNtdll);
        Path staging=temp.resolve("prepared");
        file(staging.resolve("system.reg"));file(staging.resolve("user.reg"));
        Files.createDirectories(staging.resolve("drive_c/windows/system32"));
        Files.createDirectories(staging.resolve("dosdevices"));
        PrefixInstaller.installPreparedPrefix(staging, l, "bionic-arm64ec-fex-v1");
        check(RuntimeAssessment.inspect(l).state()==RuntimeAssessment.State.STRUCTURALLY_READY,"Prepared valid runtime passes structural preflight");
        NativeProcessPolicy.requireApkNativeEntrypoint(l, l.nativeWineLauncher);
        boolean noexecDenied=false;
        try { NativeProcessPolicy.requireApkNativeEntrypoint(l,l.wineRoot.resolve("bin/wine")); }
        catch (java.io.IOException e) { noexecDenied=e.getMessage().contains("Execution denied"); }
        check(noexecDenied,"No direct exec from writable imagefs");
        Map<String,String> vars=BionicLaunchEnvironment.forFex(l);
        check("libwow64fex.dll".equals(vars.get("HODLL")),"FEX selected");
        check(vars.get("WINEPREFIX").equals(l.winePrefix.toString()),"Prefix path consistent");
        check(!vars.containsKey("WINELOADERNOEXEC"),"Must not bypass Wine loader blindly");
        boolean preserved=false;
        try { PrefixInstaller.installPreparedPrefix(staging,l,"another"); }
        catch (java.io.IOException e) { preserved=e.getMessage().contains("Existing prefix preserved"); }
        check(preserved,"Existing user data not overwritten");
        // Unsafe prefix symlinks are rejected instead of following paths outside the app.
        Path malicious = temp.resolve("malicious");
        file(malicious.resolve("system.reg"));file(malicious.resolve("user.reg"));
        Files.createDirectories(malicious.resolve("drive_c/windows/system32"));
        Files.createDirectories(malicious.resolve("dosdevices"));
        Files.createSymbolicLink(malicious.resolve("dosdevices/x:"), Paths.get("/etc"));
        RuntimeLayout other = new RuntimeLayout(temp.resolve("second-files"), temp.resolve("second-native"));
        boolean rejected=false;
        try { PrefixInstaller.installPreparedPrefix(malicious, other, "unsafe"); }
        catch (java.io.IOException ex) { rejected=ex.getMessage().contains("Unsafe symlink"); }
        check(rejected, "Out-of-tree symlinks rejected");
        check(!Files.exists(other.winePrefix), "No incomplete user prefix published");
        Files.delete(l.wineNls);
        check(RuntimeAssessment.inspect(l).state()==RuntimeAssessment.State.BLOCKED,"Missing NLS blocks runtime");
        System.out.println("PASS: blocked incomplete imagefs; validates ARM64 ELF; atomic prefix; preserves user data; FEX environment; missing NLS blocks");
    }
}
