package com.rm11.autocore.runtime;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** One coherent process plan for RM11's pinned, APK-native Wine ARM64EC smoke path.
 * This DOES NOT implement Wine child re-exec, X11, or the complete Bionic imagefs.
 */
public final class WineExecutionPlan {
    public final List<String> serverCommand;
    public final List<String> wineCommand;
    public final Map<String, String> environment;
    public final Path workingDirectory;

    private WineExecutionPlan(List<String> server, List<String> wine,
                              Map<String, String> env, Path cwd) {
        serverCommand = Collections.unmodifiableList(new ArrayList<>(server));
        wineCommand = Collections.unmodifiableList(new ArrayList<>(wine));
        environment = Collections.unmodifiableMap(new LinkedHashMap<>(env));
        workingDirectory = cwd;
    }

    public static WineExecutionPlan forBundledSmokeExe(RuntimeLayout p, Path exe) throws IOException {
        return forBundledSmokeExe(p, exe, false);
    }

    /** Separate opt-in Wine child re-exec experiment. Baseline remains unchanged. */
    public static WineExecutionPlan forBundledSmokeExeWithChildBridge(RuntimeLayout p,
                                                                      Path exe) throws IOException {
        return forBundledSmokeExe(p, exe, true);
    }

    /**
     * User-authorized standalone PE64 pilot. The source is a bounded temporary
     * app-private copy made by Android SAF, not a game folder or original file.
     * Child re-exec and pinned ws2_32 UnixLib remain diagnostic opt-ins.
     */
    public static WineExecutionPlan forSmallUserSelectedExe(RuntimeLayout p, Path exe)
            throws IOException {
        return forSmallUserSelectedExe(p, exe, false);
    }

    /** Enables bounded import-loader diagnostics only for a selected GUI EXE. */
    public static WineExecutionPlan forSmallUserSelectedGuiExe(RuntimeLayout p, Path exe)
            throws IOException {
        return forSmallUserSelectedExe(p, exe, true);
    }

    /**
     * Explicit one-shot opt-in only: direct a small user-selected PE64 to a
     * separately running TCP X11 display on this device (127.0.0.1:0).
     * Endpoint acceptance is checked in ExternalExeRunner before this plan.
     * This plan does NOT start an X server or embed it in Android.
     */
    public static WineExecutionPlan forSmallUserSelectedGuiExeWithLocalX11(RuntimeLayout p,
                                                                           Path exe)
            throws IOException {
        WineExecutionPlan baseline=forSmallUserSelectedExe(p, exe, true);
        Map<String,String> env=new LinkedHashMap<>(baseline.environment);
        env.put("DISPLAY",WineX11EndpointProbe.DISPLAY);
        // v2.8.1: Signed APK ships the verified ARM64/Bionic X11 client ELF
        // closure under nativeLibraryDir. This MUST precede the legacy
        // Termux RUNPATH compiled into the pinned winex11.so Wine module.
        env.put("LD_LIBRARY_PATH", p.apkNativeLibs.toString() + ":" +
                baseline.environment.get("LD_LIBRARY_PATH"));
        // Focus on X11 driver diagnostics instead of gigantic +module trace.
        // Console baseline and the non-X11 GUI diagnostic remain unchanged.
        env.put("WINEDEBUG", "+err,+warn,+seh,+x11drv");
        return new WineExecutionPlan(baseline.serverCommand,baseline.wineCommand,env,
                baseline.workingDirectory);
    }

    /**
     * Embedded X11 View inside RM11 owns loopback display :2.
     * This keeps the pinned Wine/FEX process plan and Bionic ELF libraries.
     * No XSDL external app, no separate Android split screen, no root access.
     */
    public static WineExecutionPlan forSmallUserSelectedGuiExeWithEmbeddedX11(RuntimeLayout p,
                                                                               Path exe)
            throws IOException {
        WineExecutionPlan baseline = forSmallUserSelectedGuiExeWithLocalX11(p, exe);
        Map<String,String> env = new LinkedHashMap<>(baseline.environment);
        env.put("DISPLAY", WineX11EndpointProbe.EMBEDDED_DISPLAY);
        // Verified against Wine's programs/wineboot/wineboot.c:
        // get_wine_inf_path() requires WINEDATADIR, not WINE_DATADIR.
        // Configure ONLY the opt-in embedded GUI run, preserving the proven
        // no-DISPLAY console baseline and earlier external-XSDL diagnostics.
        Path wineInf = p.wineShare.resolve("wine/wine.inf");
        if (!Files.isRegularFile(wineInf, LinkOption.NOFOLLOW_LINKS)
                || !Files.isReadable(wineInf) || Files.size(wineInf) < 1024)
            throw new IOException("RM11_EMBEDDED_GUI_WINEDATADIR_WINE_INF_MISSING");
        env.put("WINEDATADIR", wineInf.getParent().toString());
        env.put("WINEDEBUG", "+err,+warn,+seh,+winediag,+x11drv,+loaddll");
        return new WineExecutionPlan(baseline.serverCommand, baseline.wineCommand,
                env, baseline.workingDirectory);
    }

    private static WineExecutionPlan forSmallUserSelectedExe(RuntimeLayout p, Path exe,
                                                             boolean guiDiagnostics)
            throws IOException {
        RuntimeAssessment.inspect(p).requireReady();
        NativeProcessPolicy.requireApkNativeEntrypoint(p, p.nativeWineServer);
        NativeProcessPolicy.requireApkNativeEntrypoint(p, p.nativeWineLauncher);
        ExternalExePilotPolicy.validate(p, exe);
        if (!Files.isDirectory(p.winePrefix.resolve("drive_c/windows/system32"))
                || !Files.isRegularFile(p.winePrefixMarker()))
            throw new IOException("Committed Wine Windows prefix unavailable");
        Map<String, String> env = new LinkedHashMap<>(BionicLaunchEnvironment.forFex(p));
        env.put("WINELOADERNOEXEC", "1");
        env.put("RM11_CHILD_LOADER_BRIDGE", "1");
        env.put("RM11_WS2_UNIXLIB_REDIRECT", "1");
        env.put("WINEDEBUG", guiDiagnostics ? "+err,+warn,+seh,+process,+module"
                : "+err,+warn,+seh,+process");
        env.put("WINESERVER", p.nativeWineServer.toString());
        env.put("WINEPREFIX", p.winePrefix.toString());
        return new WineExecutionPlan(
                java.util.Arrays.asList(p.nativeWineServer.toString(), "-f", "-d1", "-p"),
                java.util.Arrays.asList(p.nativeWineLauncher.toString(), exe.toString()),
                env, p.appFiles);
    }

    private static WineExecutionPlan forBundledSmokeExe(RuntimeLayout p, Path exe,
                                                       boolean childBridge) throws IOException {
        RuntimeAssessment.inspect(p).requireReady();
        NativeProcessPolicy.requireApkNativeEntrypoint(p, p.nativeWineServer);
        NativeProcessPolicy.requireApkNativeEntrypoint(p, p.nativeWineLauncher);
        Path safeExe = p.appFiles.resolve("rm11-win32-smoke-v2420.exe").normalize();
        if (!exe.toAbsolutePath().normalize().equals(safeExe)
                || Files.isSymbolicLink(exe) || !Files.isRegularFile(exe, LinkOption.NOFOLLOW_LINKS))
            throw new IOException("Only verified RM11 bundled smoke EXE may run at this stage");
        if (!Files.isDirectory(p.winePrefix.resolve("drive_c/windows/system32"))
                || !Files.isRegularFile(p.winePrefixMarker()))
            throw new IOException("Committed Windows prefix unavailable");
        Map<String, String> env = new LinkedHashMap<>(BionicLaunchEnvironment.forFex(p));
        // The APK-hosted diagnostic bridge cannot re-exec <nativeLibraryDir>/wine.
        // Limited to the bundled smoke executable; DO NOT apply to a future game launcher.
        env.put("WINELOADERNOEXEC", "1");
        env.put("WINEDEBUG", "+err,+warn,+seh,+process,+module");
        env.put("WINESERVER", p.nativeWineServer.toString());
        if (childBridge) {
            // Only the dedicated Wineboot diagnostic activates native execv
            // translation. Do not use it with unknown game executables.
            env.put("RM11_CHILD_LOADER_BRIDGE", "1");
            env.put("RM11_WS2_UNIXLIB_REDIRECT", "1");
        }
        env.put("WINEPREFIX", p.winePrefix.toString());
        // This is a tested *layout contract*, not a claim that the Bionic sysroot exists.
        return new WineExecutionPlan(
                java.util.Arrays.asList(p.nativeWineServer.toString(), "-f", "-d1", "-p"),
                java.util.Arrays.asList(p.nativeWineLauncher.toString(), safeExe.toString()),
                env, p.appFiles);
    }
}
