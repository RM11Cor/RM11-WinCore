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
        // Wine 11's native ntdll derives its Windows WINEDATADIR from its
        // actual dladdr() ELF location, not this inherited POSIX variable.
        // When ntdll lives in Android's signed native library directory, it
        // computes an invalid Windows data path. Supply the verified,
        // app-private Wine installation ELF path for a tightly scoped
        // LD_PRELOAD dladdr override in this embedded GUI pilot ONLY.
        Path unixNtdll = p.unixNtdll();
        if (!Files.isRegularFile(unixNtdll, LinkOption.NOFOLLOW_LINKS)
                || !Files.isReadable(unixNtdll) || Files.size(unixNtdll) < 4096)
            throw new IOException("RM11_EMBEDDED_GUI_UNIX_NTDLL_LAYOUT_MISSING");
        env.put("RM11_WINE_NTDLL_VIRTUAL_PATH", unixNtdll.toString());
        env.put("RM11_NATIVE_WIN32U_DLL_REDIRECT", "1");
        // v2.9.3: same byte-identical Wine X11 native driver now resides in
        // Android signed native libs, rather than an executable ELF in
        // writable ImageFs (blocked by Android native loader restrictions).
        // Keep external X11 and console plans completely unchanged.
        Path signedX11 = p.apkNativeLibs.resolve("libwine_winex11.so");
        if (!Files.isRegularFile(signedX11, LinkOption.NOFOLLOW_LINKS)
                || !Files.isReadable(signedX11) || Files.size(signedX11) < 50000)
            throw new IOException("RM11_EMBEDDED_GUI_SIGNED_NATIVE_WINEX11_MISSING");
        env.put("RM11_NATIVE_WINEX11_DLOPEN_REDIRECT", "1");
        // v2.9.8: Wine GUI successfully paints the standard MessageBox frame
        // but its text/glyphs are blank. Upstream win32u/freetype.c dynamically
        // opens SONAME_LIBFREETYPE, which previously logged as absent.
        // Use the pinned upstream FreeType compiled by Android NDK with only core TTF support; its signed native
        // ELF has no external optional font-compression dependency closure.
        Path signedFreeType = p.apkNativeLibs.resolve("librm11_freetype_core.so");
        if (!Files.isRegularFile(signedFreeType, LinkOption.NOFOLLOW_LINKS)
                || !Files.isReadable(signedFreeType) || Files.size(signedFreeType) < 100000)
            throw new IOException("RM11_V301_SIGNED_NDK_FREETYPE_CORE_NOT_PACKAGED");
        // v2.9.9: the v2.9.8 device log shows wineserver itself aborting
        // ("wineserver crashed") before the GUI entry, exit 127. Do NOT
        // expose new FreeType hooks to Wine's privileged IPC server or the
        // prerequisite desktop process. Only the explicitly selected GUI
        // client receives an opt-in in ExternalExeRunner, and a bounded
        // fail-closed restore uses this unchanged "0" baseline.
        env.put("RM11_NATIVE_FREETYPE_DLOPEN_REDIRECT", "0");
        // v2.8.5: +loaddll floods the 11-KB offline journal and hides the
        // crash tail. Keep exception/displays warnings without module chatter.
        // Avoid +seh debug exceptions drowning the Wine session bootstrap
        // evidence; explicitly capture NtCreateUserProcess, explorer and
        // graphical-driver registration in this one embedded GUI pilot.
        env.put("WINEDEBUG", "+err,+warn,+process,+driver,+x11drv");
        return new WineExecutionPlan(baseline.serverCommand, baseline.wineCommand,
                env, baseline.workingDirectory);
    }

    /**
     * v3.0.3: first-class embedded graphical desktop process plan.
     * Start the genuine Wine file manager (winefile.exe) in RM11's private
     * Wine prefix. This is not a user-supplied EXE pilot, and never needs
     * Android's file picker or a fake/blank diagnostic Windows dialog.
     *
     * Keep the already device-proven v2.9.7 native NTDLL, signed X11 UnixLib,
     * child re-exec and GDI bridge configuration. FreeType's experimental
     * redirect defaults OFF because the 2026-10-24 device tests associated
     * enabling it with wineserver IPC failure. Glyphs can still be blank.
     */
    public static WineExecutionPlan forEmbeddedGraphicalDesktop(RuntimeLayout p)
            throws IOException {
        RuntimeAssessment.inspect(p).requireReady();
        NativeProcessPolicy.requireApkNativeEntrypoint(p, p.nativeWineServer);
        NativeProcessPolicy.requireApkNativeEntrypoint(p, p.nativeWineLauncher);
        Path winefile=p.wineDllRoot.resolve("aarch64-windows/winefile.exe");
        Path explorer=p.wineDllRoot.resolve("aarch64-windows/explorer.exe");
        Path ntdll=p.unixNtdll();
        Path info=p.wineShare.resolve("wine/wine.inf");
        Path nativeX11=p.apkNativeLibs.resolve("libwine_winex11.so");
        Path nativeWin32u=p.apkNativeLibs.resolve("libwine_win32u.so");
        for(Path required:new Path[]{winefile,explorer,ntdll,info,nativeX11,nativeWin32u}) {
            if(!Files.isRegularFile(required,LinkOption.NOFOLLOW_LINKS) ||
                !Files.isReadable(required) || Files.size(required)<4096)
                throw new IOException("RM11_V303_BUNDLED_DESKTOP_COMPONENT_MISSING: "
                        +required.getFileName());
        }
        Path trusted=p.appFiles.toRealPath();
        if(!winefile.toRealPath().startsWith(trusted) ||
           !explorer.toRealPath().startsWith(trusted) ||
           !ntdll.toRealPath().startsWith(trusted) ||
           !Files.isRegularFile(p.winePrefixMarker(),LinkOption.NOFOLLOW_LINKS))
            throw new IOException("RM11_V303_UNTRUSTED_DESKTOP_OR_PREFIX");
        try(java.io.InputStream input=Files.newInputStream(winefile)) {
            if(input.read()!='M' || input.read()!='Z')
                throw new IOException("RM11_V303_WINEFILE_NOT_PE");
        }
        Map<String,String> env=new LinkedHashMap<>(BionicLaunchEnvironment.forFex(p));
        env.put("DISPLAY",WineX11EndpointProbe.EMBEDDED_DISPLAY);
        env.put("LD_LIBRARY_PATH",p.apkNativeLibs+":"+env.get("LD_LIBRARY_PATH"));
        env.put("WINEDATADIR",info.getParent().toString());
        env.put("RM11_WINE_NTDLL_VIRTUAL_PATH",ntdll.toString());
        env.put("RM11_NATIVE_WIN32U_DLL_REDIRECT","1");
        env.put("RM11_NATIVE_WINEX11_DLOPEN_REDIRECT","1");
        env.put("RM11_NATIVE_FREETYPE_DLOPEN_REDIRECT","0");
        env.put("WINELOADERNOEXEC","1");
        env.put("RM11_CHILD_LOADER_BRIDGE","1");
        env.put("RM11_WS2_UNIXLIB_REDIRECT","1");
        env.put("WINESERVER",p.nativeWineServer.toString());
        env.put("WINEPREFIX",p.winePrefix.toString());
        env.put("WINEDEBUG","+err,+warn,+process,+driver,+x11drv");
        return new WineExecutionPlan(
            java.util.Arrays.asList(p.nativeWineServer.toString(),"-f","-d1","-p"),
            java.util.Arrays.asList(p.nativeWineLauncher.toString(),winefile.toString()),
            env,p.appFiles);
    }

    /**
     * v2.9.5 bounded, GUI-opt-in bootstrapping of Wine's actual desktop
     * initialization process. Wine's win32u/driver.c load_desktop_driver()
     * requires explorer's desktop driver registry handshake; just bundling
     * winex11.so cannot initialize display when explorer fails to spawn.
     *
     * Invoke with the same already verified APK-native Wine loader and
     * embedded DISPLAY environment; do not replace Windows prefix explorer
     * or touch registry/saved games. This is a diagnostic fallback candidate,
     * not a guarantee of visible rendering on an X11 core-only server.
     */
    public static List<String> trustedEmbeddedExplorerCommand(RuntimeLayout p)
            throws IOException {
        RuntimeAssessment.inspect(p).requireReady();
        NativeProcessPolicy.requireApkNativeEntrypoint(p,p.nativeWineLauncher);
        Path realWineExplorer = p.wineDllRoot.resolve("aarch64-windows/explorer.exe");
        if (!Files.isRegularFile(realWineExplorer,LinkOption.NOFOLLOW_LINKS)
                || !Files.isReadable(realWineExplorer)
                || Files.size(realWineExplorer) < 100000)
            throw new IOException("RM11_V295_TRUSTED_WINE_EXPLORER_BUILTIN_MISSING");
        // /desktop uses the Wine-native desktop/window-manager startup path
        // rather than opening a Windows file browser in user's prefix.
        return java.util.Arrays.asList(p.nativeWineLauncher.toString(),
                realWineExplorer.toString(), "/desktop=RM11,1024x600");
    }

    /**
     * Match the desktop's logical geometry to the foreground Android X11
     * viewport instead of forcing the legacy diagnostic 1024x600 canvas.
     */
    public static List<String> trustedEmbeddedExplorerCommand(RuntimeLayout p,
                                                                int width,int height)
            throws IOException {
        if(width<320||width>8192||height<240||height>8192)
            throw new IOException("RM11_V303_INVALID_SCREEN_GEOMETRY");
        List<String> original=trustedEmbeddedExplorerCommand(p);
        return java.util.Arrays.asList(original.get(0),original.get(1),
                "/desktop=RM11,"+width+"x"+height);
    }

    /**
     * v4.0.51: launch the genuine Wine SHELL, not winefile.exe, and not the
     * old Android imitation desktop. Wine's 'shell' desktop mode includes
     * explorer's Start/menu/taskbar. Geometry follows the verified X11 root.
     * Win32 glyph rendering remains device-unverified.
     */
    public static List<String> trustedEmbeddedShellDesktopCommand(
            RuntimeLayout p,int width,int height) throws IOException {
        if(width<320 || width>8192 || height<240 || height>8192)
            throw new IOException("RM11_V451_UNSAFE_DESKTOP_GEOMETRY");
        List<String> explorer=trustedEmbeddedExplorerCommand(p);
        return java.util.Arrays.asList(explorer.get(0),explorer.get(1),
                "/desktop=shell,"+width+"x"+height);
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
