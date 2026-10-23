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
        env.put("WINEPREFIX", p.winePrefix.toString());
        // This is a tested *layout contract*, not a claim that the Bionic sysroot exists.
        return new WineExecutionPlan(
                java.util.Arrays.asList(p.nativeWineServer.toString(), "-f", "-d1", "-p"),
                java.util.Arrays.asList(p.nativeWineLauncher.toString(), safeExe.toString()),
                env, p.appFiles);
    }
}
