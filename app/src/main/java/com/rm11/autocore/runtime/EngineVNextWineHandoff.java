package com.rm11.autocore.runtime;

import android.content.Context;
import com.rm11.autocore.engine.EngineOwnedProcessSession;
import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

/**
 * A single, source-integrated handoff of the existing Wine/FEX/X11 game plan
 * to the app-owned native Wine session supervisor.
 *
 * CRITICAL: Signed engine manifest activation is still OFF. This must not
 * silently replace the stable direct launcher before Bionic + Vulkan display
 * proof on the actual phone. It is intentionally not called by legacy UI.
 */
public final class EngineVNextWineHandoff {
    private EngineVNextWineHandoff(){}

    public static EngineOwnedProcessSession.OwnedProcess launch(
            Context context,Path selectedExe,boolean authorized,
            EngineOwnedProcessSession session)throws IOException {
        if(context==null||session==null||selectedExe==null)
            throw new IOException("ENGINE_VNEXT_LAUNCH_INPUT_MISSING");

        // First verify the actual APK-owned native files. No Wine actions,
        // prefix mutation, driver switches or process start before this gate.
        EngineVNextNativeManifestGate.Verified verified=
                EngineVNextNativeManifestGate.inspect(context);
        EngineVNextNativeManifestGate.requireActivation(verified);

        // This is the EXACT builder used by the old direct game start,
        // including DISPLAY, WINEPREFIX, FEX, abort preloads and graphics
        // flags, but no process has been created by prepare().
        NovaWineExeLauncher.PreparedGame prepared=
                NovaWineExeLauncher.prepare(context,selectedExe,authorized,false);
        List<String> command=prepared.builder.command();
        if(command==null||command.size()<2)
            throw new IOException("ENGINE_VNEXT_WINE_PLAN_EMPTY");
        Path expectedLoader=verified.signedNativeDirectory.resolve("libwineprobe.so")
                .toRealPath();
        Path plannedLoader=Path.of(command.get(0)).toRealPath();
        if(!expectedLoader.equals(plannedLoader))
            throw new IOException("ENGINE_VNEXT_LOADER_PLAN_MISMATCH");
        java.io.File cwd=prepared.builder.directory();
        if(cwd==null||!cwd.isDirectory())
            throw new IOException("ENGINE_VNEXT_MISSING_GAME_WORKDIR");
        Map<String,String> environment=prepared.builder.environment();
        if(!WineX11EndpointProbe.EMBEDDED_DISPLAY.equals(environment.get("DISPLAY"))
                ||environment.get("WINEPREFIX")==null)
            throw new IOException("ENGINE_VNEXT_WINE_ENVIRONMENT_INCOMPLETE");
        // startSupervisedWine strips guest LD_PRELOAD and LD_LIBRARY_PATH
        // from the supervisor and restores them only after fork(), before
        // Wine execv(). No child PID nor user path is exported to diagnostics.
        EngineOwnedProcessSession.OwnedProcess child=session.startSupervisedWine(
                verified.signedNativeDirectory,command.subList(1,command.size()),
                cwd.toPath(),environment,verified.supervisorSha256,
                verified.wineLoaderSha256);
        prepared.recordStarted(context,child.alive());
        return child;
    }
}
