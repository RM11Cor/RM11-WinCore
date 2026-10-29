package com.rm11.autocore.runtime;

import android.content.Context;
import com.rm11.autocore.diagnostics.OfflineDiagnosticJournal;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.ByteArrayOutputStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * Launches a user-selected existing x86-64 Windows EXE with the ORIGINAL
 * RM11 Wine/FEX loader into the CURRENT embedded X11 session.
 *
 * Does not start a second wineserver, replace the Wine prefix, copy games,
 * silently install dependencies, or claim unsupported DXVK/graphics paths.
 */
public final class NovaWineExeLauncher {
    private NovaWineExeLauncher() {}
    public static final class Check {
        public final Path path;
        public final long bytes;
        Check(Path path,long bytes){this.path=path;this.bytes=bytes;}
    }
    public static Check validate(RuntimeLayout layout,Path selected,boolean phoneAuthorized)
            throws IOException {
        if(selected==null || Files.isSymbolicLink(selected))
            throw new IOException("EXE is missing or symbolic link is not allowed");
        if(!Files.isRegularFile(selected,LinkOption.NOFOLLOW_LINKS))
            throw new IOException("Only a regular EXE can be launched");
        Path actual=selected.toRealPath();
        Path c=layout.winePrefix.resolve("drive_c").toFile().getCanonicalFile().toPath();
        Path ext=android.os.Environment.getExternalStorageDirectory()
                .getCanonicalFile().toPath();
        boolean inC=actual.startsWith(c);
        boolean inPhone=phoneAuthorized&&actual.startsWith(ext);
        if(!inC&&!inPhone)
            throw new IOException("EXE must be under Wine C: or authorized Android D:");
        String name=actual.getFileName().toString();
        if(!name.toLowerCase(java.util.Locale.ROOT).endsWith(".exe"))
            throw new IOException("Only .exe is supported in this stage");
        long n=Files.size(actual);
        if(n<512)throw new IOException("Windows executable is incomplete");
        try(java.io.RandomAccessFile f=new java.io.RandomAccessFile(actual.toFile(),"r")){
            if(f.readUnsignedByte()!=0x4d||f.readUnsignedByte()!=0x5a)
                throw new IOException("Not a Windows MZ executable");
            f.seek(0x3c);
            long peOffset=Integer.toUnsignedLong(Integer.reverseBytes(f.readInt()));
            if(peOffset<0x40||peOffset>4096||peOffset+26>n)
                throw new IOException("Invalid PE header offset");
            f.seek(peOffset);
            if(f.readUnsignedByte()!=0x50||f.readUnsignedByte()!=0x45||
                    f.readUnsignedByte()!=0||f.readUnsignedByte()!=0)
                throw new IOException("Invalid Windows PE signature");
            int machine=Short.toUnsignedInt(Short.reverseBytes(f.readShort()));
            if(machine!=0x8664)
                throw new IOException("This RM11 Wine runner requires x86-64 PE; PE32 and ARM PE unsupported");
            f.seek(peOffset+24);
            int opt=Short.toUnsignedInt(Short.reverseBytes(f.readShort()));
            if(opt!=0x20b)throw new IOException("Expected PE32+ x86-64 Windows EXE");
        }
        return new Check(actual,n);
    }

    /** Reuse the installed Wine loader and environment of the *running*
     * desktop, with an EXE path as an argv element (spaces are safe). */
    public static Process start(Context ctx,Path selected,boolean authorized)throws IOException {
        return start(ctx,selected,authorized,false);
    }

    /**
     * Optional single-process FreeType probe. Enable only for the published
     * SHA256-pinned 4096-byte Win64 dialog; no normal EXE or game changes.
     * Wineserver, Winefile, Explorer and other app processes remain baseline.
     */
    /**
     * One common fully validated plan for legacy Wine and future supervised
     * Wine launches. Do not duplicate X11/FEX/WinED3D/driver configuration.
     */
    public static final class PreparedGame {
        public final ProcessBuilder builder;
        private final Check check;
        private final Path diagnostics;
        private final NativeDriverIsolationPolicy.Decision isolation;
        private final String privateWsi;
        private final String d3dRoute;
        private final boolean probeFontRepair;
        private PreparedGame(ProcessBuilder builder,Check check,Path diagnostics,
                NativeDriverIsolationPolicy.Decision isolation,String privateWsi,
                String d3dRoute,boolean probeFontRepair){
            this.builder=builder;this.check=check;this.diagnostics=diagnostics;
            this.isolation=isolation;this.privateWsi=privateWsi;
            this.d3dRoute=d3dRoute;this.probeFontRepair=probeFontRepair;
        }
        /** Apply journal + one-shot policy only after a real process starts. */
        public void recordStarted(Context ctx,boolean processAlive) {

        if(isolation.isolate) {
            boolean consumed=NativeDriverIsolationPolicy.commitOnce(
                    diagnostics,isolation);
            OfflineDiagnosticJournal.record(ctx,"v470-actionable-seh-capture",
                    "RM11_V470_DRIVER_ISOLATION=ONE_RETEST\n"
                    +"RM11_V470_VULKAN_FALLBACK=OFF\n"
                    +"RM11_V470_PRIOR_FATAL_PC=00006ffeb1d0d0\n"
                    +"RM11_V470_PRIOR_PC_CLASS=ANONYMOUS_EXECUTABLE\n"
                    +"RM11_V470_EVIDENCE_TIMESTAMP="+isolation.sourceTimestamp+"\n"
                    +"RM11_V470_CONSUMED_MARKER_WRITTEN="+consumed+"\n"
                    +"RM11_V470_NO_ANDROID_GPU_DRIVER_MODIFICATION=true");
        }
        OfflineDiagnosticJournal.record(ctx,"v434-exe-start",
                "RM11_V434_DIRECT_EXE_PROCESS_STARTED\n"
                +"RM11_V434_PROCESS_ALIVE_UNVERIFIED_WINDOW\n"
                +"RM11_V438_FREETYPE_PROBE="+(probeFontRepair?"KNOWN_EXE_ISOLATED":"OFF")+"\n"
                +"RM11_V438_NO_WINESERVER_FONT_CHANGE=true\n"
                +"Path="+check.path+"\n"
                +"Size="+check.bytes+"\n"
                +"ProcessCreated="+(processAlive?"YES":"EXITED_BEFORE_PROBE")+"\n"
                +"RM11_V470_VULKAN_FALLBACK="+(isolation.isolate?"OFF_ONCE":"BASELINE_ON")+"\n"
                +"RM11_V479_PRIVATE_GAME_WSI="+privateWsi+"\n"
                +"RM11_V481_WINED3D_ROUTE="+d3dRoute);
        }
    }

    public static PreparedGame prepare(Context ctx,Path selected,
                  boolean authorized,boolean probeFontRepair)throws IOException {
        RuntimeLayout layout=new RuntimeLayout(ctx.getFilesDir().toPath(),
                new File(ctx.getApplicationInfo().nativeLibraryDir).toPath());
        Check check=validate(layout,selected,authorized);
        if(probeFontRepair){
            // Do not allow stale shortcuts or a direct Activity call to
            // bypass the safety rollback after the wineserver crash.
            if(!NovaGuiStabilityPolicy.allowManualExeFontProbe())
                throw new IOException("RM11_V439_FREETYPE_TRIAL_DISABLED_AFTER_SERVER_CRASH");
            NovaFontProbePolicy.requireKnownSignedProbe(check.path,layout);
        }
        // A running X11 server is required; a process launch alone is not
        // proof that a Windows window was created.
        WineX11EndpointProbe.Result x11=WineX11EndpointProbe.probeEmbeddedDisplay2();
        if(!x11.accepted)throw new IOException("RM11 embedded X11 is not connected");
        WineExecutionPlan envPlan=WineExecutionPlan.forEmbeddedGraphicalDesktop(layout);
        List<String> command=new ArrayList<>(envPlan.wineCommand);
        command.set(command.size()-1,check.path.toString());
        // CarX Street's documented Windows launch line includes -force-d3d11.
        // v482-484 device runs launched the selected CarX Street Launcher.exe
        // without it. This is strictly basename-gated; all other games retain
        // their existing arguments and the current verified Wine/WSI path.
        List<String> gameArgs=GameLaunchFlagsV485.argumentsFor(
                check.path.getFileName().toString());
        command.addAll(gameArgs);
        OfflineDiagnosticJournal.record(ctx,"v485-game-launch-args",
                "RM11_V485_SELECTED_EXE="+check.path.getFileName()+"\n"
                +"RM11_V485_CARX_D3D11_FLAG="+
                  (gameArgs.isEmpty()?"NOT_APPLICABLE":"-force-d3d11")+"\n"
                +"RM11_V485_ARGUMENT_COUNT="+gameArgs.size()+"\n"
                +"RM11_V485_OTHER_GAMES_UNMODIFIED=true");
        ProcessBuilder builder=new ProcessBuilder(command);
        builder.directory(check.path.getParent().toFile());
        Map<String,String> environment=builder.environment();
        environment.putAll(envPlan.environment);
        // Scoped to the explicitly selected game's Wine process only.
        // The basic and Fiber SEH probes passed on the physical device;
        // gather the FIRST real game exception/unwind before the large native
        // log tail rolls over. The bounded streaming journal is in the runner.
        // v486: game-only Wine process and DLL-load trace distinguishes
        // the original selected PE startup from a native Wine loader that
        // remains alive while fonts, security modules or services initialize.
        // The bounded streaming recorder preserves the *first* boot lines.
        environment.put("WINEDEBUG","+err,+warn,+seh,+unwind,+process,+loaddll");
        // DXVK writes game-specific *_d3d11.log / *_dxgi.log only if DXVK
        // really loads; keep them inside the exported offline diagnostics.
        // No DLL injection, graphics backend switch, or prefix mutation.
        try {
            Files.createDirectories(diagnosticsPathV49011(ctx));
            environment.put("DXVK_LOG_PATH",diagnosticsPathV49011(ctx).toString());
            environment.put("DXVK_LOG_LEVEL","info");
        } catch (IOException ignored) {
            // Diagnostics must never prevent the selected EXE from launching.
        }
        OfflineDiagnosticJournal.record(ctx,"v49011-dxvk-log-capture",
                "RM11_V49011_DXVK_LOG_CAPTURE=REQUESTED_NOT_PROOF\n"
                +"RM11_V49011_DXVK_LOG_DEST=offline-diagnostics\n"
                +"RM11_V49011_DXVK_DLL_INJECTION=false");
        // Scoped to the selected game only. Wine may request the Linux
        // SONAME libvulkan.so.1, absent from Android Bionic, whose native
        // Vulkan loader is libvulkan.so. The signed Wine launcher interposer
        // tries that fallback only if the original dlopen failed.
        // The device proved a native abort() from Adreno's proprietary
        // libllvm-glnext.so. A single targeted comparison is permitted
        // ONLY for Silksong and ONLY once per matching saved crash event.
        // This disables our nonstandard libvulkan.so.1 -> Android-loader
        // fallback, not Vulkan elsewhere on the device or in Wine/FEX.
        Path diagnostics=ctx.getFilesDir().toPath().resolve("offline-diagnostics");
        NativeDriverIsolationPolicy.Decision isolation=
                NativeDriverIsolationPolicy.evaluate(diagnostics,
                        check.path.getFileName().toString());
        // The exact miniature D3D11 smoke test previously aborted inside
        // Android's proprietary libllvm-glnext.so. Disable only our custom
        // dlopen(libvulkan.so.1)->Android loader fallback for this one test.
        // No effect on actual games, wineserver, X11, device drivers or GDI.
        boolean isolatedD3d11Smoke="RM11-D3D11-BLUE.exe".equalsIgnoreCase(
                check.path.getFileName().toString())
                || "RM11-D3D11-STAGE-PROOF.exe".equalsIgnoreCase(
                check.path.getFileName().toString());
        // v49019: runtime trace ONLY for two known miniature D3D11 tests.
        // Wine debug channels describe real loader calls (unlike ELF strings).
        // This does not activate DXVK, change Wine registry, or change GPU backend.
        if (isolatedD3d11Smoke) {
            environment.put("WINEDEBUG",
                    "+err,+warn,+seh,+unwind,+process,+loaddll,+d3d,+dxgi,+vulkan,+wgl");
            OfflineDiagnosticJournal.record(ctx,"v49019-mini-runtime-loader-trace",
                    "RM11_V49019_SELECTED_MINI_D3D11=true\n"
                    +"RM11_V49019_WINEDEBUG_D3D_DXGI_VULKAN_WGL=ON\n"
                    +"RM11_V49019_DXVK_ACTIVATION=UNCHANGED_OFF\n"
                    +"RM11_V49019_GPU_FALLBACK=OFF");
        }
        if (isolatedD3d11Smoke) {
            String dxvkMini=MiniDxvkRouteV49021.configure(ctx,environment,check.path);
            OfflineDiagnosticJournal.record(ctx,"v49021-mini-dxvk-activation",
                    "RM11_V49021_DXVK_MINI_ROUTE="+dxvkMini+"\\n"
                    +"RM11_V49021_OTHER_GAMES_UNCHANGED=true\\n"
                    +"RM11_V49021_HARDWARE_VULKAN_NOT_PROVEN=true");
        }
        if(isolatedD3d11Smoke && environment.containsKey("RM11_MINI_DXVK_STAGED_EXE")){
            Path privateExe=java.nio.file.Paths.get(environment.remove("RM11_MINI_DXVK_STAGED_EXE"));
            command.set(command.indexOf(check.path.toString()),privateExe.toString());
            builder.command(command);
            builder.directory(privateExe.getParent().toFile());
            OfflineDiagnosticJournal.record(ctx,"v49022-mini-app-local-dxvk",
                    "RM11_V49022_MINI_APP_LOCAL_DLLS=true\n"
                    +"RM11_V49022_ORIGINAL_GAME_FILES_UNCHANGED=true");
        }
        environment.put("RM11_V458_ANDROID_VULKAN_FALLBACK",
                (isolation.isolate||isolatedD3d11Smoke)?"0":"1");
        OfflineDiagnosticJournal.record(ctx,"v49012-d3d11-driver-isolation",
                "RM11_V49012_TARGET_MINI_D3D11="+isolatedD3d11Smoke+"\n"
                +"RM11_V49012_ANDROID_VULKAN_FALLBACK="+
                  ((isolation.isolate||isolatedD3d11Smoke)?"OFF":"BASELINE")+"\n"
                +"RM11_V49012_OTHER_GAMES_UNCHANGED=true");

        // Only the user-selected game's own child process receives private
        // Mesa+software WSI, and only when the signed v478 device proof exists.
        String privateWsi=WinePrivateWsiGameBridgeV479.configure(ctx,layout,environment);
        // Wine 11 has a per-process WineD3D Vulkan renderer. The signed
        // private Mesa loader alone was reached in v479, but WineD3D tried
        // libGL.so.1 and failed. Only this selected EXE, and only on device
        // proof that private X11 WSI works, may skip the missing GLX backend.
        String d3dRoute=WineD3dVulkanRouteV481.apply(privateWsi,environment);
        OfflineDiagnosticJournal.record(ctx,"v481-game-d3d-renderer",
                "RM11_V481_WINED3D_ROUTE="+d3dRoute+"\n"
                +"RM11_V481_RENDERER_ENV="+
                  ("ENABLED_PRIVATE_VULKAN".equals(d3dRoute)
                  ? "renderer=vulkan" : "BASELINE") + "\n"
                +"RM11_V481_WINESERVER_DESKTOP_INPUT_UNCHANGED=true");
        OfflineDiagnosticJournal.record(ctx,"v479-game-private-wsi",
                "RM11_V479_WSI_MODE="+privateWsi+"\n"
                +"RM11_V479_PRIVATE_LOADER_OPT_IN="+
                    ("ENABLED_GAME_ONLY_SW_WSI".equals(privateWsi))+"\n"
                +"RM11_V479_WINESERVER_DESKTOP_UNMODIFIED=true");
        // Isolated game-only native abort interceptor. Its sole purpose is
        // logging the original ELF caller of libc.abort() before SIGABRT
        // becomes EXCEPTION_WINE_ASSERTION. The existing Wine native shim
        // remains unmodified; no preload changes for wineserver or desktop.
        // v49023: activate native SONAME bridge ONLY for isolated mini D3D11
        // and ONLY when both signed native ELFs are present. This cannot
        // claim successful Vulkan instance, WSI, or presentation.
        Path miniVulkanBridge=layout.apkNativeLibs.resolve("librm11_v49023_mini_vulkan.so");
        Path miniAdreno=layout.apkNativeLibs.resolve("libadrenotools.so");
        Path miniTurnip=layout.apkNativeLibs.resolve("libvulkan_freedreno.so");
        boolean miniBridgeReady=isolatedD3d11Smoke
                &&Files.isRegularFile(miniVulkanBridge,LinkOption.NOFOLLOW_LINKS)
                &&Files.isRegularFile(miniAdreno,LinkOption.NOFOLLOW_LINKS)
                &&Files.isRegularFile(miniTurnip,LinkOption.NOFOLLOW_LINKS);
        if(miniBridgeReady){
            environment.put("RM11_V49023_MINI_VULKAN_BRIDGE","1");
            environment.put("RM11_V49024_MINI_LOADER_DIAGNOSTICS","1");
            // Only isolated D3D11 mini tests can use the instrumented
            // source-pinned AdrenoTools COPY; original stays installed.
            Path adoDiagnostic=layout.apkNativeLibs.resolve("librm11_adrenotools_probe_v49025.so");
            if(Files.isRegularFile(adoDiagnostic,LinkOption.NOFOLLOW_LINKS)
                    &&Files.size(adoDiagnostic)>4096)
                environment.put("RM11_V49025_DIAGNOSTIC_ADRENOTOOLS","1");
            environment.put("RM11_V49023_SIGNED_NATIVE_LIB_DIR",layout.apkNativeLibs.toString());
            String preload=environment.get("LD_PRELOAD");
            environment.put("LD_PRELOAD",miniVulkanBridge.toString()
                    +(preload==null||preload.isEmpty()?"":" "+preload));
        }
        OfflineDiagnosticJournal.record(ctx,"v49025-adrenotools-inner-trace",
                "RM11_V49025_MINI_ADRENOTOOLS_SOURCE_COPY="+
                    "1".equals(environment.get("RM11_V49025_DIAGNOSTIC_ADRENOTOOLS"))+"\\n"
                +"RM11_V49025_UPSTREAM_PIN=8fae8ce254dfc1344527e05301e43f37dea2df80\\n"
                +"RM11_V49025_ORIGINAL_ADRENOTOOLS_UNCHANGED=true");
        OfflineDiagnosticJournal.record(ctx,"v49024-turnip-stage-diagnostics",
                "RM11_V49024_MINI_DIAGNOSTICS="+miniBridgeReady+"\\n"
                +"RM11_V49024_NO_GAME_DRIVER_MODIFICATION=true\\n"
                +"RM11_V49024_FAIL_STAGE_CAPTURE_REQUESTED=true");
        OfflineDiagnosticJournal.record(ctx,"v49023-mini-vulkan-bridge",
                "RM11_V49023_MINI_BRIDGE_PRELOAD_REQUESTED="+miniBridgeReady+"\\n"
                +"RM11_V49023_FOR_OTHER_GAMES=OFF\\n"
                +"RM11_V49023_RUNTIME_GPU_INSTANCE_NOT_PROVEN=true");
        Path abortProbe=layout.apkNativeLibs.resolve("librm11_abort_caller_v465.so");
        if(!Files.isRegularFile(abortProbe,LinkOption.NOFOLLOW_LINKS)
                ||Files.size(abortProbe)<4096)
            throw new IOException("RM11_V465_SIGNED_ABORT_PROBE_MISSING");
        String existingPreload=environment.get("LD_PRELOAD");
        environment.put("LD_PRELOAD",abortProbe.toString()
                +(existingPreload==null||existingPreload.isEmpty()
                    ?"":" "+existingPreload));
        environment.put("RM11_V465_TRACE_ABORT_CALLER","1");
        environment.put("RM11_NATIVE_FREETYPE_DLOPEN_REDIRECT",
                probeFontRepair?"1":"0");
        // Leave the original Wine win32u and all other Wine clients untouched.
        environment.put("RM11_WIN32U_ISOLATED_FONTCLIENT","0");
        environment.put("RM11_NATIVE_FONTCONFIG_DLOPEN_REDIRECT","0");
        // Audit effective settings after all existing routing policies have run.
        // Presence of DLLs or an env flag is not proof of GPU presentation.
        OfflineDiagnosticJournal.record(ctx,"v49011-game-graphics-route",
                GameGraphicsRouteAuditV49011.snapshot(check.path,environment,
                        privateWsi,d3dRoute));
        builder.redirectErrorStream(true);
        // A ProcessBuilder file redirect persists output even when a Wine child
        // stalls or terminates before consumeAndWait can read its stdout pipe.
        // Restrict this to the two known mini tests; other games are unchanged.
        if (isolatedD3d11Smoke) {
            try {
                Path trace=diagnostics.resolve("last-mini-d3d11-wine-runtime.log");
                Files.createDirectories(trace.getParent());
                Files.deleteIfExists(trace);
                builder.redirectOutput(trace.toFile());
                OfflineDiagnosticJournal.record(ctx,"v49020-mini-log-persistence",
                        "RM11_V49020_MINI_STDOUT_STDERR_DIRECT_TO_FILE=true\\n"
                        +"RM11_V49020_MINI_TRACE_FILE=last-mini-d3d11-wine-runtime.log\\n"
                        +"RM11_V49020_OTHER_GAMES_UNCHANGED=true");
            } catch (IOException e) {
                OfflineDiagnosticJournal.record(ctx,"v49020-mini-log-persistence",
                        "RM11_V49020_MINI_TRACE_SETUP_FAILED="+e.getClass().getSimpleName());
            }
        }
        return new PreparedGame(builder,check,diagnostics,isolation,privateWsi,
                d3dRoute,probeFontRepair);
    }

    public static Process start(Context ctx,Path selected,boolean authorized,
                                boolean probeFontRepair)throws IOException {
        PreparedGame prepared=prepare(ctx,selected,authorized,probeFontRepair);
        Process process=prepared.builder.start();
        prepared.recordStarted(ctx,process.isAlive());
        return process;
    }

    private static Path diagnosticsPathV49011(Context ctx) {
        return ctx.getFilesDir().toPath().resolve("offline-diagnostics");
    }

    /** Drain native Wine/FEX output to avoid pipe deadlock. The log is capped
     * to 24 KiB even for very noisy games. */
    public static String consumeAndWait(Process process)throws IOException {
        ByteArrayOutputStream tail=new ByteArrayOutputStream();
        try(InputStream in=process.getInputStream()){
            byte[] buff=new byte[4096];
            int n;
            while((n=in.read(buff))!=-1){
                if(n<=0)continue;
                tail.write(buff,0,n);
                if(tail.size()>24576){
                    byte[] existing=tail.toByteArray();
                    tail.reset();
                    tail.write(existing,existing.length-16384,16384);
                }
            }
        }
        try {
            int code=process.waitFor();
            return "RM11_V434_EXE_EXIT_CODE="+code+"\n"
                    +new String(tail.toByteArray(),java.nio.charset.StandardCharsets.UTF_8);
        }catch(InterruptedException e){
            Thread.currentThread().interrupt();
            throw new IOException("EXE observer interrupted",e);
        }
    }
}
