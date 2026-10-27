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
        environment.put("RM11_V458_ANDROID_VULKAN_FALLBACK",
                isolation.isolate?"0":"1");
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
        builder.redirectErrorStream(true);
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
