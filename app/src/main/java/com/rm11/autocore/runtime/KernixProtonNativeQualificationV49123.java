package com.rm11.autocore.runtime;

import android.content.Context;
import com.rm11.autocore.diagnostics.OfflineDiagnosticJournal;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * Source-identical Proton 11 ARM64EC + FEXCore 2610 native-loader qualification.
 *
 * Only signed Android native-library ELF files are EXECUTED. The full Wine
 * modules and Windows prefix live in the verified private engine slot.
 * Version probes are bounded; a separate, strictly isolated Wineboot
 * qualification may run only after BOTH native version probes pass.
 * A passing --version is not sufficient to activate game graphics.
 */
public final class KernixProtonNativeQualificationV49123 {
    private KernixProtonNativeQualificationV49123(){}
    public static final class Plan {
        public final Path loader;
        public final Path server;
        public final Path wineRoot;
        public final Path prefix;
        public final Map<String,String> environment;
        private Plan(Path loader,Path server,Path wineRoot,Path prefix,
                     Map<String,String> environment){
            this.loader=loader;this.server=server;this.wineRoot=wineRoot;
            this.prefix=prefix;
            this.environment=java.util.Collections.unmodifiableMap(environment);
        }
        /** Headless initialization ONLY of an app-owned COPY of the Proton
         * prefix template. Never boot the source template, legacy Wine
         * registry or user game folders. */
        public ProcessBuilder prefixBootCommand(Path output)throws IOException{
            KernixProtonPrefixV49126.requireWritable(wineRoot,prefix);
            Path boot=wineRoot.resolve("lib/wine/aarch64-windows/wineboot.exe");
            Path preload=loader.getParent().resolve("librm11_wine_data_redirect.so");
            if(Files.isSymbolicLink(boot)||!Files.isRegularFile(boot,LinkOption.NOFOLLOW_LINKS)
                ||Files.size(boot)<256)
                throw new IOException("P11_WINEBOOT_PE_MISSING");
            try(java.io.InputStream in=Files.newInputStream(boot)){
                if(in.read()!='M'||in.read()!='Z')
                    throw new IOException("P11_WINEBOOT_NOT_PE");
            }
            if(Files.isSymbolicLink(preload)
                ||!Files.isRegularFile(preload,LinkOption.NOFOLLOW_LINKS)
                ||Files.size(preload)<256)
                throw new IOException("P11_SIGNED_REEXEC_INTERPOSER_MISSING");
            // Wine win32u dynamically opens FreeType by its Linux SONAME.
            // The existing signed APK ships a Bionic-compatible provider;
            // do not make Wineboot depend on untrusted Termux ImageFs ELFs.
            Path freetype=loader.getParent().resolve("librm11_freetype_core.so");
            if(Files.isSymbolicLink(freetype)
                ||!Files.isRegularFile(freetype,LinkOption.NOFOLLOW_LINKS)
                ||Files.size(freetype)<1024)
                throw new IOException("P11_SIGNED_FREETYPE_PROVIDER_MISSING");
            // The source is a prepopulated Proton prefix. Run --update, not
            // first-install --init. Repair only the owned writable copy.
            Path system32=prefix.resolve("drive_c/windows/system32");
            if(Files.isSymbolicLink(system32)
                ||!Files.isDirectory(system32,LinkOption.NOFOLLOW_LINKS))
                throw new IOException("P11_PRIVATE_SYSTEM32_MISSING");
            Path privateBoot=system32.resolve("wineboot.exe");
            if(Files.isSymbolicLink(privateBoot))
                throw new IOException("P11_PRIVATE_WINEBOOT_SYMLINK");
            if(!Files.exists(privateBoot,LinkOption.NOFOLLOW_LINKS))
                Files.copy(boot,privateBoot);
            if(!Files.isRegularFile(privateBoot,LinkOption.NOFOLLOW_LINKS)
                ||Files.size(privateBoot)<256)
                throw new IOException("P11_PRIVATE_WINEBOOT_PE_INVALID");
            try(java.io.InputStream in=Files.newInputStream(privateBoot)){
                if(in.read()!='M'||in.read()!='Z')
                    throw new IOException("P11_PRIVATE_WINEBOOT_NOT_PE");
            }
            // Pass a Windows-resolvable path rather than a raw Unix PE path,
            // which may be rejected by ShellExecute even when Wine starts.
            ProcessBuilder pb=new ProcessBuilder(
                loader.toString(),"C:\\windows\\system32\\wineboot.exe","--update");
            pb.directory(system32.toFile());
            // Remove inherited graphics, old abort hooks and old runtime
            // selections before turning on the *Proton-specific* interposer.
            for(String key:new String[]{"LD_PRELOAD","VK_DRIVER_FILES",
                "VK_ICD_FILENAMES","MESA_VK_WSI_DEBUG","WINE_D3D_CONFIG",
                "DXVK_CONFIG","DXVK_CONFIG_FILE","RM11_WS2_UNIXLIB_REDIRECT",
                "RM11_V479_PRIVATE_VULKAN_GAME"})
                pb.environment().remove(key);
            pb.environment().putAll(environment);
            pb.environment().put("LD_PRELOAD",preload.toString());
            pb.environment().put("RM11_PROTON_RUNTIME_V49124","1");
            pb.environment().put("RM11_CHILD_LOADER_BRIDGE","1");
            pb.environment().put("RM11_NATIVE_WIN32U_DLL_REDIRECT","1");
            pb.environment().put("RM11_NATIVE_WINEX11_DLOPEN_REDIRECT","1");
            // Explicitly opt in only this Proton Wine client and its signed
            // Wine-managed children. C shim also checks /proc/self/exe and
            // our exact Proton engine slot; WineServer never qualifies.
            pb.environment().put("RM11_NATIVE_FREETYPE_DLOPEN_REDIRECT","1");
            // Wine owns this flag during its native child re-exec. A fresh
            // Wineboot must enter the first-stage loader without it.
            pb.environment().remove("WINELOADERNOEXEC");
            // No X11 DISPLAY is forged, and no graphics route is implied.
            pb.environment().remove("DISPLAY");
            pb.redirectErrorStream(true);
            pb.redirectOutput(output.toFile());
            return pb;
        }

        /**
         * WineServer must be a live service for this same private Proton
         * prefix, not merely an ELF that passes --version. Launch the
         * APK-signed Proton server in foreground, without Wine-client
         * LD_PRELOAD hooks or a forged child re-exec environment.
         */
        /** Wine -p without a value persists forever. Qualification must
         * expire after the last guest instead of keeping a daemon alive. */
        public ProcessBuilder prefixServerCommand(Path output)throws IOException{
            KernixProtonPrefixV49126.requireWritable(wineRoot,prefix);
            ProcessBuilder pb=new ProcessBuilder(
                server.toString(),"-f","-p3","-d0");
            pb.directory(wineRoot.toFile());
            pb.environment().putAll(environment);
            for(String key:new String[]{"LD_PRELOAD","WINELOADERNOEXEC",
                "RM11_CHILD_LOADER_BRIDGE","RM11_PROTON_RUNTIME_V49124",
                "RM11_NATIVE_WIN32U_DLL_REDIRECT",
                "RM11_NATIVE_WINEX11_DLOPEN_REDIRECT",
                "VK_DRIVER_FILES","VK_ICD_FILENAMES","DISPLAY",
                "RM11_NATIVE_FREETYPE_DLOPEN_REDIRECT"})
                pb.environment().remove(key);
            pb.redirectErrorStream(true);
            pb.redirectOutput(output.toFile());
            return pb;
        }

        /**
         * A real WineServer can request /etc/machine-id on Android.
         * Supply an independent KERNIX-only identifier; the signed native
         * interposer redirects reads from this exact process only.
         */
        /** Stops only the independently owned Proton qualification prefix.
         * Wine -k addresses the server by WINEPREFIX, not by app UID. */
        public ProcessBuilder prefixStopCommand(Path output,Path machineId)throws IOException{
            // Match the same private machine-id used by the foreground server.
            ProcessBuilder pb=prefixServerWithIdentity(output,machineId);
            pb.command(server.toString(),"-k");
            return pb;
        }
        public ProcessBuilder prefixServerWithIdentity(
                Path output,Path identity)throws IOException{
            if(identity==null||Files.isSymbolicLink(identity)
                ||!Files.isRegularFile(identity,LinkOption.NOFOLLOW_LINKS)
                ||Files.size(identity)!=33)
                throw new IOException("P11_LOCAL_MACHINE_ID_INVALID");
            ProcessBuilder pb=prefixServerCommand(output);
            pb.environment().put("RM11_P11_MACHINE_ID_FILE",identity.toString());
            pb.environment().put("LD_PRELOAD",loader.getParent()
                .resolve("librm11_wine_data_redirect.so").toString());
            return pb;
        }

        public Plan withWritablePrefix(Path writable)throws IOException{
            KernixProtonPrefixV49126.requireWritable(wineRoot,writable);
            LinkedHashMap<String,String> vars=new LinkedHashMap<>(environment);
            vars.put("WINEPREFIX",writable.toString());
            return new Plan(loader,server,wineRoot,writable,vars);
        }
        public ProcessBuilder versionCommand(boolean wineServer,Path output){
            ArrayList<String> args=new ArrayList<>(Arrays.asList(
                (wineServer?server:loader).toString(),"--version"));
            ProcessBuilder pb=new ProcessBuilder(args);
            pb.directory(wineRoot.toFile());
            pb.environment().putAll(environment);
            // An actual ProcessBuilder inherits Android's app variables by
            // default. Explicitly discard legacy Wine/FEX/DXVK/Vulkan routes.
            for(String name:new String[]{"LD_PRELOAD","WINE_D3D_CONFIG",
                "DXVK_CONFIG","DXVK_CONFIG_FILE","VK_DRIVER_FILES",
                "VK_ICD_FILENAMES","MESA_VK_WSI_DEBUG",
                "RM11_V479_PRIVATE_VULKAN_GAME",
                "RM11_CHILD_LOADER_BRIDGE",
                "RM11_NATIVE_WINEX11_DLOPEN_REDIRECT",
                "RM11_NATIVE_WIN32U_DLL_REDIRECT",
                "RM11_NATIVE_FREETYPE_DLOPEN_REDIRECT",
                "RM11_PROTON_RUNTIME_V49124",
                "WINELOADERNOEXEC"})
                pb.environment().remove(name);
            // Wine 11 __wine_main only calls check_command_line for
            // "--version" when WINELOADERNOEXEC is ABSENT. The previous
            // shared engine environment set it to "1" and forced the
            // version probe into Windows process bootstrap (exit 127).
            // A headless version check must never boot a Windows session.
            // Keep the flag in actual Wineboot/guest launch plans only.
            // The original Proton Wine executable depends on signed
            // NTDLL redirection even for --version. Keep the WineServer
            // version command minimal; neither probe starts a game.
            if(!wineServer){
                Path preload=loader.getParent().resolve(
                    "librm11_wine_data_redirect.so");
                pb.environment().put("LD_PRELOAD",preload.toString());
                pb.environment().put("RM11_PROTON_RUNTIME_V49124","1");
            }
            pb.redirectErrorStream(true);
            pb.redirectOutput(output.toFile());
            return pb;
        }
    }
    public static Plan buildPlan(Path appFiles,Path nativeRoot) throws IOException{
        if(appFiles==null||nativeRoot==null)
            throw new IOException("P11_NO_PRIVATE_RUNTIME_ROOT");
        Path root=KernixProtonFexInstallerV49121.slotRoot(
            appFiles.toAbsolutePath().normalize());
        Path n=nativeRoot.toAbsolutePath().normalize();
        Path wine=root, prefix=root.resolve("prefix");
        Path dlls=wine.resolve("lib/wine");
        Path wineData=wine.resolve("share/wine");
        Path loader=n.resolve("libkernix_p11_loader.so");
        Path server=n.resolve("libkernix_p11_server.so");
        Path fex64=n.resolve("libkernix_p11_fex64.so");
        Path fex32=n.resolve("libkernix_p11_fex32.so");
        Path nativeRedirect=n.resolve("librm11_wine_data_redirect.so");
        for(Path file:new Path[]{
                loader,server,fex64,fex32,nativeRedirect,
                wine.resolve("lib/wine/aarch64-unix/ntdll.so"),
                wine.resolve("lib/wine/aarch64-unix/libarm64ecfex.so"),
                wine.resolve("lib/wine/aarch64-unix/libwow64fex.so"),
                wine.resolve("lib/wine/aarch64-windows/libarm64ecfex.dll"),
                wine.resolve("lib/wine/aarch64-windows/libwow64fex.dll"),
                wineData.resolve("wine.inf"),
                prefix.resolve("system.reg"),
                prefix.resolve("user.reg"),
                prefix.resolve("userdef.reg")}){
            if(Files.isSymbolicLink(file)
                ||!Files.isRegularFile(file,LinkOption.NOFOLLOW_LINKS)
                ||!Files.isReadable(file)||Files.size(file)<256)
                throw new IOException("P11_COMPONENT_UNTRUSTED_OR_MISSING:"
                    +file.getFileName());
        }
        if(!Files.isSymbolicLink(prefix.resolve("dosdevices/c:"))
            ||!Path.of("../drive_c").equals(
                Files.readSymbolicLink(prefix.resolve("dosdevices/c:"))))
            throw new IOException("P11_UNSAFE_DOSDEVICE_LINK");
        if(!Files.isDirectory(prefix.resolve("drive_c/windows/system32")))
            throw new IOException("P11_PREFIX_SYSTEM32_MISSING");
        // Private HOME, WINEPREFIX and WINESERVER MUST be the same engine
        // family: do not inherit /opt/wine, /home/xuser/.wine or old APK .so.
        LinkedHashMap<String,String> env=new LinkedHashMap<>();
        env.put("HOME",root.toString());
        env.put("WINEPREFIX",prefix.toString());
        env.put("WINESERVER",server.toString());
        env.put("USER","xuser");
        env.put("LOGNAME","xuser");
        env.put("PATH",wine.resolve("bin")+":"+appFiles.resolve("imagefs/usr/bin"));
        env.put("WINEDLLPATH",dlls.toString());
        env.put("WINEDATADIR",wineData.toString());
        env.put("WINE_DATADIR",wineData.toString());
        env.put("RM11_WINE_DATADIR",wineData.toString());
        env.put("RM11_WINE_PE_DIR",dlls.resolve("aarch64-windows").toString());
        env.put("RM11_WINE_NTDLL_VIRTUAL_PATH",
            dlls.resolve("aarch64-unix/ntdll.so").toString());
        env.put("RM11_APK_NATIVE_LIB_DIR",n.toString());
        env.put("HODLL64","libarm64ecfex.dll");
        env.put("HODLL","libwow64fex.dll");
        env.put("WINELOADERNOEXEC","1");
        env.put("LD_LIBRARY_PATH",n+":"+dlls.resolve("aarch64-unix")
            +":"+wine.resolve("lib")+":"+appFiles.resolve("imagefs/usr/lib")
            +":/system/lib64");
        env.put("XDG_DATA_DIRS",wine.resolve("share").toString());
        env.put("WINEDEBUG","+err,+warn");
        return new Plan(loader,server,wine,prefix,env);
    }

    /** Do not launch a second x64 workload after a failed/aborted Wineboot.
     * The signed x64 smoke previously passed; only boot success qualifies
     * a safe follow-on guest launch. */
    static boolean bootAllowsGuestProbe(String boot){
        return boot!=null && (boot.startsWith("EXIT_0_")
            ||"ALREADY_COMPLETED_WITH_THIS_NATIVE_BRIDGE".equals(boot));
    }
    public static synchronized String run(Context ctx){
        if(ctx==null)return "P11_CONTEXT_MISSING";
        if(!KernixProtonFexInstallerV49121.staged(ctx)){
            OfflineDiagnosticJournal.record(ctx,"v49123-proton-native-qualification",
                "P11_ENGINE_STAGE=BLOCKED_RUNTIME_NOT_STAGED\n"
                +"P11_GAME_ENGINE_ACTIVATED=false");
            return "P11_NOT_STAGED";
        }
        String loaderResult="NOT_RUN",serverResult="NOT_RUN",
            bootResult="NOT_RUN",x64Result="NOT_RUN";
        try{
            Plan plan=buildPlan(ctx.getFilesDir().toPath(),
                Path.of(ctx.getApplicationInfo().nativeLibraryDir));
            loaderResult=probe(ctx,plan,false);
            serverResult=probe(ctx,plan,true);
            if(loaderResult.startsWith("EXIT_0_")
                &&serverResult.startsWith("EXIT_0_")){
                Path working=KernixProtonPrefixV49126.prepareDefault(
                    ctx.getFilesDir().toPath());
                Plan writable=plan.withWritablePrefix(working);
                bootResult=probePrefixBoot(ctx,writable);
                if(bootAllowsGuestProbe(bootResult))
                    x64Result=KernixProtonFexSmokeV49127.run(ctx,writable);
                else {
                    // Safety: never start another guest after a timeout,
                    // thermal cutoff or failed/aborted prefix bootstrap.
                    x64Result="BLOCKED_UNTIL_WINEBOOT_PASS";
                }
            }else bootResult="BLOCKED_NATIVE_VERSION_NOT_PROVEN";
        }catch(Exception e){
            loaderResult="PLAN_BLOCKED_"+e.getClass().getSimpleName();
            bootResult="BLOCKED_NATIVE_PLAN";
        }
        // Report only exit/timeout, never a false claim about DXVK/VKD3D
        // or actual Windows game launch.
        String result="P11_LOADER="+loaderResult+"\n"
            +"P11_WINESERVER="+serverResult+"\n"
            +"P11_PREFIX_IDENTITY=IMMUTABLE_TEMPLATE_PLUS_PRIVATE_WRITABLE_COPY\n"
            +"P11_WINEBOOT="+bootResult+"\n"
            +"P11_FEX_X64_SMOKE="+x64Result+"\n"
            +"P11_GAME_ENGINE_ACTIVATED=false\n"
            +"P11_VULKAN_X11_GAME_RENDER=UNVERIFIED\n"
            +"P11_HODLL_FEX2610=STAGED_NOT_GUEST_EXEC_PROOF";
        OfflineDiagnosticJournal.record(ctx,"v49123-proton-native-qualification",result);
        return result;
    }

    /**
     * Stable installation-scoped random ID. Not Android ID, hardware serial,
     * advertising identifier or the Linux host's machine-id.
     */
    static synchronized Path localMachineId(Context ctx)
            throws IOException{
        Path file=ctx.getFilesDir().toPath().resolve(
            "kernix-proton-private-machine-id");
        if(Files.isSymbolicLink(file))
            throw new IOException("P11_MACHINE_ID_SYMLINK");
        if(!Files.exists(file,LinkOption.NOFOLLOW_LINKS)){
            byte[] random=new byte[16];
            new java.security.SecureRandom().nextBytes(random);
            StringBuilder value=new StringBuilder();
            for(byte b:random)value.append(String.format(
                java.util.Locale.ROOT,"%02x",b&255));
            value.append('\n');
            Files.write(file,value.toString().getBytes(StandardCharsets.US_ASCII),
                java.nio.file.StandardOpenOption.CREATE_NEW);
        }
        if(!Files.isRegularFile(file,LinkOption.NOFOLLOW_LINKS)
            ||Files.size(file)!=33)
            throw new IOException("P11_MACHINE_ID_NOT_PRIVATE_FILE");
        String text=new String(Files.readAllBytes(file),
            StandardCharsets.US_ASCII);
        if(!text.matches("[0-9a-f]{32}\\n"))
            throw new IOException("P11_MACHINE_ID_WRONG_FORMAT");
        return file;
    }

    /** Never start or continue bootstrapping under severe Android thermal load. */
    private static boolean deviceThermalSevere(Context ctx){
        if(android.os.Build.VERSION.SDK_INT<29)return false;
        android.os.PowerManager power=
            (android.os.PowerManager)ctx.getSystemService(Context.POWER_SERVICE);
        return power!=null && power.getCurrentThermalStatus()>=
            android.os.PowerManager.THERMAL_STATUS_SEVERE;
    }
    /** Bounded stop of the one qualification WineServer, never the legacy
     * engine or arbitrary same-UID processes. WINEPREFIX is validated. */
    static void stopOwnedQualificationServer(Context ctx,Plan plan){
        if(ctx==null||plan==null)return;
        Path log=ctx.getCacheDir().toPath().resolve("p11-owned-stop.txt");
        Process stop=null;
        String state="NOT_ATTEMPTED";
        try{
            if(Files.isSymbolicLink(log))return;
            stop=plan.prefixStopCommand(log,localMachineId(ctx)).start();
            if(stop.waitFor(2,TimeUnit.SECONDS))
                state="EXIT_"+stop.exitValue();
            else state="TIMEOUT";
        }catch(Exception ex){
            state="BLOCKED_"+ex.getClass().getSimpleName();
        }finally{
            if(stop!=null&&stop.isAlive())stop.destroyForcibly();
            try{Files.deleteIfExists(log);}catch(IOException ignored){}
            OfflineDiagnosticJournal.record(ctx,"v49132-p11-private-server-stop",
                "P11_SCOPED_PRIVATE_WINESERVER_STOP="+state
                +"\nP11_LEGACY_PREFIX_TOUCHED=false");
        }
    }
    private static String probePrefixBoot(Context ctx,Plan plan){
        Path marker=plan.prefix.resolve(".kernix-p11-wineboot-v49124");
        Path output=ctx.getCacheDir().toPath().resolve("p11-wineboot-init.txt");
        Process process=null;
        Process serverProcess=null;
        Path serverOutput=ctx.getCacheDir().toPath()
            .resolve("p11-wineserver-initialization.txt");
        String serverState="NOT_STARTED";
        try{
            if(deviceThermalSevere(ctx))return "PREFIX_BOOT_BLOCKED_THERMAL_SEVERE";
            if(Files.isSymbolicLink(marker)||Files.isSymbolicLink(output)
                ||Files.isSymbolicLink(serverOutput))
                return "UNSAFE_PREFIX_BOOT_MARKER";
            if(Files.isRegularFile(marker,LinkOption.NOFOLLOW_LINKS)){
                String prior=new String(Files.readAllBytes(marker),
                    StandardCharsets.US_ASCII).trim();
                if("P11_WINEBOOT_V49124_PASS".equals(prior))
                    return "ALREADY_COMPLETED_WITH_THIS_NATIVE_BRIDGE";
                return "EXISTING_UNTRUSTED_BOOT_MARKER";
            }
            // Wine 11 may auto-start the server, but a --version PASS
            // does not certify startup. Hold a dedicated signed native
            // server for precisely this prefix throughout Wineboot.
            Path identity=localMachineId(ctx);
            ProcessBuilder serverPb=plan.prefixServerWithIdentity(
                serverOutput,identity);
            serverProcess=serverPb.start();
            Thread.sleep(400);
            if(!serverProcess.isAlive()){
                serverState="EARLY_EXIT_"+serverProcess.exitValue();
                // A normal Wine client may auto-start its own server. Do
                // not block the actual Wineboot test merely because this
                // explicit optional foreground server ended early.
            }else serverState="RUNNING_SAME_PREFIX";
            ProcessBuilder pb=plan.prefixBootCommand(output);
            pb.environment().put("RM11_P11_MACHINE_ID_FILE",
                identity.toString());
            // Isolate the first unresolved process/path creation failure.
            // Diagnostics remain scoped to this Proton bootstrap, never to
            // user games, WineServer, or the legacy runtime.
            pb.environment().put("WINEDEBUG",
                "+err,+warn");
            process=pb.start();
            boolean bootCompleted=false;
            for(int seconds=0;seconds<22;seconds+=2){
                if(process.waitFor(2,TimeUnit.SECONDS)){
                    bootCompleted=true;
                    break;
                }
                if(deviceThermalSevere(ctx)){
                    process.destroyForcibly();
                    return "PREFIX_BOOT_ABORTED_THERMAL_SEVERE";
                }
            }
            if(!bootCompleted){
                process.destroy();
                if(!process.waitFor(1,TimeUnit.SECONDS))process.destroyForcibly();
                return "PREFIX_BOOT_SAFETY_CUTOFF_22S";
            }
            int exit=process.exitValue();
            // Read the tail as well as the first loader markers: RC226
            // lost the real exit-127 reason after the first 120 characters.
            byte[] small;
            try(java.io.RandomAccessFile log=
                    new java.io.RandomAccessFile(output.toFile(),"r")){
                int count=(int)Math.min(log.length(),4096L);
                small=new byte[count];
                log.seek(log.length()-count);
                log.readFully(small);
            }
            String sample=new String(small,StandardCharsets.UTF_8)
                .replaceAll("[^A-Za-z0-9. _()+-]"," ")
                .replaceAll("\\s+"," ").trim();
            if(sample.length()>640)sample=sample.substring(sample.length()-640);
            if(exit==0){
                Files.write(marker,
                    "P11_WINEBOOT_V49124_PASS\n".getBytes(StandardCharsets.US_ASCII),
                    java.nio.file.StandardOpenOption.CREATE_NEW);
            }
            String failures=bootFailureFingerprint(output);
            return "EXIT_"+exit+"_OUTPUT_"+(sample.isEmpty()?"EMPTY":sample)
                +"_SERVER_"+serverState
                +(exit==0?"":"_FAILURE_TRACE_"+failures);
        }catch(Exception e){
            return "PREFIX_BOOT_BLOCKED_"+e.getClass().getSimpleName();
        }finally{
            if(process!=null&&process.isAlive())process.destroyForcibly();
            // Stop only the exact server child owned by this qualification,
            // never send a global wineserver -k or touch legacy Wine.
            if(serverProcess!=null){
                boolean beforeStop=serverProcess.isAlive();
                if(beforeStop){
                    serverProcess.destroy();
                    try{
                        if(!serverProcess.waitFor(1,TimeUnit.SECONDS))
                            serverProcess.destroyForcibly();
                    }catch(InterruptedException interrupted){
                        Thread.currentThread().interrupt();
                        serverProcess.destroyForcibly();
                    }
                }
                OfflineDiagnosticJournal.record(ctx,
                    "v49132-p11-server-boot-lifecycle",
                    "P11_NATIVE_SERVER_STAGE="+serverState+"\n"
                    +"P11_NATIVE_SERVER_ALIVE_AT_CLEANUP="+beforeStop+"\n"
                    +"P11_SERVER_LOG_TAIL="+lastServerOutput(serverOutput)+"\n"
                    +"P11_LEGACY_PREFIX_TOUCHED=false");
            }
            if(process!=null||serverProcess!=null)
                stopOwnedQualificationServer(ctx,plan);
            try{Files.deleteIfExists(output);}catch(IOException ignored){}
            try{Files.deleteIfExists(serverOutput);}catch(IOException ignored){}
        }
    }

    /** Capture failing Wine process/path operations without whole raw logs. */
    private static String bootFailureFingerprint(Path output){
        try(java.io.RandomAccessFile input=
                new java.io.RandomAccessFile(output.toFile(),"r")){
            int n=(int)Math.min(input.length(),256*1024L);
            input.seek(input.length()-n);
            byte[] data=new byte[n];
            input.readFully(data);
            String raw=new String(data,StandardCharsets.UTF_8);
            StringBuilder evidence=new StringBuilder();
            for(String line:raw.split("\\r?\\n")){
                String lower=line.toLowerCase(java.util.Locale.ROOT);
                if(lower.contains("not found")
                   ||lower.contains("file not found")
                   ||lower.contains("c0000135")
                   ||lower.contains("c0000034")
                   ||lower.contains("failed to start")
                   ||lower.contains("failed to load")
                   ||lower.contains("createprocess")
                   ||lower.contains("shellexecuteex")){
                    String safe=line.replaceAll("[^A-Za-z0-9. _()+:=\\\\-]"," ")
                        .replaceAll("\\s+"," ").trim();
                    if(safe.length()>240)
                        safe=safe.substring(safe.length()-240);
                    evidence.append(safe).append(" | ");
                    if(evidence.length()>1800)
                        evidence.delete(0,evidence.length()-1800);
                }
            }
            return evidence.length()==0?"NONE":evidence.toString();
        }catch(Exception e){return "LOG_NOT_AVAILABLE";}
    }

    /** Keep only bounded server-side failure text; never export huge logs. */
    private static String lastServerOutput(Path output){
        try(java.io.RandomAccessFile file=
                new java.io.RandomAccessFile(output.toFile(),"r")){
            int count=(int)Math.min(file.length(),2048L);
            file.seek(file.length()-count);
            byte[] data=new byte[count];
            file.readFully(data);
            String sample=new String(data,StandardCharsets.UTF_8)
                .replaceAll("[^A-Za-z0-9. _()+:=-]"," ")
                .replaceAll("\\s+"," ").trim();
            return sample.length()>480
                ?sample.substring(sample.length()-480):sample;
        }catch(Exception error){return "SERVER_LOG_UNAVAILABLE";}
    }

    private static String probe(Context ctx,Plan plan,boolean server){
        Path output=ctx.getCacheDir().toPath().resolve(
            server?"p11-wineserver-version.txt":"p11-wine-version.txt");
        Process proc=null;
        try{
            if(Files.isSymbolicLink(output))return "UNSAFE_DIAGNOSTIC_FILE";
            ProcessBuilder pb=plan.versionCommand(server,output);
            // Version flags only; do not boot the registry or Windows shell.
            proc=pb.start();
            if(!proc.waitFor(8,TimeUnit.SECONDS)){
                proc.destroy();
                if(!proc.waitFor(1,TimeUnit.SECONDS))proc.destroyForcibly();
                return "VERSION_TIMEOUT";
            }
            int exit=proc.exitValue();
            // Short, sanitized fingerprint. Do not export system paths.
            byte[] shortOutput;
            try(java.io.InputStream in=Files.newInputStream(output)){
                shortOutput=in.readNBytes(4096);
            }
            String raw=new String(shortOutput,StandardCharsets.UTF_8);
            String first=raw.replaceAll("[^A-Za-z0-9. _()+-]"," ")
                 .replaceAll("\\s+"," ").trim();
            // Preserve linker error details and the signed loader redirect
            // marker; the previous 110-character report hid the root cause.
            if(first.length()>520)first=first.substring(0,520);
            return "EXIT_"+exit+"_OUTPUT_"+(first.isEmpty()?"EMPTY":first);
        }catch(Exception e){
            return "VERSION_BLOCKED_"+e.getClass().getSimpleName();
        }finally{
            if(proc!=null&&proc.isAlive())proc.destroyForcibly();
            try{Files.deleteIfExists(output);}catch(IOException ignored){}
        }
    }
}
