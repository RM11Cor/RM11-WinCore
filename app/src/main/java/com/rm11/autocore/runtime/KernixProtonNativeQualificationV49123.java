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
 * Version probes are bounded and MUST NOT run wineboot or a user's game.
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
                "RM11_NATIVE_WIN32U_DLL_REDIRECT"})
                pb.environment().remove(name);
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
        for(Path file:new Path[]{
                loader,server,fex64,fex32,
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

    public static String run(Context ctx){
        if(ctx==null)return "P11_CONTEXT_MISSING";
        if(!KernixProtonFexInstallerV49121.staged(ctx)){
            OfflineDiagnosticJournal.record(ctx,"v49123-proton-native-qualification",
                "P11_ENGINE_STAGE=BLOCKED_RUNTIME_NOT_STAGED\n"
                +"P11_GAME_ENGINE_ACTIVATED=false");
            return "P11_NOT_STAGED";
        }
        String loaderResult="NOT_RUN",serverResult="NOT_RUN";
        try{
            Plan plan=buildPlan(ctx.getFilesDir().toPath(),
                Path.of(ctx.getApplicationInfo().nativeLibraryDir));
            loaderResult=probe(ctx,plan,false);
            serverResult=probe(ctx,plan,true);
        }catch(Exception e){
            loaderResult="PLAN_BLOCKED_"+e.getClass().getSimpleName();
        }
        // Report only exit/timeout, never a false claim about DXVK/VKD3D
        // or actual Windows game launch.
        String result="P11_LOADER="+loaderResult+"\n"
            +"P11_WINESERVER="+serverResult+"\n"
            +"P11_PREFIX_IDENTITY=ISOLATED_TEMPLATE\n"
            +"P11_GAME_ENGINE_ACTIVATED=false\n"
            +"P11_VULKAN_X11_GAME_RENDER=UNVERIFIED\n"
            +"P11_HODLL_FEX2610=STAGED_NOT_GUEST_EXEC_PROOF";
        OfflineDiagnosticJournal.record(ctx,"v49123-proton-native-qualification",result);
        return result;
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
            if(first.length()>110)first=first.substring(0,110);
            return "EXIT_"+exit+"_OUTPUT_"+(first.isEmpty()?"EMPTY":first);
        }catch(Exception e){
            return "VERSION_BLOCKED_"+e.getClass().getSimpleName();
        }finally{
            if(proc!=null&&proc.isAlive())proc.destroyForcibly();
            try{Files.deleteIfExists(output);}catch(IOException ignored){}
        }
    }
}
