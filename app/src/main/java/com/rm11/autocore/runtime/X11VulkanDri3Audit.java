package com.rm11.autocore.runtime;

import android.content.Context;
import com.rm11.autocore.diagnostics.OfflineDiagnosticJournal;
import org.json.JSONObject;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.concurrent.TimeUnit;

/**
 * v476: distinguish Xlib baseline from missing X11 DRI3/Present Vulkan WSI on live Lorie X.Org :2.
 * This method MUST run on a worker only after X11 wire connection succeeds.
 * Not invoked from the home Activity and not from the Wine/game launcher.
 * A crashing GPU driver is confined to a signed native child process.
 */
public final class X11VulkanDri3Audit {
    private X11VulkanDri3Audit(){}
    private static final String CHILD="librm11_vkdri3_v476.so";
    private static final String ICD="librm11_vkdriver_v473.so";
    private static final String LOADER="librm11_vkloader_v473.so";
    private static final int MAX_OUTPUT=8192;
    private static final long MAX_RUN_MS=15000;

    public static void inspectOnce(Context app) {
        if(app==null)return;
        Process child=null;
        Path output=null;
        try {
            Path dir=app.getFilesDir().toPath().resolve("offline-diagnostics");
            Files.createDirectories(dir);
            if(Files.isRegularFile(dir.resolve("last-v476-x11-present.json"),
                    LinkOption.NOFOLLOW_LINKS))return;
            OfflineDiagnosticJournal.record(app,"v476-x11-vulkan-present",
                "RM11_V476_CHILD=START_REQUESTED\n"
                +"RM11_V476_GAME_STARTED=false\n"
                +"RM11_V476_PRESENT_PROBE_ISOLATED=true");
            Path libs=Paths.get(app.getApplicationInfo().nativeLibraryDir);
            Path executable=libs.resolve(CHILD);
            Path loader=libs.resolve(LOADER);
            Path driver=libs.resolve(ICD);
            Path xlib=libs.resolve("libX11.so");
            if(!Files.isRegularFile(executable,LinkOption.NOFOLLOW_LINKS)
                ||!Files.isRegularFile(loader,LinkOption.NOFOLLOW_LINKS)
                ||!Files.isRegularFile(driver,LinkOption.NOFOLLOW_LINKS)
                ||!Files.isRegularFile(xlib,LinkOption.NOFOLLOW_LINKS)){
                record(app,"SIGNED_XLIB_OR_VULKAN_MISSING","",null);return;
            }
            Path config=dir.resolve("v476-freedreno-icd.json");
            if(Files.isSymbolicLink(config)){
                record(app,"ICD_SYMLINK_REJECTED","",null);return;
            }
            JSONObject json=new JSONObject();
            json.put("file_format_version","1.0.0");
            JSONObject icd=new JSONObject();
            icd.put("library_path",driver.toString());
            icd.put("api_version","1.3.0");
            json.put("ICD",icd);
            Files.write(config,json.toString().getBytes(StandardCharsets.UTF_8));
            output=dir.resolve("v476-vulkan-surface-output.pending");
            if(Files.isSymbolicLink(output)){
                record(app,"OUTPUT_SYMLINK_REJECTED","",null);return;
            }
            ProcessBuilder command=new ProcessBuilder(executable.toString());
            String nativePath=libs.toString();
            String inherited=command.environment().get("LD_LIBRARY_PATH");
            command.environment().put("LD_LIBRARY_PATH",nativePath+
                (inherited==null||inherited.isEmpty()?"":":"+inherited));
            command.environment().put("VK_DRIVER_FILES",config.toString());
            command.environment().put("VK_ICD_FILENAMES",config.toString());
            command.environment().put("DISPLAY","127.0.0.1:2");
            // Termux's default /data/data/com.termux shader-cache directory
            // is not writable to RM11. Use our own private writable location.
            Path cache=app.getCacheDir().toPath().resolve("rm11-mesa");
            Files.createDirectories(cache);
            command.environment().put("HOME",app.getFilesDir().getAbsolutePath());
            command.environment().put("XDG_CACHE_HOME",cache.toString());
            command.environment().put("MESA_SHADER_CACHE_DIR",cache.toString());
            command.redirectErrorStream(true);
            command.redirectOutput(output.toFile());
            child=command.start();
            boolean ended=child.waitFor(MAX_RUN_MS,TimeUnit.MILLISECONDS);
            if(!ended){
                child.destroyForcibly();
                child.waitFor(300,TimeUnit.MILLISECONDS);
            }
            String observed="";
            if(Files.isRegularFile(output,LinkOption.NOFOLLOW_LINKS)
                &&Files.size(output)<=MAX_OUTPUT)
                observed=new String(Files.readAllBytes(output),StandardCharsets.UTF_8);
            record(app,ended?"EXITED":"TIMEOUT_KILLED",observed,
                ended?child.exitValue():null);
        }catch(InterruptedException e) {
            if(child!=null)child.destroyForcibly();
            Thread.currentThread().interrupt();
            record(app,"INTERRUPTED","",null);
        }catch(Exception e){
            if(child!=null)child.destroyForcibly();
            record(app,"FAILED_"+e.getClass().getSimpleName(),"",null);
        }finally{
            if(output!=null)try{Files.deleteIfExists(output);}catch(IOException ignored){}
        }
    }
    private static void record(Context app,String state,String out,Integer exit){
        OfflineDiagnosticJournal.record(app,"v476-x11-vulkan-present",
            "RM11_V476_CHILD="+state+"\n"
            +"RM11_V476_CHILD_EXIT="+(exit==null?"UNVERIFIED":exit)+"\n"
            +"RM11_V476_DISPLAY=127.0.0.1:2\n"
            +"RM11_V476_GAME_STARTED=false\n"
            +"RM11_V476_DRI3_WSI_VERDICT="+X11VulkanDri3Verdict.classify(out)+"\n"
            +"RM11_V476_XLIB_CPU_GREEN_VISIBILITY=UNVERIFIED\n"
            +"RM11_V476_CHILD_OUTPUT:\n"+out);
    }
}
