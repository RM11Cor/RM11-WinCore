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
 * v478: test Mesa software X11 WSI in signed child only, leaving Wine unchanged.
 * This method MUST run on a worker only after X11 wire connection succeeds.
 * Not invoked from the home Activity and not from the Wine/game launcher.
 * A crashing GPU driver is confined to a signed native child process.
 */
public final class X11VulkanSoftwareWsiAudit {
    private X11VulkanSoftwareWsiAudit(){}
    private static final String CHILD="librm11_vkswapchain_v477.so";
    private static final String ICD="librm11_vkdriver_v473.so";
    private static final String LOADER="librm11_vkloader_v473.so";
    private static final int MAX_OUTPUT=8192;
    private static final long MAX_RUN_MS=15000;

    public static void inspectOnce(Context app) {
        inspect(app,false);
    }
    /** v49094: deliberate, isolated recheck on the CURRENT APK/device.
     * Never reuse a stale v478 result as a new frame proof. The X11 service
     * must already have accepted a fresh wire handshake.
     */
    public static void inspectFresh(Context app) {
        inspect(app,true);
    }
    private static void inspect(Context app,boolean fresh) {
        if(app==null)return;
        Process child=null;
        Path output=null;
        try {
            Path dir=app.getFilesDir().toPath().resolve("offline-diagnostics");
            Files.createDirectories(dir);
            if(!fresh && Files.isRegularFile(dir.resolve("last-v478-x11-software-wsi.json"),
                    LinkOption.NOFOLLOW_LINKS))return;
            if(fresh)OfflineDiagnosticJournal.record(app,
                "v49094-x11-wsi-fresh",
                "KERNIX_X11_WSI_RECHECK=STARTED\\n"
                +"KERNIX_WINE_GAME_STARTED=false\\n"
                +"KERNIX_PREVIOUS_V478_RECEIPT_NOT_TRUSTED_AS_CURRENT=true");
            OfflineDiagnosticJournal.record(app,"v478-x11-software-wsi-audit",
                "RM11_V478_CHILD=START_REQUESTED\n"
                +"RM11_V478_GAME_STARTED=false\n"
                +"RM11_V478_PRESENT_PROBE_ISOLATED=true");
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
            Path config=dir.resolve("v478-freedreno-icd.json");
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
            output=dir.resolve("v478-vulkan-surface-output.pending");
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
            command.environment().put("MESA_VK_WSI_DEBUG","sw");
            command.environment().put("MESA_DEBUG","1");
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
            if(fresh)recordFresh(app,ended?"EXITED":"TIMEOUT",
                observed,ended?child.exitValue():null);
        }catch(InterruptedException e) {
            if(child!=null)child.destroyForcibly();
            Thread.currentThread().interrupt();
            record(app,"INTERRUPTED","",null);
            if(fresh)recordFresh(app,"INTERRUPTED","",null);
        }catch(Exception e){
            if(child!=null)child.destroyForcibly();
            record(app,"FAILED_"+e.getClass().getSimpleName(),"",null);
            if(fresh)recordFresh(app,"FAILED_"+e.getClass().getSimpleName(),"",null);
        }finally{
            if(output!=null)try{Files.deleteIfExists(output);}catch(IOException ignored){}
        }
    }
    private static void recordFresh(Context app,String state,String out,Integer exit){
        boolean present=exit!=null&&exit==0
            &&out.contains("RM11_V477_VK_CREATE_XLIB_SURFACE_RESULT=0")
            &&out.contains("RM11_V477_VK_CREATE_SWAPCHAIN_RESULT=0")
            &&out.contains("RM11_V477_VK_QUEUE_PRESENT_RESULT=0");
        OfflineDiagnosticJournal.record(app,"v49094-x11-wsi-fresh",
            "KERNIX_X11_WSI_RECHECK="+state+"\\n"
            +"KERNIX_NATIVE_EXIT="+(exit==null?"UNVERIFIED":exit)+"\\n"
            +"KERNIX_X11_SURFACE_SWAPCHAIN_PRESENT="+(present?"PASS":"NOT_PROVEN")+"\\n"
            +"KERNIX_ANDROID_LORIE_PIXELS=NOT_YET_VISUALLY_PROVEN\\n"
            +"KERNIX_GAME_DXVK_FRAMES=NOT_TESTED\\n"
            +"KERNIX_WSI_OVERRIDE=sw\\n"
            +"KERNIX_NATIVE_TRACE_BEGIN\\n"+out);
    }
    private static void record(Context app,String state,String out,Integer exit){
        OfflineDiagnosticJournal.record(app,"v478-x11-software-wsi-audit",
            "RM11_V478_CHILD="+state+"\n"
            +"RM11_V478_WSI_OVERRIDE=sw\n"
            +"RM11_V478_CHILD_EXIT="+(exit==null?"UNVERIFIED":exit)+"\n"
            +"RM11_V478_DISPLAY=127.0.0.1:2\n"
            +"RM11_V478_GAME_STARTED=false\n"
            +"RM11_V478_SOFTWARE_WSI_VERDICT="+X11VulkanSwapchainVerdict.classify(out)+"\n"
            +"RM11_V478_XLIB_CPU_GREEN_VISIBILITY=UNVERIFIED\n"
            +"RM11_V478_CHILD_OUTPUT:\n"+out);
    }
}
