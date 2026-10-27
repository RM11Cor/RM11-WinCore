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
 * v473: run a *separate* signed Bionic ELF to verify a privately bundled
 * Mesa/Freedreno X11 Vulkan loader. Never change graphics environment for
 * the Wine executable and never invoke a Vulkan ICD on the Android UI thread.
 */
public final class X11VulkanBundleProbe {
    private X11VulkanBundleProbe(){}
    private static final int MAX_STDOUT_BYTES=8192;
    private static final long TIMEOUT_MS=4000;
    private static final String CHILD="librm11_vkprobe_v473.so";
    private static final String ICD="librm11_vkdriver_v473.so";
    private static final String LOADER="librm11_vkloader_v473.so";

    public static void inspectOnce(Context app){
        if(app==null)return;
        Path pending=null;
        Process child=null;
        try{
            Path dir=app.getFilesDir().toPath().resolve("offline-diagnostics");
            Files.createDirectories(dir);
            if(Files.isRegularFile(dir.resolve("last-v473-private-vulkan.json"),
                    LinkOption.NOFOLLOW_LINKS))return;
            OfflineDiagnosticJournal.record(app,"v473-private-x11-vulkan",
                "RM11_V473_CHILD=START_REQUESTED\nRM11_V473_WINE_RENDERER_CHANGED=false");

            Path libs=Paths.get(app.getApplicationInfo().nativeLibraryDir);
            Path executable=libs.resolve(CHILD);
            Path driver=libs.resolve(ICD);
            Path loader=libs.resolve(LOADER);
            if(!Files.isRegularFile(executable,LinkOption.NOFOLLOW_LINKS)
                ||!Files.isRegularFile(driver,LinkOption.NOFOLLOW_LINKS)
                ||!Files.isRegularFile(loader,LinkOption.NOFOLLOW_LINKS)
                ||Files.size(executable)<4096||Files.size(driver)<4096
                ||Files.size(loader)<4096){
                record(app,"SIGNED_PRIVATE_BACKEND_MISSING","",null);
                return;
            }
            Path json=dir.resolve("v473-freedreno-icd.json");
            if(Files.isSymbolicLink(json)){
                record(app,"UNSAFE_ICD_PATH","",null);
                return;
            }
            JSONObject data=new JSONObject();
            data.put("file_format_version","1.0.0");
            JSONObject icd=new JSONObject();
            icd.put("library_path",driver.toString());
            icd.put("api_version","1.3.0");
            data.put("ICD",icd);
            Files.write(json,data.toString().getBytes(StandardCharsets.UTF_8));
            pending=dir.resolve("v473-child-output.pending");
            if(Files.isSymbolicLink(pending)){
                record(app,"UNSAFE_OUTPUT_PATH","",null);
                return;
            }
            ProcessBuilder command=new ProcessBuilder(executable.toString());
            String nativePath=libs.toString();
            String original=command.environment().get("LD_LIBRARY_PATH");
            command.environment().put("LD_LIBRARY_PATH",nativePath+
                    (original==null||original.isEmpty()?"":":"+original));
            // The desktop Vulkan loader is NOT Android system libvulkan.so.
            command.environment().put("VK_DRIVER_FILES",json.toString());
            command.environment().put("VK_ICD_FILENAMES",json.toString());
            command.redirectErrorStream(true);
            command.redirectOutput(pending.toFile());
            child=command.start();
            boolean ended=child.waitFor(TIMEOUT_MS,TimeUnit.MILLISECONDS);
            if(!ended){
                child.destroyForcibly();
                child.waitFor(400,TimeUnit.MILLISECONDS);
            }
            String output="";
            if(Files.isRegularFile(pending,LinkOption.NOFOLLOW_LINKS)
                &&Files.size(pending)<=MAX_STDOUT_BYTES)
                output=new String(Files.readAllBytes(pending),StandardCharsets.UTF_8);
            record(app,ended?"EXITED":"TIMEOUT_KILLED",output,
                ended?child.exitValue():null);
        }catch(InterruptedException e){
            if(child!=null)child.destroyForcibly();
            Thread.currentThread().interrupt();
            record(app,"INTERRUPTED","",null);
        }catch(Exception e){
            if(child!=null)child.destroyForcibly();
            record(app,"FAILED_"+e.getClass().getSimpleName(),"",null);
        }finally{
            if(pending!=null){
                try{Files.deleteIfExists(pending);}catch(IOException ignored){}
            }
        }
    }
    private static void record(Context app,String childState,String out,Integer code){
        OfflineDiagnosticJournal.record(app,"v473-private-x11-vulkan",
            "RM11_V473_CHILD="+childState+"\n"
            +"RM11_V473_CHILD_EXIT="+(code==null?"UNVERIFIED":code)+"\n"
            +"RM11_V473_ISOLATED_MESA_BACKEND=true\n"
            +"RM11_V473_WINE_RENDERER_CHANGED=false\n"
            +"RM11_V473_PRIVATE_BACKEND_VERDICT="+
                X11VulkanBundleVerdict.classify(out)+"\n"
            +"RM11_V473_X11_SURFACE_PRESENTATION=UNVERIFIED\n"
            +"RM11_V473_CHILD_OUTPUT:\n"+out);
    }
}
