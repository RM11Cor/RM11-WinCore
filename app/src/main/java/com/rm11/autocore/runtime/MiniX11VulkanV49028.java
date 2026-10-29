package com.rm11.autocore.runtime;

import android.content.Context;
import com.rm11.autocore.diagnostics.OfflineDiagnosticJournal;
import org.json.JSONObject;
import org.json.JSONArray;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.util.Map;

/** Private desktop Vulkan X11 WSI, verified and mini-only; does not prove GPU. */
public final class MiniX11VulkanV49028 {
    private MiniX11VulkanV49028(){}
    private static final char[] HEX="0123456789abcdef".toCharArray();
    private static String digest(Path file) throws Exception {
        MessageDigest hash=MessageDigest.getInstance("SHA-256");
        try(java.io.InputStream input=Files.newInputStream(file)) {
            byte[] buffer=new byte[1024*1024];
            int n;
            while((n=input.read(buffer))>0)hash.update(buffer,0,n);
        }
        byte[] bytes=hash.digest();
        char[] text=new char[bytes.length*2];
        for(int i=0;i<bytes.length;i++){
            text[i*2]=HEX[(bytes[i]&0xff)>>>4];
            text[i*2+1]=HEX[bytes[i]&15];
        }
        return new String(text);
    }
    private static JSONObject readManifest(Context app) throws Exception {
        try(java.io.InputStream in=app.getAssets().open(
                "runtime/rm11-v473-x11-vulkan-stage.json")){
            java.io.ByteArrayOutputStream bytes=new java.io.ByteArrayOutputStream();
            byte[] buffer=new byte[8192];
            int n;
            while((n=in.read(buffer))>0){
                if(bytes.size()+n>200*1024)throw new java.io.IOException("MANIFEST_TOO_LARGE");
                bytes.write(buffer,0,n);
            }
            return new JSONObject(bytes.toString("UTF-8"));
        }
    }
    public static boolean configure(Context ctx,RuntimeLayout layout,
                                    Map<String,String> env,boolean mini) {
        return configureScoped(ctx,layout,env,mini,false);
    }
    /** v49032: only an explicitly matched CarX Street EXE may opt in. */
    public static boolean configureSelectedCarx(Context ctx,RuntimeLayout layout,
                                    Map<String,String> env,boolean selectedCarx) {
        return configureScoped(ctx,layout,env,false,selectedCarx);
    }
    private static boolean configureScoped(Context ctx,RuntimeLayout layout,
                                    Map<String,String> env,boolean mini,boolean carx) {
        if(!(mini||carx) || ctx==null || layout==null || env==null)return false;
        String stage="START";
        try {
            Path loader=layout.apkNativeLibs.resolve("librm11_vkloader_v473.so");
            Path icd=layout.apkNativeLibs.resolve("librm11_vkdriver_v473.so");
            Path bridge=layout.apkNativeLibs.resolve("librm11_v49028_mini_x11_vulkan.so");
            for(Path p:new Path[]{loader,icd,bridge}){
                if(!Files.isRegularFile(p,LinkOption.NOFOLLOW_LINKS)
                        ||Files.isSymbolicLink(p)||Files.size(p)<4096){
                    stage="REQUIRED_SIGNED_LIBRARIES_ABSENT";return false;
                }
            }
            JSONObject manifest=readManifest(ctx);
            if(!"ISOLATED_STAGING_ONLY_NOT_SELECTED_FOR_WINE".equals(
                    manifest.optString("mode"))
                    ||!"librm11_vkloader_v473.so".equals(manifest.optString("loader"))
                    ||!"librm11_vkdriver_v473.so".equals(manifest.optString("freedreno_icd"))){
                stage="PRIVATE_X11_STAGE_MANIFEST_INVALID";return false;
            }
            JSONArray libs=manifest.getJSONArray("native_libraries");
            if(libs.length()<2 || libs.length()>90){
                stage="PRIVATE_X11_CLOSURE_COUNT_INVALID";return false;
            }
            boolean checkedLoader=false,checkedDriver=false;
            for(int i=0;i<libs.length();i++){
                JSONObject item=libs.getJSONObject(i);
                String name=item.getString("apk_library"),expected=item.getString("sha256");
                if(!name.matches("librm11_vk_[A-Za-z0-9_]+[.]so")
                        &&!"librm11_vkloader_v473.so".equals(name)
                        &&!"librm11_vkdriver_v473.so".equals(name)){
                    stage="PRIVATE_X11_CLOSURE_NAME_INVALID";return false;
                }
                if(!expected.matches("[0-9a-f]{64}")){
                    stage="PRIVATE_X11_CLOSURE_HASH_INVALID";return false;
                }
                Path p=layout.apkNativeLibs.resolve(name);
                if(!Files.isRegularFile(p,LinkOption.NOFOLLOW_LINKS)
                        ||Files.isSymbolicLink(p) || Files.size(p)<4096
                        ||!expected.equals(digest(p))) {
                    stage="PRIVATE_X11_CLOSURE_MISMATCH";return false;
                }
                checkedLoader|=name.equals("librm11_vkloader_v473.so");
                checkedDriver|=name.equals("librm11_vkdriver_v473.so");
            }
            if(!checkedLoader || !checkedDriver){
                stage="X11_LOADER_OR_ICD_NOT_ATTESTED";return false;
            }
            // A desktop Vulkan loader requires an ICD JSON, never Android HAL.
            Path directory=ctx.getFilesDir().toPath().resolve("offline-diagnostics");
            Files.createDirectories(directory);
            Path json=directory.resolve("v49028-mini-desktop-vulkan.json");
            if(Files.isSymbolicLink(json)){
                stage="ICD_JSON_SYMLINK_DENIED";return false;
            }
            JSONObject config=new JSONObject();
            JSONObject driver=new JSONObject();
            driver.put("library_path",icd.toString());
            driver.put("api_version","1.3.0");
            config.put("file_format_version","1.0.0");
            config.put("ICD",driver);
            Files.write(json,config.toString().getBytes(StandardCharsets.UTF_8),
                    StandardOpenOption.CREATE,StandardOpenOption.TRUNCATE_EXISTING,
                    StandardOpenOption.WRITE);
            env.put("VK_DRIVER_FILES",json.toString());
            env.put("VK_ICD_FILENAMES",json.toString());
            env.put("MESA_VK_WSI_DEBUG","sw");
            env.put("HOME",ctx.getFilesDir().toString());
            Path cache=ctx.getCacheDir().toPath().resolve("rm11-v49028-x11-vk");
            Files.createDirectories(cache);
            env.put("XDG_CACHE_HOME",cache.toString());
            env.put("MESA_SHADER_CACHE_DIR",cache.toString());
            env.put("RM11_V49028_MINI_X11_WSI","1");
            env.put("RM11_V49028_NATIVE_LIB_DIR",layout.apkNativeLibs.toString());
            String current=env.get("LD_PRELOAD");
            env.put("LD_PRELOAD",bridge.toString()+
                    (current==null||current.isEmpty()?"":" "+current));
            stage="X11_WSI_REQUESTED_NO_GPU_CLAIM";
            return true;
        }catch(Exception e){
            stage="SETUP_ERROR_"+e.getClass().getSimpleName();
            return false;
        }finally{
            OfflineDiagnosticJournal.record(ctx,"v49028-mini-x11-wsi",
                    "RM11_V49028_X11_WSI_STAGE="+stage+"\\n"+
                    "RM11_V49028_ONLY_MINI_D3D11="+mini+"\\n"+
                    "RM11_V49032_SELECTED_CARX_STREET="+carx+"\\n"+
                    "RM11_V49028_MESA_SOFTWARE_PRESENT_MODE=true\\n"+
                    "RM11_V49028_HARDWARE_ACCELERATION_UNVERIFIED=true");
        }
    }
}
