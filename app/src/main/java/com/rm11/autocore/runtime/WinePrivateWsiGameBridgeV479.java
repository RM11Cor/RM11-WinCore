package com.rm11.autocore.runtime;

import android.content.Context;
import org.json.JSONObject;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Map;

/** Proof-gated private Mesa Vulkan in a user-selected Wine EXE child ONLY.
 * No change to wineserver, Wine desktop, game files or global Android GPU.
 */
public final class WinePrivateWsiGameBridgeV479 {
    private WinePrivateWsiGameBridgeV479(){}

    static boolean isApprovedV478(String result) {
        return result!=null
            &&result.contains("RM11_V478_CHILD_EXIT=0")
            &&result.contains("RM11_V478_WSI_OVERRIDE=sw")
            &&result.contains("RM11_V477_VK_CREATE_SWAPCHAIN_RESULT=0")
            &&result.contains("RM11_V477_VK_QUEUE_PRESENT_RESULT=0")
            &&result.contains("RM11_V477_PRESENT_STATUS=MAGENTA_FRAME_SUBMITTED_VIA_XLIB")
            &&result.contains("RM11_V477_PROCESS_COMPLETED=0");
    }

    public static String configure(Context app,RuntimeLayout layout,Map<String,String> env) {
        if(app==null||layout==null||env==null)return "DENIED_INVALID_ARGUMENT";
        try {
            Path diag=app.getFilesDir().toPath().resolve("offline-diagnostics");
            Path proof=diag.resolve("last-v478-x11-software-wsi.json");
            if(!Files.isRegularFile(proof,LinkOption.NOFOLLOW_LINKS)
                    ||Files.size(proof)>18000)return "SKIPPED_NO_V478_PROOF";
            JSONObject snapshot=new JSONObject(new String(Files.readAllBytes(proof),
                    StandardCharsets.UTF_8));
            if(!"v478-x11-software-wsi-audit".equals(snapshot.optString("test"))
                    ||!isApprovedV478(snapshot.optString("result")))
                return "SKIPPED_V478_GPU_PRESENT_UNVERIFIED";

            Path loader=layout.apkNativeLibs.resolve("librm11_vkloader_v473.so");
            Path icd=layout.apkNativeLibs.resolve("librm11_vkdriver_v473.so");
            if(!Files.isRegularFile(loader,LinkOption.NOFOLLOW_LINKS)
                    ||!Files.isRegularFile(icd,LinkOption.NOFOLLOW_LINKS)
                    ||Files.size(loader)<4096||Files.size(icd)<4096)
                return "SKIPPED_PRIVATE_MESA_SIGNED_LIBRARIES_MISSING";

            Path config=diag.resolve("v479-game-freedreno-icd.json");
            if(Files.isSymbolicLink(config))return "DENIED_ICD_CONFIG_SYMLINK";
            JSONObject manifest=new JSONObject();
            manifest.put("file_format_version","1.0.0");
            JSONObject driver=new JSONObject();
            driver.put("library_path",icd.toString());
            driver.put("api_version","1.3.0");
            manifest.put("ICD",driver);
            Files.write(config,manifest.toString().getBytes(StandardCharsets.UTF_8),
                    StandardOpenOption.CREATE,StandardOpenOption.TRUNCATE_EXISTING,
                    StandardOpenOption.WRITE);
            Path cache=app.getCacheDir().toPath().resolve("rm11-v479-mesa");
            Files.createDirectories(cache);
            // Match the triple that presented magenta in v478.
            env.put("RM11_V479_PRIVATE_VULKAN_GAME","1");
            env.put("MESA_VK_WSI_DEBUG","sw");
            env.put("VK_DRIVER_FILES",config.toString());
            env.put("VK_ICD_FILENAMES",config.toString());
            env.put("HOME",app.getFilesDir().toString());
            env.put("XDG_CACHE_HOME",cache.toString());
            env.put("MESA_SHADER_CACHE_DIR",cache.toString());
            // Fail closed instead of reverting to proprietary Android loader.
            env.put("RM11_V458_ANDROID_VULKAN_FALLBACK","0");
            return "ENABLED_GAME_ONLY_SW_WSI";
        }catch(Exception e){
            return "SKIPPED_SETUP_"+e.getClass().getSimpleName();
        }
    }
}
