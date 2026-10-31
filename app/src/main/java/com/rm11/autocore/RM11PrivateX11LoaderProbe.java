package com.rm11.autocore;

import android.content.Context;
import com.rm11.autocore.runtime.MiniX11VulkanV49028;
import com.rm11.autocore.runtime.RuntimeLayout;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import org.json.JSONObject;

/** v49093: checks the signed desktop Vulkan LOADER, not a bare Mesa ICD.
 * Isolated Android diagnostic process only; no user files, Wine or games.
 * X11 surface creation, presentation, DXVK and GPU gameplay are NOT proven.
 */
public final class RM11PrivateX11LoaderProbe {
    private RM11PrivateX11LoaderProbe(){}
    private static native String nativeProbe(String loader,String icdJson);

    public static JSONObject run(Context context)throws Exception {
        if(context==null)throw new IllegalArgumentException("CONTEXT_REQUIRED");
        Path libs=new File(context.getApplicationInfo().nativeLibraryDir).toPath();
        RuntimeLayout layout=new RuntimeLayout(context.getFilesDir().toPath(),libs);
        Map<String,String> env=new HashMap<>();
        if(!MiniX11VulkanV49028.configure(context,layout,env,true))
            throw new IllegalStateException("PRIVATE_SIGNED_X11_LOADER_SETUP_UNAVAILABLE");
        Path loader=libs.resolve("librm11_vkloader_v473.so");
        String configured=env.get("VK_DRIVER_FILES");
        if(configured==null)throw new IllegalStateException("ICD_JSON_NOT_PREPARED");
        Path icd=java.nio.file.Paths.get(configured);
        if(!Files.isRegularFile(loader,LinkOption.NOFOLLOW_LINKS)
                ||Files.isSymbolicLink(loader)
                ||!Files.isRegularFile(icd,LinkOption.NOFOLLOW_LINKS)
                ||Files.isSymbolicLink(icd))
            throw new IllegalStateException("PRIVATE_LOADER_OR_ICD_JSON_UNAVAILABLE");
        System.loadLibrary("rm11_private_x11_loader_probe_v49093");
        JSONObject result=new JSONObject(nativeProbe(loader.toString(),icd.toString()));
        if(!"kernix.private-x11-loader.v49093".equals(result.optString("schema"))
                ||result.optBoolean("swapchainPresented",false)
                ||result.optBoolean("realGameFrameProven",false)
                ||result.optBoolean("wineD3dFrameProven",false))
            throw new IllegalStateException("PRIVATE_X11_LOADER_REPORT_INVALID");
        return result;
    }
}
