package com.rm11.autocore.runtime;

import android.content.Context;
import android.os.Build;
import org.json.JSONObject;
import java.io.File;

/** Read-only real component inventory for KERNIX, never gameplay proof.
 * Does not initialize Wine/X11, download binaries or edit user game files. */
public final class KernixEngineStatusV49079 {
    private KernixEngineStatusV49079(){}
    public static String state(boolean present){return present?"present":"absent";}
    public static JSONObject snapshot(Context context){
        JSONObject json=new JSONObject();
        if(context==null)return json;
        try{
            json.put("schema","kernix.engine.snapshot.v1");
            json.put("device",Build.MODEL);
            json.put("sdk",Build.VERSION.SDK_INT);
            String version="unknown";
            try{version=context.getPackageManager().getPackageInfo(
                context.getPackageName(),0).versionName;}catch(Exception ignored){}
            json.put("version",version);
            json.put("wine",state(R4ManualComponentsV49069.versions(
                context,R4ManualComponentsV49069.WINE)[0].installed));
            json.put("fex",state(R4ManualComponentsV49069.versions(
                context,R4ManualComponentsV49069.FEX)[0].installed));
            json.put("x11",state(R4ManualComponentsV49069.versions(
                context,R4ManualComponentsV49069.X11)[0].installed));
            json.put("dxvk",state(R4GameRuntimeConfigV49066.hasApkDxvk(context)));
            json.put("vkd3d",R4Vkd3dV49073.hasBundledProvider(context)
                ?"experimental":"absent");
            json.put("vulkan",R4AutoGraphicsV49071.hasSoftwareWsi(context)
                ?"experimental":"absent");
            json.put("controller","experimental");
            json.put("gameplayProof","NOT_ATTESTED_BY_APK");
            json.put("dataMigration","PRESERVE_EXISTING_LIBRARY_AND_PROFILES");
        }catch(Exception ignored){}
        return json;
    }
}
