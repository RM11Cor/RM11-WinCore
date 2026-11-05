package com.rm11.autocore.runtime;

import android.content.Context;
import android.content.SharedPreferences;
import org.json.JSONObject;
import org.json.JSONArray;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Locale;

/**
 * Explicit, per-EXE settings. Only reads/writes private preferences.
 * A graphics profile never changes Wine prefix/registry, original game files,
 * system GPU driver or the user's working universal controller.
 */
public final class R4GameRuntimeConfigV49066 {
    private R4GameRuntimeConfigV49066() {}
    private static final String PREF="r4_v49066_per_game_graphics";
    public static final String AUTO="AUTO",WINED3D="WINED3D",
                               DXVK="DXVK",VKD3D="VKD3D";
    private static String key(File game){
        if(game==null)return null;
        try{
            String canonical=game.getCanonicalPath();
            byte[] sha=MessageDigest.getInstance("SHA-256").digest(
                    canonical.getBytes(StandardCharsets.UTF_8));
            StringBuilder text=new StringBuilder("profile_");
            for(int i=0;i<16;i++)text.append(String.format(Locale.ROOT,"%02x",sha[i]&255));
            return text.toString();
        }catch(Exception e){return null;}
    }
    private static boolean valid(String mode){
        return AUTO.equals(mode)||WINED3D.equals(mode)||DXVK.equals(mode)
                ||VKD3D.equals(mode);
    }
    public static String get(Context ctx,File game){
        String key=key(game);
        if(ctx==null||key==null)return AUTO;
        String value=ctx.getSharedPreferences(PREF,0).getString(key,AUTO);
        // Never use a saved DX12 choice after its on-device proof expires.
        return valid(value) && (!VKD3D.equals(value)||deviceVkd3dQualified(ctx))
            ?value:AUTO;
    }
    /**
     * v49128: explicit VKD3D is unlocked by three INDEPENDENT same-device
     * qualifications, never merely by files packaged in the APK.
     * Slots 2, 3 and 5 are Adreno GPU queue, Vulkan WSI Present and
     * Windows x64 VKD3D D3D12 visible frames. A stale saved setting does
     * not bypass this gate, and the legacy Wine game launcher is unchanged.
     */
    static boolean mayEnableVkd3d(boolean provider,boolean[] stages){
        return provider && stages!=null
            &&stages.length==KernixEngineQualificationV49090.REQUIRED.length
            &&stages[2]&&stages[3]&&stages[5];
    }
    public static boolean deviceVkd3dQualified(Context ctx){
        if(ctx==null||!R4Vkd3dV49073.hasBundledProvider(ctx))return false;
        try{
            JSONObject status=KernixEngineQualificationV49090.snapshot(ctx);
            JSONArray checks=status.optJSONArray("checks");
            if(checks==null||checks.length()!=
                    KernixEngineQualificationV49090.REQUIRED.length)return false;
            boolean[] stages=new boolean[checks.length()];
            for(int i=0;i<checks.length();i++){
                JSONObject check=checks.getJSONObject(i);
                if(!KernixEngineQualificationV49090.REQUIRED[i]
                        .equals(check.optString("stage")))return false;
                stages[i]=KernixEngineQualificationV49090.VERIFIED
                    .equals(check.optString("state"));
            }
            return mayEnableVkd3d(true,stages);
        }catch(Exception ignored){return false;}
    }
    public static boolean save(Context ctx,File game,String mode){
        String key=key(game);
        if(ctx==null||key==null||!valid(mode))return false;
        // A real same-device VKD3D frame receipt is mandatory.
        if(VKD3D.equals(mode)&&!deviceVkd3dQualified(ctx))return false;
        return ctx.getSharedPreferences(PREF,0).edit().putString(key,mode).commit();
    }
    public static JSONObject describe(Context ctx,File exe){
        JSONObject j=new JSONObject();
        try{
            String mode=get(ctx,exe);
            boolean carx=CarXStreetDxvkV49032.isSelectedCarXStreet(exe.toPath());
            j.put("mode",mode);
            j.put("lockedCarx",false);
            j.put("label",label(mode));
            j.put("wine",nativeExists(ctx,"libwine.so")?"present":"integrated-runtime");
            j.put("dxvk",hasApkDxvk(ctx)?"signed-asset-present":"asset-missing");
            j.put("vkd3d",deviceVkd3dQualified(ctx)
                ?"same-device-dx12-frames-verified-selectable"
                :"not-verified-not-selectable");
            j.put("turnip","native-gpu-wsi-unverified");
            j.put("winebus","existing-shared-controller-unchanged");
        }catch(Exception ignored){}
        return j;
    }
    public static String label(String mode){
        if(WINED3D.equals(mode))return "WineD3D";
        if(DXVK.equals(mode))return "DXVK تجريبي";
        if(VKD3D.equals(mode))return "VKD3D غير جاهز";
        return "تلقائي";
    }
    private static boolean nativeExists(Context ctx,String name){
        return ctx!=null && new File(ctx.getApplicationInfo().nativeLibraryDir,name).isFile();
    }
    public static boolean hasApkDxvk(Context ctx){
        if(ctx==null)return false;
        try{
            // Presence is NOT proof of actual Wine loading or rendered frames.
            try(java.io.InputStream x=ctx.getAssets().open(
                "engine/providers/dxvk/x64/d3d11.dll");
                java.io.InputStream y=ctx.getAssets().open(
                "engine/providers/dxvk/x64/dxgi.dll");
                java.io.InputStream manifest=ctx.getAssets().open(
                "engine/engine-bundle-manifest.json")){
                return x.read()=='M' && y.read()=='M' && manifest.read()=='{';
            }
        }catch(Exception ignored){return false;}
    }
}
