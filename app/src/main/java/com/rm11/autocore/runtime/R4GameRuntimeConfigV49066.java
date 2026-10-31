package com.rm11.autocore.runtime;

import android.content.Context;
import android.content.SharedPreferences;
import org.json.JSONObject;
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
        return valid(value)?value:AUTO;
    }
    public static boolean save(Context ctx,File game,String mode){
        String key=key(game);
        if(ctx==null||key==null||!valid(mode))return false;
        // VKD3D is listed in the catalogue but cannot be enabled while its
        // binary, SHA-pinned manifest and hardware WSI remain unverified.
        if(VKD3D.equals(mode))return false;
        if(CarXStreetDxvkV49032.isSelectedCarXStreet(game.toPath())
             &&!AUTO.equals(mode))return false; // preserve proven CarX route
        return ctx.getSharedPreferences(PREF,0).edit().putString(key,mode).commit();
    }
    public static JSONObject describe(Context ctx,File exe){
        JSONObject j=new JSONObject();
        try{
            String mode=get(ctx,exe);
            boolean carx=CarXStreetDxvkV49032.isSelectedCarXStreet(exe.toPath());
            j.put("mode",mode);
            j.put("lockedCarx",carx);
            j.put("label",label(mode));
            j.put("wine",nativeExists(ctx,"libwine.so")?"present":"integrated-runtime");
            j.put("dxvk",hasApkDxvk(ctx)?"signed-asset-present":"asset-missing");
            j.put("vkd3d","not-verified-not-selectable");
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
