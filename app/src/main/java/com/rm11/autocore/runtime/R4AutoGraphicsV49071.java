package com.rm11.autocore.runtime;

import android.content.Context;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.LinkOption;

/** R4 v4.90.71: runtime-only graphics choice, not a UI label or a game-name
 * whitelist. The observed PE import table is only a hint; shader/device
 * success must be demonstrated on Android with DXVK logs and X11 frames. */
public final class R4AutoGraphicsV49071 {
    private R4AutoGraphicsV49071(){}
    public static final class Decision {
        public final String mode,reason;
        public final boolean dxvkFiles,softwareWsi;
        private Decision(String mode,String reason,boolean dxvkFiles,boolean wsi){
            this.mode=mode;this.reason=reason;this.dxvkFiles=dxvkFiles;
            this.softwareWsi=wsi;
        }
    }
    public static String modeFor(String api,String engine,boolean dxvk,boolean wsi,
                                 boolean directX12,boolean anticheat){
        if(directX12||anticheat)return R4GameRuntimeConfigV49066.WINED3D;
        boolean d3d11=api!=null&&api.startsWith("Direct3D 11");
        boolean unity=engine!=null&&engine.startsWith("Unity");
        if((d3d11||unity)&&dxvk&&wsi)return R4GameRuntimeConfigV49066.DXVK;
        return R4GameRuntimeConfigV49066.WINED3D;
    }
    public static boolean hasSoftwareWsi(Context ctx){
        if(ctx==null)return false;
        String dir=ctx.getApplicationInfo().nativeLibraryDir;
        for(String name:new String[]{"librm11_vkloader_v473.so",
                     "librm11_vkdriver_v473.so",
                     "librm11_v49028_mini_x11_vulkan.so"}){
            File f=new File(dir,name);
            try{
                if(!Files.isRegularFile(f.toPath(),LinkOption.NOFOLLOW_LINKS)
                    ||Files.isSymbolicLink(f.toPath())||f.length()<4096)return false;
            }catch(Exception e){return false;}
        }
        return true;
    }
    public static Decision choose(Context ctx,GameCompatibilityV49064.Result profile,
                                  java.nio.file.Path requestedExe){
        boolean dxvk=R4GameRuntimeConfigV49066.hasApkDxvk(ctx);
        boolean wsi=hasSoftwareWsi(ctx);
        String mode=modeFor(profile.api,profile.engine,dxvk,wsi,
            profile.requiresDx12,profile.hasAntiCheat);
        boolean witcherClassic=R4WitcherExecutableV49072.classicDx11(
            requestedExe==null?null:requestedExe.toFile());
        if(witcherClassic && dxvk && wsi && !profile.hasAntiCheat)
            mode=R4GameRuntimeConfigV49066.DXVK;
        String reason=witcherClassic && R4GameRuntimeConfigV49066.DXVK.equals(mode)
            ?"WITCHER3_EXISTING_DX11_EXECUTABLE_DXVK_WSI_REQUESTED":
            profile.requiresDx12?"D3D12_DETECTED_VKD3D_NOT_AVAILABLE":
            profile.hasAntiCheat?"ANTICHEAT_PRESENT_NOT_SUPPORTED":
            R4GameRuntimeConfigV49066.DXVK.equals(mode)
                ?"D3D11_OR_UNITY_WITH_BUNDLED_DXVK_SOFTWARE_WSI":
                "SAFE_BUILTIN_FALLBACK_OR_API_UNKNOWN";
        return new Decision(mode,reason,dxvk,wsi);
    }
}
