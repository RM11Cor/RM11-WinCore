package com.rm11.autocore.runtime;

import android.content.Context;
import android.os.Build;
import org.json.JSONObject;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.Locale;

/**
 * v49102: observed (historical) Windows D3D11 result is distinct from
 * current-APK engine certification. Combining actual Win32 output,
 * Wine-native DXVK load and Android PixelCopy color transitions is stronger
 * than claiming success from a blue screen or provider manifest.
 *
 * Strict current-APK certification continues to require an explicit
 * same-version qualified receipt in KernixEngineQualificationV49090.
 */
public final class KernixDx11DeviceEvidenceV49102 {
    private KernixDx11DeviceEvidenceV49102(){}
    private static final long TTL=7L*24*60*60*1000;
    private static final long WINDOW=10L*60*1000;

    static boolean fullProgress(String s){
        return hasLine(s,"KERNIX_V49101_RESULT_FRAMES=900 FAILED=0")
            &&hasLine(s,"KERNIX_V49101_FINAL_COMPLETE=1 STATUS=0")
            &&hasLine(s,"RM11_V49029_STAGE=CREATE_D3D11_DEVICE_SWAPCHAIN HRESULT=0x00000000");
    }
    private static boolean hasLine(String text,String line){
        if(text==null)return false;
        for(String l:text.split("\\r?\\n"))if(line.equals(l.trim()))return true;
        return false;
    }
    static boolean visibleTransitions(String report){
        if(report==null)return false;
        return hasLine(report,"KERNIX_DX11_PIXELCOPY=SUCCESS")
            &&hasLine(report,"KERNIX_DX11_COLOR_TRANSITION_PROVEN=true")
            &&(hasLine(report,"KERNIX_DX11_DISTINCT_COLORS_VISIBLE=2")
              ||hasLine(report,"KERNIX_DX11_DISTINCT_COLORS_VISIBLE=3")
              ||hasLine(report,"KERNIX_DX11_DISTINCT_COLORS_VISIBLE=4"));
    }
    static boolean dxvkNativeLoaded(String log){
        if(log==null)return false;
        String t=log.toLowerCase(Locale.ROOT);
        return t.contains("dxvk: v")
            &&t.contains("found device: adreno")
            &&t.contains("mini-dxvk-v49021")
            &&t.matches("(?s).*loaded.*d3d11\\\\.dll.*native.*")
            &&t.matches("(?s).*loaded.*dxgi\\\\.dll.*native.*");
    }
    static boolean verified(String win32,String pixelReport,String wine){
        return fullProgress(win32)
            &&visibleTransitions(pixelReport)
            &&dxvkNativeLoaded(wine);
    }
    private static String bounded(Path p,int max){
        try{
            if(Files.isSymbolicLink(p)
                ||!Files.isRegularFile(p,LinkOption.NOFOLLOW_LINKS)
                ||Files.size(p)>max)return "";
            return new String(Files.readAllBytes(p),StandardCharsets.UTF_8);
        }catch(Exception ignored){return "";}
    }
    private static long modified(Path p){
        try{return Files.getLastModifiedTime(p,LinkOption.NOFOLLOW_LINKS).toMillis();}
        catch(Exception ignored){return 0;}
    }
    public static JSONObject snapshot(Context ctx){
        JSONObject answer=new JSONObject();
        try{
            answer.put("schema","kernix.dx11.historical-device-observation.v49102");
            answer.put("note","Does not attest latest APK or all game compatibility");
            answer.put("currentApkCertified",false);
            answer.put("sameDeviceProof",false);
            answer.put("historicalDx11FrameResult","UNVERIFIED");
            if(ctx==null)return answer;
            Path app=ctx.getFilesDir().toPath(),journal=app.resolve("offline-diagnostics");
            Path originalProgress=app.resolve("mini-dxvk-v49021")
                .resolve("KERNIX_D3D11_ENGINE_PROGRESS_V49101.txt");
            Path lastColor=journal.resolve("last-v49100-dx11-visible-colors.json");
            Path wine=journal.resolve("last-mini-d3d11-wine-runtime.log");
            String progress=KernixWin32D3D11ProbeV49097.readRuntimeProgress(ctx);
            String colorText=bounded(lastColor,4096);
            String wineText=bounded(wine,65536);
            long now=System.currentTimeMillis(),wp=modified(originalProgress),
                wc=modified(lastColor),ww=modified(wine);
            boolean recent=wp>0 && wc>0 && ww>0 && now>=wp
                && now-wp<=TTL && Math.abs(wp-wc)<=WINDOW
                &&Math.abs(wp-ww)<=WINDOW;
            String visual="";
            if(!colorText.isEmpty()){
                JSONObject event=new JSONObject(colorText);
                if("v49100-dx11-visible-colors".equals(event.optString("test"))
                   &&Math.abs(event.optLong("timeUnixMs",0)-wc)<=WINDOW)
                    visual=event.optString("result");
            }
            boolean complete=fullProgress(progress);
            boolean changed=visibleTransitions(visual);
            boolean dxvk=dxvkNativeLoaded(wineText);
            answer.put("sameDeviceProof",recent && complete && changed && dxvk);
            answer.put("historicalDx11FrameResult",
                recent && complete && changed && dxvk
                    ?"PREVIOUS_ON_DEVICE_DX11_900_FRAMES_VALIDATED"
                    :"INSUFFICIENT_COHERENT_PROOF");
            answer.put("win32FrameLoop900",complete);
            answer.put("androidPixelColorChanges",changed);
            answer.put("wineNativeDxvkTurnip",dxvk);
            answer.put("evidenceTimeWindowMatched",recent);
            answer.put("actualHardwareTurnipWsiPerformanceCertified",false);
            answer.put("allGamesCompatible",false);
        }catch(Exception ignored){}
        return answer;
    }
}
