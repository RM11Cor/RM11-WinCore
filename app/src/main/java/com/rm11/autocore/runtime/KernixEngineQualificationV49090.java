package com.rm11.autocore.runtime;

import android.content.Context;
import android.os.Build;
import org.json.JSONArray;
import org.json.JSONObject;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

/**
 * v49090: single engine acceptance contract. An APK, Wine process, Vulkan
 * instance, driver dlopen or an X11 root window is NEVER a game-frame proof.
 * Record only results from built-in native probes after they actually run on
 * the device. Probe receipts are version/device scoped and app-private.
 *
 * The seven mandatory stages remain PENDING until trusted on-device probes
 * supply real evidence. This class does NOT promote build-time tests to
 * device qualifications and never edits a game or the Wine prefix.
 */
public final class KernixEngineQualificationV49090 {
    private KernixEngineQualificationV49090(){}
    public static final String[] REQUIRED={
        "WINE_FEX_WIN32_EXIT",
        "WIN32_X11_VISIBLE_FRAME",
        "NATIVE_VULKAN_GPU_QUEUE",
        "NATIVE_VULKAN_WSI_PRESENT",
        "WINE_DXVK_D3D11_VISIBLE_FRAMES",
        "WINE_VKD3D_D3D12_VISIBLE_FRAMES",
        "WINDOWS_XINPUT_ACTUAL_READ"
    };
    public static final String PENDING="DEVICE_PROOF_REQUIRED";
    public static final String VERIFIED="DEVICE_PROOF_RECORDED";
    private static final String SCHEMA="kernix.engine.device-proof.v49090";
    private static final long TTL_MS=7L*24*60*60*1000;

    public static boolean mandatoryComplete(boolean[] stages){
        if(stages==null||stages.length!=REQUIRED.length)return false;
        for(boolean b:stages)if(!b)return false;
        return true;
    }
    public static String firstMissing(boolean[] stages){
        if(stages==null||stages.length!=REQUIRED.length)return REQUIRED[0];
        for(int i=0;i<stages.length;i++)if(!stages[i])return REQUIRED[i];
        return "NONE";
    }
    private static int index(String stage){
        if(stage==null)return -1;
        for(int i=0;i<REQUIRED.length;i++)if(REQUIRED[i].equals(stage))return i;
        return -1;
    }
    private static Path receipt(Context context,String stage){
        return context.getFilesDir().toPath().resolve("kernix-engine-proof-v49090-"+
                stage+".json");
    }
    private static long version(Context ctx){
        try{return ctx.getPackageManager().getPackageInfo(
            ctx.getPackageName(),0).getLongVersionCode();}
        catch(Exception e){return -1;}
    }
    private static boolean safeRecord(Context ctx,String stage,boolean pass){
        if(ctx==null||index(stage)<0||!pass)return false;
        try{
            JSONObject j=new JSONObject();
            j.put("schema",SCHEMA);
            j.put("stage",stage);
            j.put("versionCode",version(ctx));
            j.put("androidSdk",Build.VERSION.SDK_INT);
            j.put("device",Build.MODEL);
            j.put("timestamp",System.currentTimeMillis());
            j.put("nativeResultValidated",true);
            Path target=receipt(ctx,stage);
            Path pending=target.resolveSibling(target.getFileName()+".pending");
            if(Files.isSymbolicLink(target)||Files.isSymbolicLink(pending))
                return false;
            Files.write(pending,j.toString().getBytes(StandardCharsets.UTF_8));
            try{Files.move(pending,target,StandardCopyOption.REPLACE_EXISTING,
                StandardCopyOption.ATOMIC_MOVE);}
            catch(java.nio.file.AtomicMoveNotSupportedException unsupported){
                Files.move(pending,target,StandardCopyOption.REPLACE_EXISTING);
            }
            return true;
        }catch(Exception e){return false;}
    }
    /** Adreno/Turnip GPU queue execution with validated read-back, not a frame. */
    public static boolean recordGpuQueue(Context ctx,JSONObject nativeResult){
        if(nativeResult==null)return false;
        return safeRecord(ctx,"NATIVE_VULKAN_GPU_QUEUE",
            "rm11.turnip-gpu-transfer.v1".equals(nativeResult.optString("schema"))
            &&nativeResult.optBoolean("queue_submit_success",false)
            &&nativeResult.optBoolean("fence_completed",false)
            &&nativeResult.optBoolean("gpu_buffer_readback_match",false)
            &&nativeResult.optLong("vendor_id",0)!=0);
    }
    /** A native present result is not independent proof of visible pixels. */
    public static boolean recordNativeWsi(Context ctx,JSONObject nativeResult){
        if(nativeResult==null)return false;
        return safeRecord(ctx,"NATIVE_VULKAN_WSI_PRESENT",
            nativeResult.optBoolean("success",false)
            &&nativeResult.optInt("frames",0)>=60
            &&nativeResult.optInt("width",0)>0
            &&nativeResult.optInt("height",0)>0
            &&nativeResult.optInt("vkResult",-999)==0);
    }
    /**
     * v49091: persist the LAST attempt even on driver failure or Android
     * process abort. The RUNNING marker is written before native code, so an
     * interrupted test is distinguishable from a never-run test.
     * A new attempt revokes a stale previously-successful same-stage proof.
     */
    public static boolean recordProbeAttempt(Context ctx,String stage,
             String outcome,String nativeStage){
        if(ctx==null||index(stage)<0
            ||!("RUNNING".equals(outcome)||"PASS".equals(outcome)
                ||"FAIL".equals(outcome)))return false;
        try{
            String safeStage=nativeStage==null?"UNKNOWN":
                nativeStage.replaceAll("[^A-Za-z0-9_.-]","_");
            if(safeStage.length()>80)safeStage=safeStage.substring(0,80);
            JSONObject j=new JSONObject();
            j.put("schema","kernix.engine.probe-attempt.v49091");
            j.put("stage",stage);
            j.put("outcome",outcome);
            j.put("nativeStage",safeStage);
            j.put("timestamp",System.currentTimeMillis());
            j.put("versionCode",version(ctx));
            j.put("sdk",Build.VERSION.SDK_INT);
            j.put("device",Build.MODEL);
            // Isolated native GPU probes run in another Android process.
            // SharedPreferences caches are not a reliable cross-process
            // transport; use an atomic file receipt in app-private storage.
            Path dest=attemptFile(ctx,stage);
            Path tmp=dest.resolveSibling(dest.getFileName()+".pending");
            if(Files.isSymbolicLink(dest)||Files.isSymbolicLink(tmp))return false;
            Files.write(tmp,j.toString().getBytes(StandardCharsets.UTF_8));
            try{Files.move(tmp,dest,StandardCopyOption.REPLACE_EXISTING,
                StandardCopyOption.ATOMIC_MOVE);}
            catch(java.nio.file.AtomicMoveNotSupportedException unsupported){
                Files.move(tmp,dest,StandardCopyOption.REPLACE_EXISTING);
            }
            if("RUNNING".equals(outcome)||"FAIL".equals(outcome))
                Files.deleteIfExists(receipt(ctx,stage));
            return true;
        }catch(Exception ignored){return false;}
    }
    private static Path attemptFile(Context context,String stage){
        return context.getFilesDir().toPath().resolve(
            "kernix-engine-attempt-v49091-"+stage+".json");
    }
    private static JSONObject lastAttempt(Context ctx,String stage){
        if(ctx==null)return null;
        try{
            Path source=attemptFile(ctx,stage);
            if(Files.isSymbolicLink(source)
                ||!Files.isRegularFile(source,LinkOption.NOFOLLOW_LINKS)
                ||Files.size(source)>2048)return null;
            JSONObject j=new JSONObject(new String(
                Files.readAllBytes(source),StandardCharsets.UTF_8));
            long now=System.currentTimeMillis(),at=j.optLong("timestamp",0);
            if(!"kernix.engine.probe-attempt.v49091".equals(j.optString("schema"))
                ||!stage.equals(j.optString("stage"))
                ||j.optLong("versionCode",-1)!=version(ctx)
                ||j.optInt("sdk",-1)!=Build.VERSION.SDK_INT
                ||!Build.MODEL.equals(j.optString("device"))
                ||at<=0||now<at||now-at>TTL_MS)return null;
            return j;
        }catch(Exception ignored){return null;}
    }
    private static boolean validReceipt(Context ctx,String stage){
        try{
            Path p=receipt(ctx,stage);
            if(Files.isSymbolicLink(p)
                ||!Files.isRegularFile(p,LinkOption.NOFOLLOW_LINKS)
                ||Files.size(p)>2048)return false;
            JSONObject j=new JSONObject(new String(
                Files.readAllBytes(p),StandardCharsets.UTF_8));
            long at=j.optLong("timestamp",0),now=System.currentTimeMillis();
            return SCHEMA.equals(j.optString("schema"))
                &&stage.equals(j.optString("stage"))
                &&j.optLong("versionCode",-1)==version(ctx)
                &&j.optInt("androidSdk",-1)==Build.VERSION.SDK_INT
                &&Build.MODEL.equals(j.optString("device"))
                &&j.optBoolean("nativeResultValidated",false)
                &&at>0 &&now>=at &&now-at<=TTL_MS;
        }catch(Exception ignored){return false;}
    }
    public static JSONObject snapshot(Context ctx){
        JSONObject j=new JSONObject();
        try{
            j.put("schema","kernix.engine.qualification.v49090");
            j.put("componentInstalledIsNotRuntimeProof",true);
            j.put("gameCompatibilityIsNotProvenByBuild",true);
            j.put("noUserGameFilesModified",true);
            boolean[] proofs=new boolean[REQUIRED.length];
            JSONArray checks=new JSONArray();
            for(int i=0;i<REQUIRED.length;i++){
                proofs[i]=ctx!=null &&validReceipt(ctx,REQUIRED[i]);
                JSONObject row=new JSONObject();
                row.put("stage",REQUIRED[i]);
                row.put("state",proofs[i]?VERIFIED:PENDING);
                JSONObject attempt=lastAttempt(ctx,REQUIRED[i]);
                if(attempt!=null)row.put("lastAttempt",attempt);
                checks.put(row);
            }
            j.put("checks",checks);
            boolean complete=mandatoryComplete(proofs);
            j.put("qualified",complete);
            j.put("state",complete?"ENGINE_DEVICE_QUALIFIED":"ENGINE_NOT_YET_QUALIFIED");
            j.put("firstMissing",firstMissing(proofs));
            j.put("fullyGameCompatible",false);
            j.put("releaseGate","NEEDS_SAME_DEVICE_ALL_STAGE_PROOFS");
        }catch(Exception ignored){}
        return j;
    }
}
