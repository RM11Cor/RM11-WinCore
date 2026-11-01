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
     * v49102: only a NEW, app-authored Windows D3D11 test can certify
     * visible frames: validated DXGI device, 900 successful Presents in
     * native Win32 progress, AND >=2 distinct native-clear colors observed
     * by Android PixelCopy in that same test session.
     * Build success, one BLUE frame, stale test logs and mere Swapchain
     * creation are not sufficient. No D3D12 or all-games claim.
     */
    private static boolean hasExactLine(String progress,String line){
        if(progress==null||progress.length()>16384)return false;
        for(String row:progress.split("\\r?\\n"))
            if(line.equals(row.trim()))return true;
        return false;
    }
    public static boolean verifiedWin64Dx11Frames(String progress,int seenColors){
        return Integer.bitCount(seenColors&15)>=2
            &&hasExactLine(progress,
                "RM11_V49029_STAGE=CREATE_D3D11_DEVICE_SWAPCHAIN HRESULT=0x00000000")
            &&hasExactLine(progress,
                "RM11_V49029_STAGE=GET_BACK_BUFFER HRESULT=0x00000000")
            &&hasExactLine(progress,
                "RM11_V49029_STAGE=CREATE_RENDER_TARGET HRESULT=0x00000000")
            &&hasExactLine(progress,"KERNIX_V49101_RESULT_FRAMES=900 FAILED=0")
            &&hasExactLine(progress,"KERNIX_V49101_FINAL_COMPLETE=1 STATUS=0");
    }
    public static boolean recordWin64Dx11Frames(Context ctx,String progress,
                                                 int seenColors){
        return safeRecord(ctx,"WINE_DXVK_D3D11_VISIBLE_FRAMES",
            verifiedWin64Dx11Frames(progress,seenColors));
    }
    /**
     * v49107: strict DX12 Win64 device/frame evidence is separate from
     * successful Device+Queue and from the user's own game compatibility.
     * Win32 240 Presents, the native app-local VKD3D+DXGI loads on Adreno,
     * and >=2 separately observed Android Surface colors are all mandatory.
     */
    public static boolean verifiedWin64Dx12Frames(
            String progress,int seenColors,String wineLog){
        if(Integer.bitCount(seenColors&15)<2
            ||progress==null||progress.length()>16384
            ||wineLog==null||wineLog.length()>200000)return false;
        for(String stage:new String[]{
            "KERNIX_V49106_STAGE=PROGRAM_STARTED HRESULT=0x00000000",
            "KERNIX_V49106_STAGE=D3D12_CREATE_DEVICE HRESULT=0x00000000",
            "KERNIX_V49106_STAGE=D3D12_CREATE_COMMAND_QUEUE HRESULT=0x00000000",
            "KERNIX_V49106_STAGE=DXGI_CREATE_SWAPCHAIN HRESULT=0x00000000",
            "KERNIX_V49106_STAGE=DXGI_SWAPCHAIN3 HRESULT=0x00000000",
            "KERNIX_V49106_STAGE=D3D12_CREATE_COMMAND_LIST HRESULT=0x00000000",
            "KERNIX_V49106_STAGE=D3D12_CREATE_FENCE HRESULT=0x00000000",
            "KERNIX_V49106_STAGE=D3D12_FRAMES_PRESENT_COMPLETE HRESULT=0x00000000",
            "KERNIX_V49106_RESULT_FRAMES=240 EXPECTED=240 FAILED=0"}){
            if(!hasExactLine(progress,stage))return false;
        }
        for(int color=0;color<4;color++){
            String line="KERNIX_V49106_PRESENT FRAME="+(1+color*60)
                +" COLOR="+color+" HRESULT=0x00000000";
            if(!hasExactLine(progress,line))return false;
        }
        String lower=wineLog.toLowerCase(java.util.Locale.ROOT);
        if(!lower.contains("found device: adreno")
            ||!lower.contains("vkd3d-proton")
            ||!lower.contains("applicationversion: 3.0.1"))return false;
        boolean exe=false,dx12=false,core=false,dxgi=false;
        for(String line:lower.split("\\r?\\n")){
            if(!line.contains("loaded")||!line.contains("native")
               ||!line.contains("mini-vkd3d-v49106-"))continue;
            if(line.contains("kernix-d3d12-frames.exe"))exe=true;
            if(line.contains("d3d12.dll"))dx12=true;
            if(line.contains("d3d12core.dll"))core=true;
            if(line.contains("dxgi.dll"))dxgi=true;
        }
        return exe&&dx12&&core&&dxgi;
    }
    public static boolean recordWin64Dx12Frames(Context ctx,String progress,
                  int seenColors,String wineLog){
        return safeRecord(ctx,"WINE_VKD3D_D3D12_VISIBLE_FRAMES",
            verifiedWin64Dx12Frames(progress,seenColors,wineLog));
    }
    /**
     * v49109: reconcile a completed signed Windows 240-frame run after the
     * user closes its X11 Activity. The final Win32 trace can be written only
     * AFTER the last Android PixelCopy sample and the Activity may finish
     * before delayed UI verification. No game file is read or modified.
     *
     * A RUNNING attempt is never certified from historical color counts,
     * old Wine logs, an unverified DLL, or the user's visual report alone.
     */
    public static int verifiedDx12PixelMask(String result) {
        if(result==null||result.length()>4096
            ||!hasExactLine(result,"KERNIX_DX12_PIXELCOPY=SUCCESS")
            ||!hasExactLine(result,"KERNIX_DX12_EXPECTED_COLOR_VISIBLE=true"))
            return 0;
        int n=-1,mask=-1,index=-1;
        try{
            for(String line:result.split("\\r?\\n")){
                if(line.startsWith("KERNIX_V49106_DISTINCT_ANDROID_COLORS="))
                    n=Integer.parseInt(line.substring(line.indexOf('=')+1));
                else if(line.startsWith("KERNIX_V49106_COLOR_MASK="))
                    mask=Integer.parseInt(line.substring(line.indexOf('=')+1));
                else if(line.startsWith("KERNIX_V49106_SAMPLE_INDEX="))
                    index=Integer.parseInt(line.substring(line.indexOf('=')+1));
            }
        }catch(NumberFormatException ignored){return 0;}
        if(index<1||index>10||mask<1||mask>15||n<2||n>4
            ||Integer.bitCount(mask)!=n)return 0;
        return mask;
    }
    public static boolean reconcileCompletedDx12FrameProof(Context ctx){
        if(ctx==null)return false;
        final String stage="WINE_VKD3D_D3D12_VISIBLE_FRAMES";
        try{
            JSONObject attempt=lastAttempt(ctx,stage);
            if(attempt==null||!"RUNNING".equals(attempt.optString("outcome"))
                ||!"DX12_WIN64_240_FRAMES_AND_ANDROID_PIXELCOPY".equals(
                    attempt.optString("nativeStage")))return false;
            long start=attempt.optLong("timestamp",0);
            long now=System.currentTimeMillis();
            if(start<=0||now<start||now-start>120000)return false;
            Path journal=ctx.getFilesDir().toPath().resolve("offline-diagnostics");
            Path pixel=journal.resolve("last-v49106-dx12-visible-colors.json");
            Path winePath=journal.resolve("last-mini-d3d12-frames-wine-runtime.log");
            if(Files.isSymbolicLink(pixel)||Files.isSymbolicLink(winePath)
                ||!Files.isRegularFile(pixel,LinkOption.NOFOLLOW_LINKS)
                ||!Files.isRegularFile(winePath,LinkOption.NOFOLLOW_LINKS)
                ||Files.size(pixel)>4096||Files.size(winePath)>200000
                ||Files.size(winePath)<256)return false;
            JSONObject sample=new JSONObject(new String(
                Files.readAllBytes(pixel),StandardCharsets.UTF_8));
            long sampled=sample.optLong("timeUnixMs",0);
            if(!"v49106-dx12-visible-colors".equals(sample.optString("test"))
                ||sampled<start||sampled>now||sampled-start>60000
                ||Files.getLastModifiedTime(pixel).toMillis()<start
                ||Files.getLastModifiedTime(winePath).toMillis()<start)
                return false;
            int mask=verifiedDx12PixelMask(sample.optString("result"));
            if(Integer.bitCount(mask)<2)return false;
            String progress=MiniVkd3dRouteV49103.readFrameProgress(ctx);
            String wine=new String(Files.readAllBytes(winePath),
                StandardCharsets.UTF_8);
            if(!MiniVkd3dRouteV49103.frameEvidenceFromThisRun(ctx,start)
                ||!verifiedWin64Dx12Frames(progress,mask,wine))return false;
            boolean persisted=recordWin64Dx12Frames(ctx,progress,mask,wine);
            if(!persisted)return false;
            recordProbeAttempt(ctx,stage,"PASS",
                "RECOVERED_SIGNED_240_PRESENT_AND_ANDROID_PIXELS");
            com.rm11.autocore.diagnostics.OfflineDiagnosticJournal.record(ctx,
                "v49109-dx12-post-run-recovery",
                "KERNIX_V49109_SIGNED_CURRENT_RUN=true\n"
                +"KERNIX_V49109_WINDOWS_FRAMES=240\n"
                +"KERNIX_V49109_ANDROID_COLORS="+Integer.bitCount(mask)+"\n"
                +"KERNIX_V49109_DX12_FRAME_QUALIFICATION=PASS\n"
                +"KERNIX_V49109_REAL_GAMES=NOT_VERIFIED");
            return true;
        }catch(Exception ignored){return false;}
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
    /** Only the current APK's signed Proton receipt can certify this
     * single stage. It must never imply X11 pixels, DXVK or gameplay. */
    static boolean currentProtonWin64Evidence(JSONObject p){
        return p!=null
            &&p.optBoolean("assetsInstalled",false)
            &&p.optBoolean("separateWritablePrefix",false)
            &&p.optBoolean("nativeWin64GuestQualified",false)
            &&"PINNED_PREFIX_RESTART_ONLY".equals(p.optString("bootstrapMode"))
            &&!p.optBoolean("gameEngineActivated",true);
    }
    public static JSONObject snapshot(Context ctx){
        // v49110: the engine panel should reconcile the finished DX12
        // proof when returning from Wine, even before ZIP export.
        // This accepts ONLY the same-run signed and PixelCopy evidence;
        // it does not run a game or mark the other six stages successful.
        reconcileCompletedDx12FrameProof(ctx);
        JSONObject j=new JSONObject();
        try{
            j.put("schema","kernix.engine.qualification.v49090");
            j.put("componentInstalledIsNotRuntimeProof",true);
            j.put("gameCompatibilityIsNotProvenByBuild",true);
            j.put("noUserGameFilesModified",true);
            JSONObject p11=ctx==null?null:
                KernixProtonProvisioningV49129.snapshot(ctx);
            boolean p11Win64=currentProtonWin64Evidence(p11);
            j.put("protonWin64GuestEvidence",p11Win64
                ?"CURRENT_APK_SIGNED_PRIVATE_PREFIX_WIN64_EXIT47"
                :"NOT_YET_QUALIFIED");
            boolean[] proofs=new boolean[REQUIRED.length];
            JSONArray checks=new JSONArray();
            for(int i=0;i<REQUIRED.length;i++){
                proofs[i]=ctx!=null &&(validReceipt(ctx,REQUIRED[i])
                    ||(i==0&&p11Win64));
                JSONObject row=new JSONObject();
                row.put("stage",REQUIRED[i]);
                row.put("state",proofs[i]?VERIFIED:PENDING);
                if(i==0&&p11Win64)row.put("provenBy",
                    "PROTON_11_FEX_2610_SIGNED_WIN64_GUEST_EXIT47");
                JSONObject attempt=lastAttempt(ctx,REQUIRED[i]);
                if(attempt!=null)row.put("lastAttempt",attempt);
                checks.put(row);
            }
            j.put("checks",checks);
            // Previous device evidence is displayed honestly as historical.
            // Never convert older-version logs into a same-APK proof receipt.
            j.put("historicalDx11DeviceEvidence",
                KernixDx11DeviceEvidenceV49102.snapshot(ctx));
            // Foundation only: real on-device D3D12 device+queue+allocator.
            // A native VKD3D log NEVER certifies D3D12 frames / gameplay.
            j.put("dx12DeviceFoundation",
                KernixDx12DeviceEvidenceV49105.snapshot(ctx));
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
