package com.rm11.autocore.runtime;

import android.content.Context;
import org.json.JSONObject;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Locale;

/**
 * v49105: OBSERVED D3D12 foundation on the actual device. Distinct from
 * the seven engine qualification stages. This never promotes device/queue
 * creation to D3D12 displayed frames or compatibility with any real game.
 *
 * Evidence requires exact Win32 progress from the SHA-matched signed probe
 * and matching native Wine/VKD3D/Adreno traces written in the same session.
 */
public final class KernixDx12DeviceEvidenceV49105 {
    private KernixDx12DeviceEvidenceV49105(){}
    private static final long TTL_MS=7L*24*60*60*1000;
    private static final long COHERENCE_MS=10L*60*1000;
    private static final String EXE="KERNIX-D3D12-DEVICE.exe";
    private static final String TRACE="KERNIX_D3D12_DEVICE_PROGRESS_V49103.txt";
    private static final String[] EXACT_SUCCESS={
        "KERNIX_V49103_D3D12_STAGE=PROGRAM_STARTED HRESULT=0x00000000",
        "KERNIX_V49103_D3D12_STAGE=D3D12_CREATE_DEVICE HRESULT=0x00000000",
        "KERNIX_V49103_D3D12_STAGE=D3D12_CREATE_COMMAND_QUEUE HRESULT=0x00000000",
        "KERNIX_V49103_D3D12_STAGE=D3D12_CREATE_COMMAND_ALLOCATOR HRESULT=0x00000000",
        "KERNIX_V49103_D3D12_STAGE=D3D12_DEVICE_QUEUE_COMPLETE HRESULT=0x00000000"
    };

    static boolean verifiedDeviceStages(String progress){
        if(progress==null||progress.length()>4096)return false;
        String[] lines=progress.trim().split("\\r?\\n");
        if(lines.length!=EXACT_SUCCESS.length)return false;
        for(int i=0;i<lines.length;i++)
            if(!EXACT_SUCCESS[i].equals(lines[i].trim()))return false;
        return true;
    }
    static boolean verifiedWineVkd3dTurnip(String wine){
        if(wine==null||wine.length()>200000)return false;
        String text=wine.toLowerCase(Locale.ROOT);
        if(!text.contains("found device: adreno") ||
            !text.contains("vkd3d-proton") ||
            !text.contains("applicationversion: 3.0.1") ||
            !text.contains("loaded") ||
            !text.contains("kernix-d3d12-device.exe"))return false;
        boolean d3d12=false,core=false,dxgi=false,exe=false;
        for(String line:text.split("\\r?\\n")){
            if(!line.contains("loaded")||!line.contains("native")||
               !line.contains("mini-vkd3d-v49103-"))continue;
            if(line.contains("d3d12.dll"))d3d12=true;
            if(line.contains("d3d12core.dll"))core=true;
            if(line.contains("dxgi.dll"))dxgi=true;
            if(line.contains("kernix-d3d12-device.exe"))exe=true;
        }
        return d3d12&&core&&dxgi&&exe;
    }
    static boolean coherentTimes(long progressTime,long wineTime,long now){
        return progressTime>0&&wineTime>0&&now>=progressTime&&
            now>=wineTime&&now-progressTime<=TTL_MS&&
            now-wineTime<=TTL_MS&&
            Math.abs(progressTime-wineTime)<=COHERENCE_MS;
    }
    private static String sha256(Path p)throws Exception{
        MessageDigest md=MessageDigest.getInstance("SHA-256");
        try(InputStream in=Files.newInputStream(p)){
            byte[] buf=new byte[32768];int n;
            while((n=in.read(buf))>=0){if(n>0)md.update(buf,0,n);}
        }
        StringBuilder out=new StringBuilder(64);
        for(byte b:md.digest())out.append(String.format(Locale.ROOT,"%02x",b&255));
        return out.toString();
    }
    private static String bounded(Path p,int max)throws Exception{
        if(Files.isSymbolicLink(p)
           ||!Files.isRegularFile(p,LinkOption.NOFOLLOW_LINKS)
           ||Files.size(p)<=0||Files.size(p)>max)return "";
        return new String(Files.readAllBytes(p),StandardCharsets.UTF_8);
    }
    public static JSONObject snapshot(Context ctx){
        JSONObject out=new JSONObject();
        try{
            out.put("schema","kernix.dx12.device-foundation.v49105");
            out.put("d3d12DeviceAndQueueVerified",false);
            out.put("win32DeviceQueueAllocatorComplete",false);
            out.put("wineNativeVkd3dOnAdreno",false);
            out.put("signedProbeMatchesCurrentApk",false);
            out.put("coherentOnDeviceRun",false);
            out.put("d3d12VisibleFramesVerified",false);
            out.put("actualGameCompatibilityVerified",false);
            out.put("note","Foundational D3D12 device smoke only; not GPU frames or game proof");
            if(ctx==null)return out;
            byte[] jsonBytes;
            try(InputStream in=ctx.getAssets().open("runtime/engine-probes-dx12/manifest.json")){
                jsonBytes=new byte[65537];
                int total=0,n;
                while((n=in.read(jsonBytes,total,jsonBytes.length-total))>0){
                    total+=n;if(total>=jsonBytes.length)return out;
                }
                if(total==0)return out;
                jsonBytes=java.util.Arrays.copyOf(jsonBytes,total);
            }
            JSONObject manifest=new JSONObject(new String(jsonBytes,StandardCharsets.UTF_8));
            if(!"kernix.win64-vkd3d-device.v49103".equals(
                    manifest.optString("schema")) ||
                !EXE.equals(manifest.optString("name")))return out;
            String sha=manifest.optString("sha256");
            if(!sha.matches("[0-9a-f]{64}"))return out;
            RuntimeLayout layout=new RuntimeLayout(ctx.getFilesDir().toPath(),
                java.nio.file.Paths.get(ctx.getApplicationInfo().nativeLibraryDir));
            Path drive=layout.winePrefix.resolve("drive_c");
            Path folder=drive.resolve("KERNIX/engine-tests/mini-vkd3d-v49103-"+
                sha.substring(0,20));
            Path executable=folder.resolve(EXE);
            if(Files.isSymbolicLink(folder)||Files.isSymbolicLink(executable)||
               !Files.isDirectory(folder,LinkOption.NOFOLLOW_LINKS)||
               !folder.toRealPath().startsWith(drive.toRealPath())||
               !Files.isRegularFile(executable,LinkOption.NOFOLLOW_LINKS)||
               Files.size(executable)!=manifest.optLong("bytes",-1)||
               Files.size(executable)>4*1024*1024||
               !sha.equals(sha256(executable)))return out;
            out.put("signedProbeMatchesCurrentApk",true);
            Path progressFile=folder.resolve(TRACE);
            Path wineFile=ctx.getFilesDir().toPath().resolve(
                "offline-diagnostics/last-mini-d3d12-wine-runtime.log");
            String progress=bounded(progressFile,4096);
            String wine=bounded(wineFile,200000);
            boolean win32=verifiedDeviceStages(progress);
            boolean vkd3d=verifiedWineVkd3dTurnip(wine);
            long a=Files.getLastModifiedTime(progressFile).toMillis();
            long b=Files.getLastModifiedTime(wineFile).toMillis();
            boolean sameRun=coherentTimes(a,b,System.currentTimeMillis());
            out.put("win32DeviceQueueAllocatorComplete",win32);
            out.put("wineNativeVkd3dOnAdreno",vkd3d);
            out.put("coherentOnDeviceRun",sameRun);
            out.put("d3d12DeviceAndQueueVerified",win32&&vkd3d&&sameRun);
        }catch(Exception ignored){}
        return out;
    }
}
