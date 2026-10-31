package com.rm11.autocore.runtime;

import android.content.Context;
import com.rm11.autocore.diagnostics.OfflineDiagnosticJournal;
import org.json.JSONObject;
import java.io.InputStream;
import java.io.ByteArrayOutputStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Locale;
import java.util.Map;

/**
 * v49103. Windows D3D12 device test only. Stages exact SHA-pinned Windows
 * VKD3D-Proton 3.0.1 d3d12/d3d12core plus DXVK dxgi next to our own test
 * EXE. Does not edit real games, Wine prefix, or DLLs in Windows system32.
 */
public final class MiniVkd3dRouteV49103 {
    private MiniVkd3dRouteV49103(){}
    private static final String ASSET="runtime/engine-probes-dx12/";
    private static final String EXE="KERNIX-D3D12-DEVICE.exe";
    private static final String FRAME_EXE="KERNIX-D3D12-FRAMES.exe";
    private static final String FRAME_ASSET="runtime/engine-probes-dx12-frame/";
    private static final String FRAME_TRACE="KERNIX_D3D12_FRAMES_PROGRESS_V49106.txt";
    private static final String V3PIN=
        "3cf2315522af5e43605ef6d3c41dad91387040bf97199934f3f7ab76caaa2f0c";
    private static final long MAX=64L*1024*1024;
    private static String hash(byte[] bytes)throws Exception{
        byte[] digest=MessageDigest.getInstance("SHA-256").digest(bytes);
        StringBuilder out=new StringBuilder(64);
        for(byte b:digest)out.append(String.format(Locale.ROOT,"%02x",b&255));
        return out.toString();
    }
    private static byte[] read(InputStream input,int max)throws Exception {
        ByteArrayOutputStream buf=new ByteArrayOutputStream();
        byte[] block=new byte[8192]; int n;
        while((n=input.read(block))!=-1){
            if(n==0)continue;
            if(buf.size()+n>max)throw new IllegalStateException("DX12_ASSET_TOO_LARGE");
            buf.write(block,0,n);
        }
        return buf.toByteArray();
    }
    private static JSONObject manifest(Context ctx,String path)throws Exception {
        try(InputStream input=ctx.getAssets().open(path)){
            return new JSONObject(new String(read(input,65536),
                StandardCharsets.UTF_8));
        }
    }
    private static void copyChecked(Context ctx,String source,Path target,
                                    String sha,long max)throws Exception{
        if(!sha.matches("[0-9a-f]{64}"))throw new IllegalStateException("BAD_SHA");
        if(Files.isSymbolicLink(target))throw new IllegalStateException("TARGET_SYMLINK");
        Path pending=target.resolveSibling(target.getFileName()+".pending");
        if(Files.isSymbolicLink(pending))throw new IllegalStateException("TEMP_SYMLINK");
        MessageDigest md=MessageDigest.getInstance("SHA-256");
        long count=0;
        try(InputStream in=ctx.getAssets().open(source);
            java.io.OutputStream out=Files.newOutputStream(pending)){
            byte[] block=new byte[65536];int n;
            while((n=in.read(block))!=-1){
                if(n==0)continue;
                count+=n;if(count>max)throw new IllegalStateException("DX12_FILE_TOO_LARGE");
                md.update(block,0,n);out.write(block,0,n);
            }
        }
        StringBuilder received=new StringBuilder();
        for(byte b:md.digest())received.append(String.format(Locale.ROOT,"%02x",b&255));
        if(count<4096||!received.toString().equals(sha)){
            Files.deleteIfExists(pending);
            throw new IllegalStateException("DX12_COPY_SHA_MISMATCH");
        }
        Files.move(pending,target,StandardCopyOption.REPLACE_EXISTING);
    }
    /**
     * Use the SAME validated Wine C: root as the signed D3D11 engine probe.
     * The previous v49103 app-files root was rejected by NovaWineExeLauncher
     * before Wine started (EXE must be under Wine C: or authorized Android D:).
     * Only an app-authored, SHA-verified DX12 test is staged here.
     */
    private static Path wineEngineTestRoot(Context ctx,boolean create)throws Exception{
        RuntimeLayout layout=new RuntimeLayout(ctx.getFilesDir().toPath(),
            java.nio.file.Paths.get(ctx.getApplicationInfo().nativeLibraryDir));
        Path app=ctx.getFilesDir().toPath().toRealPath();
        Path drive=layout.winePrefix.resolve("drive_c");
        if(Files.isSymbolicLink(drive)
            ||!Files.isDirectory(drive,LinkOption.NOFOLLOW_LINKS)
            ||!drive.toRealPath().startsWith(app))
            throw new IllegalStateException("DX12_WINE_C_DRIVE_NOT_READY");
        Path kernix=drive.resolve("KERNIX");
        if(Files.isSymbolicLink(kernix))
            throw new IllegalStateException("DX12_KERNIX_DIR_SYMLINK");
        if(create)Files.createDirectories(kernix);
        Path root=kernix.resolve("engine-tests");
        if(Files.isSymbolicLink(root))
            throw new IllegalStateException("DX12_TEST_ROOT_SYMLINK");
        if(create)Files.createDirectories(root);
        if(Files.exists(root,LinkOption.NOFOLLOW_LINKS)){
            if(!Files.isDirectory(root,LinkOption.NOFOLLOW_LINKS)
                ||!root.toRealPath().startsWith(drive.toRealPath()))
                throw new IllegalStateException("DX12_TEST_ROOT_OUTSIDE_WINE_C");
        }
        return root;
    }
    public static Path stage(Context ctx)throws Exception{return stageSelected(ctx,false);}
    public static Path stageFrames(Context ctx)throws Exception{return stageSelected(ctx,true);}
    private static Path stageSelected(Context ctx,boolean frames)throws Exception{
        if(ctx==null)throw new IllegalArgumentException("CONTEXT_REQUIRED");
        if(!R4Vkd3dV49073.hasBundledProvider(ctx))
            throw new IllegalStateException("VKD3D_PROVIDER_UNAVAILABLE");
        String asset=frames?FRAME_ASSET:ASSET;
        String exe=frames?FRAME_EXE:EXE;
        String schema=frames?"kernix.win64-d3d12-frame.v49106":
            "kernix.win64-vkd3d-device.v49103";
        JSONObject exeManifest=manifest(ctx,asset+"manifest.json");
        if(!schema.equals(exeManifest.optString("schema"))
            ||!exe.equals(exeManifest.optString("name"))
            ||!exeManifest.optString("sha256").matches("[0-9a-f]{64}"))
            throw new IllegalStateException("DX12_TEST_MANIFEST_NOT_TRUSTED");
        JSONObject vkd3d=manifest(ctx,"engine/providers/vkd3d/vkd3d-provider.json");
        if(!"v3.0.1".equals(vkd3d.optString("upstream_tag"))
            ||!V3PIN.equals(vkd3d.optString("upstream_archive_sha256")))
            throw new IllegalStateException("VKD3D_UPSTREAM_PIN_MISMATCH");
        JSONObject dxvk=manifest(ctx,"engine/engine-bundle-manifest.json");
        if(!"rm11.engine.bundle.v1".equals(dxvk.optString("schema")))
            throw new IllegalStateException("DXVK_BUNDLE_MANIFEST_NOT_TRUSTED");
        JSONObject dxgi=dxvk.getJSONObject("dxvk").getJSONObject("pe_files")
                .getJSONObject("dxgi.dll");
        if(!"assets/engine/providers/dxvk/x64/dxgi.dll".equals(
                dxgi.optString("apk_path")))
            throw new IllegalStateException("DXGI_BUNDLE_PATH_WRONG");
        Path root=wineEngineTestRoot(ctx,true);
        String folder=(frames?"mini-vkd3d-v49106-":"mini-vkd3d-v49103-")
            +exeManifest.getString("sha256").substring(0,20);
        Path dest=root.resolve(folder);
        if(Files.isSymbolicLink(dest))throw new IllegalStateException("DX12_DIR_SYMLINK");
        Files.createDirectories(dest);
        if(!dest.toRealPath().startsWith(root.toRealPath()))
            throw new IllegalStateException("DX12_PATH_ESCAPES_APP");
        for(String dll:new String[]{"d3d12.dll","d3d12core.dll"}){
            copyChecked(ctx,"engine/providers/vkd3d/x64/"+dll,dest.resolve(dll),
                vkd3d.getJSONObject("files").getString(dll),MAX);
        }
        copyChecked(ctx,"engine/providers/dxvk/x64/dxgi.dll",
            dest.resolve("dxgi.dll"),dxgi.getString("sha256"),MAX);
        Path target=dest.resolve(exe);
        copyChecked(ctx,asset+exe,target,exeManifest.getString("sha256"),4L*1024*1024);
        // Fresh result for each attempt, never treat old frames as current.
        Path oldTrace=dest.resolve(frames?FRAME_TRACE:
            "KERNIX_D3D12_DEVICE_PROGRESS_V49103.txt");
        if(Files.isSymbolicLink(oldTrace))
            throw new IllegalStateException("DX12_TRACE_SYMLINK");
        Files.deleteIfExists(oldTrace);
        return target;
    }
    public static String readProgress(Context ctx){
        try{
            JSONObject manifest=manifest(ctx,ASSET+"manifest.json");
            String sha=manifest.optString("sha256");
            if(!sha.matches("[0-9a-f]{64}"))return "KERNIX_D3D12_TRACE=INVALID_MANIFEST";
            Path root=wineEngineTestRoot(ctx,false);
            Path target=root.resolve("mini-vkd3d-v49103-"+sha.substring(0,20))
                .resolve("KERNIX_D3D12_DEVICE_PROGRESS_V49103.txt");
            if(Files.isSymbolicLink(target)
                ||!Files.isRegularFile(target,LinkOption.NOFOLLOW_LINKS))
                return "KERNIX_D3D12_TRACE=NOT_WRITTEN";
            if(Files.size(target)>4096)
                return "KERNIX_D3D12_TRACE=OVERSIZE";
            String raw=new String(Files.readAllBytes(target),StandardCharsets.UTF_8);
            StringBuilder safe=new StringBuilder();
            for(String line:raw.split("\\r?\\n")){
                if(line.matches("KERNIX_V49103_D3D12_STAGE=[A-Z0-9_]+ HRESULT=0x[0-9A-Fa-f]{8}"))
                    safe.append(line).append('\n');
            }
            return safe.length()>0?safe.toString():"KERNIX_D3D12_TRACE=NO_VALID_LINES";
        }catch(Exception e){return "KERNIX_D3D12_TRACE=READ_ERROR_"+
            e.getClass().getSimpleName();}
    }

    public static String readFrameProgress(Context ctx){
        try{
            JSONObject m=manifest(ctx,FRAME_ASSET+"manifest.json");
            String sha=m.optString("sha256");
            if(!sha.matches("[0-9a-f]{64}"))
                return "KERNIX_V49106_FRAME_TRACE=INVALID_MANIFEST";
            Path file=wineEngineTestRoot(ctx,false)
                .resolve("mini-vkd3d-v49106-"+sha.substring(0,20))
                .resolve(FRAME_TRACE);
            if(Files.isSymbolicLink(file)
                ||!Files.isRegularFile(file,LinkOption.NOFOLLOW_LINKS))
                return "KERNIX_V49106_FRAME_TRACE=NOT_WRITTEN";
            if(Files.size(file)>16384)
                return "KERNIX_V49106_FRAME_TRACE=OVERSIZE";
            StringBuilder safe=new StringBuilder();
            for(String line:new String(Files.readAllBytes(file),
                    StandardCharsets.UTF_8).split("\\r?\\n")){
                if(line.matches("KERNIX_V49106_STAGE=[A-Z0-9_]+ HRESULT=0x[0-9A-Fa-f]{8}")
                    ||line.matches("KERNIX_V49106_PRESENT FRAME=[0-9]{1,3} COLOR=[0-3] HRESULT=0x[0-9A-Fa-f]{8}")
                    ||line.matches("KERNIX_V49106_RESULT_FRAMES=[0-9]{1,3} EXPECTED=240 FAILED=[01]"))
                    safe.append(line).append('\n');
            }
            return safe.length()==0?"KERNIX_V49106_FRAME_TRACE=NO_VALID_LINES":
                safe.toString();
        }catch(Exception error){
            return "KERNIX_V49106_FRAME_TRACE=READ_ERROR_"+
                error.getClass().getSimpleName();
        }
    }

    public static boolean configure(Context ctx,Map<String,String> env,Path selected){
        try{
            if(selected==null||selected.getFileName()==null)return false;
            boolean frames=FRAME_EXE.equalsIgnoreCase(selected.getFileName().toString());
            if(!frames&&!EXE.equalsIgnoreCase(selected.getFileName().toString()))
                return false;
            Path effective=frames?stageFrames(ctx):stage(ctx);
            String dllRoot=effective.getParent().toString();
            env.put("RM11_MINI_VKD3D_STAGED_EXE",effective.toString());
            String prev=env.get("WINEDLLPATH");
            env.put("WINEDLLPATH",dllRoot+
                (prev==null||prev.isEmpty()?"":":"+prev));
            env.put("WINEDLLOVERRIDES",
                R4WineDllOverridesV49067.forDx12(env.get("WINEDLLOVERRIDES")));
            env.put("VKD3D_DEBUG","info");
            env.put("VKD3D_CONFIG","nodxr");
            env.put("DXVK_LOG_LEVEL","info");
            OfflineDiagnosticJournal.record(ctx,"v49103-mini-vkd3d-route",
                "KERNIX_V49103_SIGNED_MINI_VKD3D_DLLS=SHA_VERIFIED\n"
                +"KERNIX_V49103_D3D12_DEVICE_QUEUE=NOT_YET_TESTED\n"
                +"KERNIX_V49103_D3D12_VISIBLE_FRAME=NOT_TESTED\n"
                +"KERNIX_V49103_REAL_GAMES_UNCHANGED=true");
            return true;
        }catch(Exception error){
            OfflineDiagnosticJournal.record(ctx,"v49103-mini-vkd3d-route",
                "KERNIX_V49103_SETUP_FAILED="+error.getClass().getSimpleName()+"\n"
                +"KERNIX_V49103_D3D12_DEVICE_QUEUE=UNVERIFIED");
            return false;
        }
    }
}
