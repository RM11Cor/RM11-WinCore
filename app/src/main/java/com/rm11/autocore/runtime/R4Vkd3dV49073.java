package com.rm11.autocore.runtime;

import android.content.Context;
import com.rm11.autocore.diagnostics.OfflineDiagnosticJournal;
import org.json.JSONObject;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.LinkOption;
import java.nio.file.DirectoryStream;
import java.nio.file.StandardCopyOption;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Locale;
import java.util.Map;

/** v4.90.73: signed APK VKD3D-Proton x64 staging, experimental and
 * specifically NOT hardware Vulkan/presentation proof. Never writes to a
 * user's game files or global Wine prefix. Only called for a D3D12 game. */
public final class R4Vkd3dV49073 {
    private R4Vkd3dV49073(){}
    private static final String ROOT="engine/providers/vkd3d/x64/";
    private static final String MANIFEST="engine/providers/vkd3d/vkd3d-provider.json";
    private static final String PIN="3cf2315522af5e43605ef6d3c41dad91387040bf97199934f3f7ab76caaa2f0c";
    private static final String[] FILES={"d3d12.dll","d3d12core.dll"};
    public static final class Result {
        public final Path exe;
        public final String status;
        private Result(Path exe,String status){this.exe=exe;this.status=status;}
        public boolean ready(){return exe!=null;}
    }
    public static boolean isWitcherDx12(Path path){
        if(path==null||path.getFileName()==null)return false;
        Path parent=path.getParent();
        return "witcher3.exe".equalsIgnoreCase(path.getFileName().toString())
           &&parent!=null&&parent.getFileName()!=null
           &&"x64_dx12".equalsIgnoreCase(parent.getFileName().toString());
    }
    private static String sha(byte[] data)throws Exception{
        byte[] d=MessageDigest.getInstance("SHA-256").digest(data);
        StringBuilder s=new StringBuilder();
        for(byte b:d)s.append(String.format(Locale.ROOT,"%02x",b&255));
        return s.toString();
    }
    private static String fileSha(Path p)throws Exception{
        MessageDigest digest=MessageDigest.getInstance("SHA-256");
        try(InputStream in=Files.newInputStream(p)){
            byte[] buf=new byte[65536];
            for(int n;(n=in.read(buf))!=-1;)if(n>0)digest.update(buf,0,n);
        }
        StringBuilder b=new StringBuilder();
        for(byte n:digest.digest())b.append(String.format(Locale.ROOT,"%02x",n&255));
        return b.toString();
    }
    private static JSONObject providerManifest(Context ctx)throws Exception{
        byte[] data;
        try(InputStream in=ctx.getAssets().open(MANIFEST)){
            java.io.ByteArrayOutputStream out=new java.io.ByteArrayOutputStream();
            byte[] buf=new byte[8192];
            for(int n;(n=in.read(buf))!=-1;){
                if(out.size()+n>65536)throw new java.io.IOException("MANIFEST_TOO_LARGE");
                out.write(buf,0,n);
            }
            data=out.toByteArray();
        }
        JSONObject obj=new JSONObject(new String(data,StandardCharsets.UTF_8));
        if(!"rm11.v49073.vkd3d-proton-provider.v1".equals(obj.optString("schema"))
                ||!"v3.0.1".equals(obj.optString("upstream_tag"))
                ||!PIN.equals(obj.optString("upstream_archive_sha256")))
            throw new java.io.IOException("VKD3D_MANIFEST_PROVENANCE_FAILED");
        for(String name:FILES){
            String digest=obj.getJSONObject("files").getString(name);
            if(!digest.matches("[0-9a-f]{64}"))
                throw new java.io.IOException("VKD3D_INVALID_PE_HASH_"+name);
        }
        return obj;
    }
    /** Cheap UI readiness only; per-file hashes are verified on each stage. */
    public static boolean hasBundledProvider(Context ctx){
        if(ctx==null)return false;
        try {
            providerManifest(ctx);
            for(String f:FILES){
                try(InputStream in=ctx.getAssets().open(ROOT+f)){
                    if(in.read()!=0x4d||in.read()!=0x5a)return false;
                }
            }
            return R4GameRuntimeConfigV49066.hasApkDxvk(ctx)
                &&R4AutoGraphicsV49071.hasSoftwareWsi(ctx);
        }catch(Exception ignored){return false;}
    }
    private static Path stageOne(Context ctx,String name,String expected,Path dst)
            throws Exception{
        if(Files.isSymbolicLink(dst))throw new java.io.IOException("STAGE_SYMLINK_"+name);
        Path tmp=dst.resolveSibling(name+".pending");
        if(Files.isSymbolicLink(tmp))throw new java.io.IOException("PENDING_SYMLINK_"+name);
        MessageDigest digest=MessageDigest.getInstance("SHA-256");
        long size=0;
        try(InputStream in=ctx.getAssets().open(ROOT+name);
            OutputStream out=Files.newOutputStream(tmp)){
            byte[] buf=new byte[65536];
            for(int n;(n=in.read(buf))!=-1;){
                if(n==0)continue;
                size+=n;
                if(size>64L*1024*1024)throw new java.io.IOException("VKD3D_DLL_TOO_LARGE");
                out.write(buf,0,n);digest.update(buf,0,n);
            }
        }
        StringBuilder hash=new StringBuilder();
        for(byte b:digest.digest())hash.append(String.format(Locale.ROOT,"%02x",b&255));
        if(size<4096||!hash.toString().equals(expected)){
            Files.deleteIfExists(tmp);
            throw new java.io.IOException("VKD3D_DLL_HASH_MISMATCH_"+name);
        }
        Files.move(tmp,dst,StandardCopyOption.REPLACE_EXISTING);
        return dst;
    }
    public static Result prepare(Context ctx,RuntimeLayout layout,Path original,
                                 Path previousEffective,Map<String,String> env) {
        String status="NOT_STARTED";
        try{
            if(ctx==null||layout==null||original==null||env==null)
                return new Result(null,status="DENIED_ARGUMENTS");
            if(!hasBundledProvider(ctx))
                return new Result(null,status="DENIED_VKD3D_OR_VULKAN_PROVIDER_ABSENT");
            if(Files.isSymbolicLink(original)
                    ||!Files.isRegularFile(original,LinkOption.NOFOLLOW_LINKS))
                return new Result(null,status="DENIED_EXE_NOT_REGULAR");
            JSONObject manifest=providerManifest(ctx);
            Path source=original.toRealPath(),gameDir=source.getParent().toRealPath();
            if(Files.size(source)>768L*1024*1024)
                return new Result(null,status="DENIED_EXE_TOO_LARGE");
            for(String dll:new String[]{"d3d12.dll","d3d12core.dll","dxgi.dll"}){
                if(Files.exists(gameDir.resolve(dll),LinkOption.NOFOLLOW_LINKS))
                    return new Result(null,status="DENIED_GAME_OWN_"+dll);
            }
            Path app=ctx.getFilesDir().toPath().toRealPath();
            String pathKey=sha(source.toString().getBytes(StandardCharsets.UTF_8))
                .substring(0,24);
            Path stage=app.resolve("r4-vkd3d-v49073-"+pathKey);
            if(Files.isSymbolicLink(stage))return new Result(null,status="DENIED_STAGE_SYMLINK");
            Files.createDirectories(stage);
            if(!stage.toRealPath().startsWith(app))
                return new Result(null,status="DENIED_STAGE_ESCAPE");
            int siblings=0;
            try(DirectoryStream<Path> contents=Files.newDirectoryStream(gameDir)){
                for(Path item:contents){
                    if(++siblings>1500)
                        return new Result(null,status="DENIED_TOO_MANY_SIBLINGS");
                    String name=item.getFileName().toString();
                    if(name.equalsIgnoreCase(source.getFileName().toString()))continue;
                    if(Files.isSymbolicLink(item))
                        return new Result(null,status="DENIED_SOURCE_LINK");
                    Path target=item.toRealPath();
                    if(!target.getParent().equals(gameDir))
                        return new Result(null,status="DENIED_SOURCE_ESCAPE");
                    Path local=stage.resolve(name);
                    if(Files.isSymbolicLink(local)){
                        if(!Files.readSymbolicLink(local).equals(target))
                            return new Result(null,status="DENIED_STALE_SIDECAR_LINK");
                    }else if(Files.exists(local,LinkOption.NOFOLLOW_LINKS)){
                        return new Result(null,status="DENIED_SIDECAR_COLLISION");
                    }else Files.createSymbolicLink(local,target);
                }
            }
            for(String dll:FILES)stageOne(ctx,dll,
                manifest.getJSONObject("files").getString(dll),stage.resolve(dll));
            // Only SHA-attested DXGI from the already bundled DXVK provider.
            Path dxgi=CarXStreetDxvkV49032.stageProvider(ctx).resolve("dxgi.dll");
            Path localDxgi=stage.resolve("dxgi.dll");
            if(Files.isSymbolicLink(localDxgi))
                return new Result(null,status="DENIED_LOCAL_DXGI_SYMLINK");
            Files.copy(dxgi,localDxgi,StandardCopyOption.REPLACE_EXISTING);
            if(!fileSha(dxgi).equals(fileSha(localDxgi)))
                return new Result(null,status="DENIED_DXGI_HASH");
            Path targetExe=stage.resolve(source.getFileName());
            if(Files.isSymbolicLink(targetExe))
                return new Result(null,status="DENIED_EXE_SIDECAR_SYMLINK");
            Files.copy(source,targetExe,StandardCopyOption.REPLACE_EXISTING);
            if(!fileSha(source).equals(fileSha(targetExe)))
                return new Result(null,status="DENIED_EXE_COPY_HASH");
            // GPU X11/WSI is experimental. Fail closed if not attestable.
            if(!MiniX11VulkanV49028.configureSelectedGame(ctx,layout,env,true))
                return new Result(null,status="DENIED_X11_WSI_CLOSURE_NOT_READY");
            env.put("WINEDLLOVERRIDES",
                R4WineDllOverridesV49067.forDx12(env.get("WINEDLLOVERRIDES")));
            env.put("VKD3D_DEBUG","info");
            env.put("VKD3D_CONFIG","nodxr");
            env.put("DXVK_LOG_LEVEL","info");
            env.put("R4_V49073_EXPERIMENTAL_DX12","1");
            status="VKD3D_3_0_1_STAGED_X11_SW_WSI_GPU_UNVERIFIED";
            return new Result(targetExe,status);
        }catch(Exception e){
            return new Result(null,status="DENIED_"+e.getClass().getSimpleName()
                +(e.getMessage()==null?"":":"+e.getMessage()));
        }finally {
            if(ctx!=null)OfflineDiagnosticJournal.record(ctx,"v49073-vkd3d-dx12-route",
                "R4_V49073_STATUS="+status+"\n"
                +"R4_V49073_GAME_FILES_MODIFIED=false\n"
                +"R4_V49073_HARDWARE_VULKAN_VERIFIED=false\n"
                +"R4_V49073_D3D12_WINDOW_RENDERED=UNVERIFIED\n"
                +"R4_V49073_CONTROLLER_UNCHANGED=true");
        }
    }
}
