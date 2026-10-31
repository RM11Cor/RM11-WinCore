package com.rm11.autocore.runtime;

import android.content.Context;
import com.rm11.autocore.diagnostics.OfflineDiagnosticJournal;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.util.Locale;
import java.util.Map;

/**
 * User-opt-in, PER-GAME app-private DXVK installation based on signed PE
 * assets already included in R4. Never injects DLLs into the user's EXE folder.
 * An experiment, NOT proof of hardware Vulkan / rendered games.
 */
public final class R4GameDxvkV49066 {
    private R4GameDxvkV49066(){}
    private static final String[] DLLS={"d3d11.dll","dxgi.dll"};
    public static final class Result {
        public final Path exe;
        public final String status;
        private Result(Path p,String s){exe=p;status=s;}
        public boolean ready(){return exe!=null;}
    }
    private static String hash(Path p)throws Exception {
        byte[] digest=MessageDigest.getInstance("SHA-256").digest(
            p.toRealPath().toString().getBytes(StandardCharsets.UTF_8));
        StringBuilder b=new StringBuilder();
        for(int i=0;i<12;i++)b.append(String.format(Locale.ROOT,"%02x",digest[i]&255));
        return b.toString();
    }
    private static String fileHash(Path p)throws Exception {
        MessageDigest dig=MessageDigest.getInstance("SHA-256");
        try(InputStream in=Files.newInputStream(p)){
            byte[] buffer=new byte[64*1024];
            for(int n;(n=in.read(buffer))!=-1;)if(n>0)dig.update(buffer,0,n);
        }
        StringBuilder text=new StringBuilder();
        for(byte b:dig.digest())text.append(String.format(Locale.ROOT,"%02x",b&255));
        return text.toString();
    }
    private static boolean oneOf(String filename,String[] names){
        for(String name:names)if(name.equalsIgnoreCase(filename))return true;
        return false;
    }
    public static Result apply(Context ctx,RuntimeLayout layout,Path original,
                               Path inputEffective,Map<String,String> env){
        String status="NOT_STARTED";
        try{
            if(ctx==null||layout==null||original==null||env==null)
                return new Result(null,status="DENIED_ARGUMENTS");
            if(CarXStreetDxvkV49032.isSelectedCarXStreet(original))
                return new Result(null,status="CARX_REQUIRES_ORIGINAL_PROVEN_PATH");
            if(Files.isSymbolicLink(original)||
               !Files.isRegularFile(original,LinkOption.NOFOLLOW_LINKS))
                return new Result(null,status="DENIED_ORIGINAL_EXE");
            Path source=original.toRealPath(),dir=source.getParent().toRealPath();
            if(Files.size(source)<512||Files.size(source)>768L*1024*1024)
                return new Result(null,status="DENIED_EXE_SIZE");
            for(String dll:DLLS){
                if(Files.exists(dir.resolve(dll),LinkOption.NOFOLLOW_LINKS))
                    return new Result(null,status="DENIED_GAME_OWN_D3D_DLL_"+dll);
            }
            // The CarX provider uses the same authenticated APK manifest and
            // validates each DXVK PE DLL against a signed SHA-256 digest.
            Path provider=CarXStreetDxvkV49032.stageProvider(ctx);
            Path root=ctx.getFilesDir().toPath().toRealPath();
            Path stage=root.resolve("r4-game-dxvk-v49066-"+hash(source));
            if(Files.isSymbolicLink(stage))
                return new Result(null,status="DENIED_STAGE_SYMLINK");
            Files.createDirectories(stage);
            if(!stage.toRealPath().startsWith(root))
                return new Result(null,status="DENIED_OUTSIDE_APP_ROOT");
            // Preserve all game assets and original DLL dependencies with
            // symlinks ONLY inside app-private staging. No source file write.
            int entries=0,linked=0;
            try(DirectoryStream<Path> paths=Files.newDirectoryStream(dir)){
                for(Path item:paths){
                    if(++entries>1200)return new Result(null,status="DENIED_TOO_MANY_SIBLINGS");
                    if(Files.isSymbolicLink(item))
                        return new Result(null,status="DENIED_SOURCE_SYMLINK");
                    String name=item.getFileName().toString();
                    if(name.equalsIgnoreCase(source.getFileName().toString())
                        ||oneOf(name,DLLS))continue;
                    if(name.equalsIgnoreCase("xinput1_4.dll")
                        ||name.equalsIgnoreCase("xinput1_3.dll")
                        ||name.equalsIgnoreCase("xinput9_1_0.dll"))continue;
                    Path target=item.toRealPath();
                    if(!target.getParent().equals(dir))
                        return new Result(null,status="DENIED_SOURCE_ESCAPE");
                    Path dst=stage.resolve(name);
                    if(Files.isSymbolicLink(dst)){
                        if(!Files.readSymbolicLink(dst).equals(target))
                            return new Result(null,status="DENIED_STALE_SYMLINK");
                    }else if(Files.exists(dst,LinkOption.NOFOLLOW_LINKS)){
                        return new Result(null,status="DENIED_APP_PRIVATE_STAGE_COLLISION");
                    }else Files.createSymbolicLink(dst,target);
                    linked++;
                }
            }
            if(linked<1)return new Result(null,status="DENIED_NO_ASSET_SIBLINGS");
            // Carry over already-verified, app-local native gamepad DLLs,
            // preserving the universal XInput + Winebus controls.
            for(String name:new String[]{"xinput1_4.dll","xinput1_3.dll",
                                          "xinput9_1_0.dll"}){
                Path input=inputEffective==null?null:inputEffective.getParent().resolve(name);
                if(input==null||Files.isSymbolicLink(input)
                    ||!Files.isRegularFile(input,LinkOption.NOFOLLOW_LINKS))continue;
                if(!input.toRealPath().startsWith(root))continue;
                Path dst=stage.resolve(name);
                if(Files.isSymbolicLink(dst))
                    return new Result(null,status="DENIED_INPUT_STAGE_SYMLINK");
                Files.copy(input,dst,StandardCopyOption.REPLACE_EXISTING);
                if(!fileHash(input).equals(fileHash(dst)))
                    return new Result(null,status="DENIED_INPUT_COPY_SHA");
            }
            for(String name:DLLS){
                Path providerDll=provider.resolve(name),dest=stage.resolve(name);
                if(Files.isSymbolicLink(providerDll)||Files.isSymbolicLink(dest))
                    return new Result(null,status="DENIED_DXVK_SYMLINK");
                Files.copy(providerDll,dest,StandardCopyOption.REPLACE_EXISTING);
                if(!fileHash(providerDll).equals(fileHash(dest)))
                    return new Result(null,status="DENIED_DXVK_HASH_MISMATCH_"+name);
            }
            Path stagedExe=stage.resolve(source.getFileName().toString());
            if(Files.isSymbolicLink(stagedExe))
                return new Result(null,status="DENIED_STAGED_EXE_SYMLINK");
            Files.copy(source,stagedExe,StandardCopyOption.REPLACE_EXISTING);
            if(!fileHash(source).equals(fileHash(stagedExe)))
                return new Result(null,status="DENIED_STAGED_EXE_SHA");
            // Validate the authenticated X11 software WSI closure. If missing,
            // do not return an active DXVK process at all.
            if(!MiniX11VulkanV49028.configureSelectedGame(ctx,layout,env,true))
                return new Result(null,status="DENIED_NO_VERIFIED_X11_WSI");
            env.put("WINEDLLOVERRIDES",R4WineDllOverridesV49067.forGameGraphics(
                env.get("WINEDLLOVERRIDES"),true));
            env.put("DXVK_CONFIG","dxgi.syncInterval = 0");
            env.put("DXVK_LOG_LEVEL","info");
            env.put("R4_V49066_EXPLICIT_DXVK","1");
            status="OPT_IN_DXVK_APP_PRIVATE_WSI_SW_UNPROVEN";
            return new Result(stagedExe,status);
        }catch(Exception e){
            return new Result(null,status="DENIED_"+e.getClass().getSimpleName());
        }finally{
            if(ctx!=null)OfflineDiagnosticJournal.record(ctx,"v49066-user-dxvk-profile",
                "R4_V49066_DXVK_STATUS="+status+"\n"
                +"R4_V49066_ORIGINAL_GAME_BYTES_UNCHANGED=true\n"
                +"R4_V49066_SHARED_PREFIX_UNCHANGED=true\n"
                +"R4_V49066_GPU_PRESENT_UNVERIFIED=true\n"
                +"R4_V49066_WINEBUS_UNCHANGED=true");
        }
    }
}
