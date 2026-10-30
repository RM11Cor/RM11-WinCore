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

/**
 * App-owned Windows app-local XInput deployment for all validated Win64 games.
 *
 * In v49050 Wine did NOT load our private XInput via WINEPATH (zero native
 * GetState reads). An already-verified CarX graphics sidecar is used directly;
 * other games receive an isolated copy of the PE and symlinked original assets.
 * NEVER modify the game's original directory or the shared Wine prefix.
 *
 * The three verified PE DLLs are installed alongside the effective EXE,
 * before Wine runs it, so Windows' application-directory DLL precedence applies.
 * This is a native XInput API, NOT Android keyboard mapping.
 */
public final class UniversalAppLocalPadV49051 {
    private UniversalAppLocalPadV49051() {}
    private static final String[] INPUT_DLLS={
        "xinput1_4.dll","xinput1_3.dll","xinput9_1_0.dll"
    };
    private static final long MAX_EXE_BYTES=768L*1024*1024;
    private static final int MAX_SIBLINGS=1200;

    public static final class Result {
        public final Path exe;
        public final String status;
        private Result(Path exe,String status){this.exe=exe;this.status=status;}
        public boolean ready(){return exe!=null;}
    }
    private static String sha(Path source)throws Exception{
        MessageDigest dig=MessageDigest.getInstance("SHA-256");
        try(InputStream in=Files.newInputStream(source)){
            byte[] buf=new byte[65536];
            for(int n;(n=in.read(buf))!=-1;)dig.update(buf,0,n);
        }
        return hex(dig.digest());
    }
    private static String hex(byte[] bytes){
        StringBuilder out=new StringBuilder(bytes.length*2);
        for(byte b:bytes)out.append(String.format(Locale.ROOT,"%02x",b&255));
        return out.toString();
    }
    private static boolean reserved(String name,String exe){
        if(name.equalsIgnoreCase(exe))return true;
        for(String dll:INPUT_DLLS)if(name.equalsIgnoreCase(dll))return true;
        return false;
    }
    private static void installVerifiedDlls(Path library,Path stage)throws Exception {
        for(String name:INPUT_DLLS){
            Path src=library.resolve(name),dst=stage.resolve(name);
            if(Files.isSymbolicLink(src)||Files.isSymbolicLink(dst)
                    ||!Files.isRegularFile(src,LinkOption.NOFOLLOW_LINKS)
                    ||Files.size(src)<4096)
                throw new java.io.IOException("UNTRUSTED_APP_LOCAL_DLL_"+name);
            Files.copy(src,dst,StandardCopyOption.REPLACE_EXISTING);
            if(!sha(src).equals(sha(dst)))
                throw new java.io.IOException("APP_LOCAL_DLL_SHA256_MISMATCH_"+name);
        }
    }
    /**
     * @param source original PE that NovaWineExeLauncher.validate() approved
     * @param effective executable currently chosen (CarX graphics sidecar, or source)
     * @param route previous SHA-verified v49049 installation result
     */
    public static Result stage(Context app,Path source,Path effective,String route){
        String status="NOT_STARTED";
        Path chosen=null;
        try {
            if(app==null||source==null||effective==null
                    ||!"GLOBAL_XINPUT_WINDOWS_PATH_CONFIGURED_NEEDS_GAME_POLL".equals(route))
                return new Result(null,status="DENIED_XINPUT_DLLS_NOT_VERIFIED");
            if(Files.isSymbolicLink(source)||!Files.isRegularFile(source,LinkOption.NOFOLLOW_LINKS))
                return new Result(null,status="DENIED_UNTRUSTED_ORIGINAL_PE");
            Path root=app.getFilesDir().toPath().toRealPath();
            Path library=root.resolve("rm11-universal-xinput-v49049");
            if(Files.isSymbolicLink(library)||!Files.isDirectory(library,LinkOption.NOFOLLOW_LINKS)
                    ||!library.toRealPath().startsWith(root))
                return new Result(null,status="DENIED_PRIVATE_LIBRARY_ROOT");
            Path sourceReal=source.toRealPath();
            Path effectiveReal=effective.toRealPath();
            Path stage;
            if(effectiveReal.startsWith(root)
                    &&"carx-app-local-v49034".equals(
                            effectiveReal.getParent().getFileName().toString())){
                // CarX already has a SHA-verified private EXE copy and symlinked
                // assets for DXVK. Reuse it, preserving that graphics route.
                stage=effectiveReal.getParent();
                chosen=effectiveReal;
                status="CARX_SIGNED_GRAPHICS_SIDECAR_PLUS_XINPUT";
            }else{
                long size=Files.size(sourceReal);
                if(size<512||size>MAX_EXE_BYTES)
                    return new Result(null,status="DENIED_EXE_SIZE_OUT_OF_BOUNDS");
                String identity=hex(MessageDigest.getInstance("SHA-256").digest(
                        sourceReal.toString().getBytes(StandardCharsets.UTF_8))).substring(0,24);
                stage=root.resolve("rm11-xinput-app-local-v49051-"+identity);
                if(Files.isSymbolicLink(stage))
                    return new Result(null,status="DENIED_SIDECAR_SYMLINK");
                Files.createDirectories(stage);
                if(!stage.toRealPath().startsWith(root))
                    return new Result(null,status="DENIED_PRIVATE_STAGE_ESCAPE");
                Path sourceParent=sourceReal.getParent().toRealPath();
                int count=0;
                try(DirectoryStream<Path> entries=Files.newDirectoryStream(sourceParent)){
                    for(Path entry:entries){
                        if(++count>MAX_SIBLINGS)
                            return new Result(null,status="DENIED_TOO_MANY_GAME_SIBLINGS");
                        String name=entry.getFileName().toString();
                        if(reserved(name,sourceReal.getFileName().toString()))continue;
                        if(Files.isSymbolicLink(entry))
                            return new Result(null,status="DENIED_UNTRUSTED_SOURCE_SYMLINK");
                        Path target=entry.toRealPath();
                        if(!target.getParent().equals(sourceParent))
                            return new Result(null,status="DENIED_SOURCE_ESCAPE");
                        Path mirror=stage.resolve(name);
                        if(Files.isSymbolicLink(mirror)){
                            if(!Files.readSymbolicLink(mirror).equals(target))
                                return new Result(null,status="DENIED_EXISTING_LINK_COLLISION");
                        }else if(Files.exists(mirror,LinkOption.NOFOLLOW_LINKS)){
                            return new Result(null,status="DENIED_EXISTING_STAGE_COLLISION");
                        }else Files.createSymbolicLink(mirror,target);
                    }
                }
                chosen=stage.resolve(sourceReal.getFileName().toString());
                if(Files.isSymbolicLink(chosen))
                    return new Result(null,status="DENIED_STAGE_EXE_SYMLINK");
                // A previous build's probe EXE can retain exactly the same
                // byte length despite different code. v49054 device proof:
                // size-only cache returned DENIED_STAGE_EXE_HASH_MISMATCH,
                // forcing Wine builtin XInput (1167) on controller probe.
                // Compare authenticated content, not merely file size.
                boolean fresh=Files.isRegularFile(chosen,LinkOption.NOFOLLOW_LINKS)
                        &&Files.size(chosen)==size
                        &&sha(sourceReal).equals(sha(chosen));
                if(!fresh){
                    Files.copy(sourceReal,chosen,StandardCopyOption.REPLACE_EXISTING);
                }
                if(!sha(sourceReal).equals(sha(chosen)))
                    return new Result(null,status="DENIED_STAGE_EXE_HASH_MISMATCH");
                status="GENERIC_APP_PRIVATE_EXE_AND_ASSETS_MIRRORED";
            }
            installVerifiedDlls(library,stage);
            status+="_XINPUT_3_DLLS_HASH_VERIFIED";
            return new Result(chosen,status);
        }catch(Exception error){
            return new Result(null,status="DENIED_"+error.getClass().getSimpleName());
        }finally {
            if(app!=null)OfflineDiagnosticJournal.record(app,"v49051-app-local-xinput",
                "RM11_V49051_STAGE="+status+"\n"
                +"RM11_V49051_STAGED_APP_OWNED="+(chosen!=null)+"\n"
                +"RM11_V49051_ORIGINAL_GAME_FILES_UNCHANGED=true\n"
                +"RM11_V49051_KEYBOARD_FALLBACK=DISABLED\n"
                +"RM11_V49051_DLL_LOAD_GAME_PROOF=NEEDS_WIN32_GETSTATE_READS");
        }
    }
}
