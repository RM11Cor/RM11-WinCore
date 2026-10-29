package com.rm11.autocore.runtime;

import android.content.Context;
import com.rm11.autocore.diagnostics.OfflineDiagnosticJournal;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.util.Locale;

/**
 * CarX Street only: Windows always searches the application directory for
 * native DLLs. v49033 proved WINEPATH=n,b did not select signed DXVK; Wine
 * loaded its builtin d3d11, and the game never created a viewable window.
 *
 * Stage only a PRIVATE copy of the game PE next to the previously SHA256
 * authenticated DXVK DLLs. All sibling files/folders are *symlinks* to their
 * original read-only targets, preserving Unity's *_Data folder and every
 * original byte. Never alter the original game tree or shared Wine prefix.
 *
 * The passed original EXE was already validated and user-authorized by
 * NovaWineExeLauncher.validate() before this path is reached.
 */
public final class CarXAppLocalDxvkV49034 {
    private CarXAppLocalDxvkV49034() {}
    private static final int MAX_CHILDREN=512;
    private static final long MAX_EXE_BYTES=512L*1024*1024;
    private static final String APP_DIR="carx-app-local-v49034";
    public static final class Result {
        public final Path exe;
        public final String status;
        private Result(Path exe,String status){this.exe=exe;this.status=status;}
        public boolean ready(){return exe!=null;}
    }

    static boolean exactGame(Path path){
        return path!=null && path.getFileName()!=null
            &&"carx street.exe".equals(path.getFileName().toString()
                .toLowerCase(Locale.ROOT));
    }
    private static String sha256(Path file)throws Exception{
        MessageDigest hash=MessageDigest.getInstance("SHA-256");
        try(InputStream in=Files.newInputStream(file)){
            byte[] buf=new byte[65536];int n;
            while((n=in.read(buf))!=-1)hash.update(buf,0,n);
        }
        StringBuilder out=new StringBuilder();
        for(byte b:hash.digest())out.append(String.format(Locale.ROOT,"%02x",b&255));
        return out.toString();
    }
    private static boolean isReserved(String filename,String basename){
        return filename.equalsIgnoreCase(basename)
            || filename.equalsIgnoreCase("d3d11.dll")
            || filename.equalsIgnoreCase("dxgi.dll");
    }
    public static Result prepare(Context app,Path selected,String signedDxvkStatus){
        if(!exactGame(selected))return new Result(null,"SKIPPED_NOT_DIRECT_CARX_EXE");
        String status="NOT_STARTED";
        Path original=selected;
        try {
            if(app==null || !"CARX_PRIVATE_X11_DXVK_WINEPATH_REQUESTED_LOAD_UNVERIFIED"
                    .equals(signedDxvkStatus))
                return new Result(null,status="DENIED_SIGNED_DXVK_ROUTE_MISSING");
            if(!Files.isRegularFile(original,LinkOption.NOFOLLOW_LINKS)
                    ||Files.isSymbolicLink(original))
                return new Result(null,status="DENIED_ORIGINAL_EXE_UNTRUSTED");
            long exeBytes=Files.size(original);
            if(exeBytes<512 || exeBytes>MAX_EXE_BYTES)
                return new Result(null,status="DENIED_EXE_BYTES_OUT_OF_BOUNDS");
            Path gameRoot=original.getParent().toRealPath();
            if(!original.toRealPath().getParent().equals(gameRoot))
                return new Result(null,status="DENIED_ORIGINAL_PATH_OUTSIDE_ROOT");
            Path provider=app.getFilesDir().toPath().resolve("carx-dxvk-v49032");
            Path stage=app.getFilesDir().toPath().resolve(APP_DIR);
            if(Files.isSymbolicLink(provider)||Files.isSymbolicLink(stage))
                return new Result(null,status="DENIED_STAGE_SYMLINK");
            for(String dll:new String[]{"d3d11.dll","dxgi.dll"}){
                Path trusted=provider.resolve(dll);
                if(!Files.isRegularFile(trusted,LinkOption.NOFOLLOW_LINKS)
                        ||Files.isSymbolicLink(trusted)||Files.size(trusted)<4096)
                    return new Result(null,status="DENIED_ATTESTED_DXVK_MISSING_"+dll);
            }
            Files.createDirectories(stage);
            int count=0,links=0;
            try(DirectoryStream<Path> entries=Files.newDirectoryStream(gameRoot)){
                for(Path entry:entries){
                    if(++count>MAX_CHILDREN)
                        return new Result(null,status="DENIED_GAME_DIRECTORY_TOO_MANY_ENTRIES");
                    String filename=entry.getFileName().toString();
                    if(isReserved(filename,original.getFileName().toString()))continue;
                    if(Files.isSymbolicLink(entry))
                        return new Result(null,status="DENIED_GAME_SOURCE_SYMLINK");
                    Path actual=entry.toRealPath();
                    if(!actual.getParent().equals(gameRoot))
                        return new Result(null,status="DENIED_SOURCE_OUTSIDE_GAME_ROOT");
                    Path destination=stage.resolve(filename);
                    if(Files.isSymbolicLink(destination)){
                        if(!Files.readSymbolicLink(destination).equals(actual))
                            return new Result(null,status="DENIED_EXISTING_LINK_MISMATCH");
                    } else if(Files.exists(destination,LinkOption.NOFOLLOW_LINKS)){
                        return new Result(null,status="DENIED_EXISTING_STAGE_COLLISION");
                    } else {
                        Files.createSymbolicLink(destination,actual);
                    }
                    if(!Files.exists(destination))
                        return new Result(null,status="DENIED_GAME_LINK_NOT_READABLE");
                    links++;
                }
            }
            if(links<1)
                return new Result(null,status="DENIED_GAME_ASSET_LINKS_EMPTY");

            // Authentication is performed in CarXStreetDxvkV49032 before
            // selecting this path. Verify byte-identical sidecar copies too.
            for(String dll:new String[]{"d3d11.dll","dxgi.dll"}){
                Path src=provider.resolve(dll),dst=stage.resolve(dll);
                if(Files.isSymbolicLink(dst))
                    return new Result(null,status="DENIED_DXVK_DST_SYMLINK");
                Files.copy(src,dst,StandardCopyOption.REPLACE_EXISTING);
                if(!sha256(src).equals(sha256(dst)))
                    return new Result(null,status="DENIED_DXVK_COPY_HASH_MISMATCH");
            }
            Path stagedExe=stage.resolve(original.getFileName().toString());
            if(Files.isSymbolicLink(stagedExe))
                return new Result(null,status="DENIED_EXE_DST_SYMLINK");
            Files.copy(original,stagedExe,StandardCopyOption.REPLACE_EXISTING);
            if(Files.size(stagedExe)!=exeBytes || !sha256(original).equals(sha256(stagedExe)))
                return new Result(null,status="DENIED_EXE_COPY_HASH_MISMATCH");

            status="APP_LOCAL_DXVK_NATIVE_FIRST_REQUESTED_ASSETS_LINKED="+links;
            return new Result(stagedExe,status);
        }catch(Exception e){
            return new Result(null,status="DENIED_"+e.getClass().getSimpleName());
        }finally{
            if(app!=null)
                OfflineDiagnosticJournal.record(app,"v49034-carx-sidecar",
                        "RM11_V49034_SELECTED_EXE="+original.getFileName()+"\n"
                        +"RM11_V49034_STATUS="+status+"\n"
                        +"RM11_V49034_ORIGINAL_GAME_CONTENT_UNCHANGED=true\n"
                        +"RM11_V49034_SHARED_PREFIX_UNCHANGED=true\n"
                        +"RM11_V49034_NATIVE_DXVK_LOAD_UNVERIFIED_UNTIL_WINE_LOG=true");
        }
    }
}
