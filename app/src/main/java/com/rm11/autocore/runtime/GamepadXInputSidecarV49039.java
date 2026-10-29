package com.rm11.autocore.runtime;

import android.content.Context;
import com.rm11.autocore.diagnostics.OfflineDiagnosticJournal;
import java.io.InputStream;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.Locale;

/**
 * App-private EXE sidecar for general Windows games. Existing game folders
 * remain untouched; relative resource paths are linked to original assets.
 * No global Wine prefix changes. Fail closed on inaccessible paths.
 *
 * CarX Street keeps its own proven v49034 graphics sidecar; this universal
 * path is only for other selected user-authorized Win64 EXE games.
 */
public final class GamepadXInputSidecarV49039 {
    public static final class Result {
        public final Path exe;public final String status;
        Result(Path p,String s){exe=p;status=s;}
        public boolean ready(){return exe!=null;}
    }
    private static final int MAX_ENTRIES=1600;
    private static final long MAX_EXE_SIZE=512L*1024L*1024L;
    private GamepadXInputSidecarV49039(){}
    private static String hex(byte[] bytes){
        StringBuilder str=new StringBuilder();
        for(byte b:bytes)str.append(String.format(Locale.ROOT,"%02x",b&255));
        return str.toString();
    }
    private static String digest(byte[] bytes)throws Exception {
        return hex(MessageDigest.getInstance("SHA-256").digest(bytes));
    }
    private static String hashFile(Path f)throws Exception{
        MessageDigest dig=MessageDigest.getInstance("SHA-256");
        try(InputStream in=Files.newInputStream(f)){
            byte[] buf=new byte[65536];int n;
            while((n=in.read(buf))!=-1)dig.update(buf,0,n);
        }
        return hex(dig.digest());
    }
    private static boolean reserved(String name,String exe){
        return name.equalsIgnoreCase(exe)
                ||name.equalsIgnoreCase("xinput1_4.dll")
                ||name.equalsIgnoreCase("xinput1_3.dll")
                ||name.equalsIgnoreCase("xinput9_1_0.dll");
    }
    public static Result prepare(Context app,Path original){
        String status="NOT_STARTED";
        try{
            if(app==null||original==null||original.getFileName()==null)
                return new Result(null,status="SKIPPED_NO_GAME");
            if(CarXAppLocalDxvkV49034.exactGame(original))
                return new Result(null,status="SKIPPED_CARX_PROVEN_GRAPHICS_SIDECAR");
            if(!Files.isRegularFile(original,LinkOption.NOFOLLOW_LINKS)
                    ||Files.isSymbolicLink(original))
                return new Result(null,status="DENIED_ORIGINAL_EXE_INVALID");
            long exeLength=Files.size(original);
            if(exeLength<1024||exeLength>MAX_EXE_SIZE)
                return new Result(null,status="DENIED_EXE_SIZE");
            Path gameRoot=original.getParent().toRealPath();
            if(!original.toRealPath().getParent().equals(gameRoot))
                return new Result(null,status="DENIED_EXE_ESCAPES_PARENT");
            // Deterministic fingerprint of canonical path, not user-supplied
            // folder or EXE name, to avoid filename traversal/collision.
            String hashed=digest(original.toRealPath().toString().getBytes(
                    java.nio.charset.StandardCharsets.UTF_8)).substring(0,20);
            Path stage=app.getFilesDir().toPath().resolve("gamepad-stage-v49039-"+hashed);
            if(Files.isSymbolicLink(stage))
                return new Result(null,status="DENIED_STAGE_IS_SYMLINK");
            Files.createDirectories(stage);
            int linked=0,seen=0;
            try(DirectoryStream<Path> files=Files.newDirectoryStream(gameRoot)){
                for(Path entry:files){
                    if(++seen>MAX_ENTRIES)
                        return new Result(null,status="DENIED_TOO_MANY_ASSETS");
                    String name=entry.getFileName().toString();
                    if(reserved(name,original.getFileName().toString()))continue;
                    if(Files.isSymbolicLink(entry))
                        return new Result(null,status="DENIED_GAME_CONTAINS_SYMLINK");
                    Path real=entry.toRealPath();
                    if(!real.getParent().equals(gameRoot))
                        return new Result(null,status="DENIED_ASSET_ESCAPES_ROOT");
                    Path dest=stage.resolve(name);
                    if(Files.isSymbolicLink(dest)){
                        if(!Files.readSymbolicLink(dest).equals(real))
                            return new Result(null,status="DENIED_EXISTING_ASSET_LINK_CHANGED");
                    } else if(Files.exists(dest,LinkOption.NOFOLLOW_LINKS)){
                        return new Result(null,status="DENIED_ASSET_NAME_COLLISION");
                    }else{
                        Files.createSymbolicLink(dest,real);
                    }
                    if(!Files.exists(dest))return new Result(null,status="DENIED_ASSET_LINK_INACCESSIBLE");
                    linked++;
                }
            }
            if(linked==0)return new Result(null,status="DENIED_NO_LINKED_GAME_ASSETS");
            Path copy=stage.resolve(original.getFileName());
            if(Files.isSymbolicLink(copy))
                return new Result(null,status="DENIED_EXE_COPY_IS_LINK");
            String sourceHash=hashFile(original);
            if(!Files.isRegularFile(copy,LinkOption.NOFOLLOW_LINKS)
                    ||Files.size(copy)!=exeLength||!sourceHash.equals(hashFile(copy))){
                Files.copy(original,copy,StandardCopyOption.REPLACE_EXISTING);
                if(!sourceHash.equals(hashFile(copy)))
                    return new Result(null,status="DENIED_COPY_MISMATCH");
            }
            status="APP_PRIVATE_EXE_AND_"+linked+"_GAME_ASSET_LINKS_READY";
            return new Result(copy,status);
        }catch(Exception e){
            return new Result(null,status="DENIED_"+e.getClass().getSimpleName());
        }finally{
            if(app!=null)OfflineDiagnosticJournal.record(app,"v49039-universal-sidecar",
                "RM11_V49039_GAMEPAD_STAGE="+status+"\n"
                +"RM11_V49039_SOURCE_FILES_UNMODIFIED=true\n"
                +"RM11_V49039_GLOBAL_WINE_PREFIX_UNMODIFIED=true\n"
                +"RM11_V49039_UNSUPPORTED_GAMES_USE_EXISTING_ORIGINAL_LAUNCH=true");
        }
    }
}
