package com.rm11.autocore.runtime;

import android.content.Context;
import com.rm11.autocore.RM11VirtualXInputV49037;
import com.rm11.autocore.diagnostics.OfflineDiagnosticJournal;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.util.Locale;
import java.util.Map;

/**
 * Universal Win64 XInput backend for all user-selected games.
 *
 * No keyboard mapping, no original game file changes, no system32 DLL overwrite.
 * Signed XInput PE DLLs live in one app-private Windows PATH directory and
 * read exactly the same 64-byte shared Xbox state as the SDL Winebus device.
 * Winebus/DirectInput is kept as the other, independent Windows controller API.
 *
 * This is an API route, not proof that a particular game loaded it. Observe
 * last-v49049-universal-xinput.log and the read counter on a real device.
 */
public final class UniversalWineXInputV49049 {
    private UniversalWineXInputV49049() {}
    private static final String ASSET_ROOT="rm11-v49037-xinput/";
    private static final String[] DLLS={
        "xinput1_4.dll","xinput1_3.dll","xinput9_1_0.dll"
    };
    private static String hex(byte[] data){
        StringBuilder out=new StringBuilder(data.length*2);
        for(byte b:data)out.append(String.format(Locale.ROOT,"%02x",b&255));
        return out.toString();
    }
    public static String install(Context ctx,RuntimeLayout layout,Map<String,String> env){
        String result="NOT_STARTED";
        try{
            if(ctx==null||layout==null||env==null)return "NO_RUNTIME";
            Path state=RM11VirtualXInputV49037.statePath(ctx);
            if(Files.isSymbolicLink(state)||
               !Files.isRegularFile(state,LinkOption.NOFOLLOW_LINKS)||
               Files.size(state)!=64)
                return result="STATE_FILE_NOT_INITIALIZED";

            Path root=ctx.getFilesDir().toPath().toRealPath();
            Path directory=root.resolve("rm11-universal-xinput-v49049");
            if(Files.isSymbolicLink(directory))
                return result="DENIED_PRIVATE_FOLDER_SYMLINK";
            Files.createDirectories(directory);
            if(!directory.toRealPath().startsWith(root))
                return result="DENIED_PRIVATE_FOLDER_ESCAPE";

            String manifest;
            try(InputStream input=ctx.getAssets().open(ASSET_ROOT+"SHA256SUMS")){
                byte[] bytes=new byte[1000];
                int length=input.read(bytes);
                if(length<=0)return result="SIGNED_MANIFEST_EMPTY";
                manifest=new String(bytes,0,length,StandardCharsets.UTF_8);
            }
            for(String name:DLLS){
                String expected=null;
                for(String line:manifest.split("\n")){
                    String[] parts=line.trim().split("\\s+",2);
                    if(parts.length==2 && parts[1].equals(name))
                        expected=parts[0];
                }
                if(expected==null||!expected.matches("[0-9a-f]{64}"))
                    return result="SIGNED_MANIFEST_MISSING_"+name;

                byte[] binary;
                try(InputStream input=ctx.getAssets().open(ASSET_ROOT+name);
                    ByteArrayOutputStream output=new ByteArrayOutputStream()){
                    byte[] buf=new byte[32768];int n;
                    while((n=input.read(buf))!=-1){
                        if(output.size()+n>5_000_000)
                            return result="DLL_SIZE_LIMIT_"+name;
                        output.write(buf,0,n);
                    }
                    binary=output.toByteArray();
                }
                if(binary.length<4096 || !hex(MessageDigest.getInstance("SHA-256")
                        .digest(binary)).equals(expected))
                    return result="APK_SIGNATURE_MANIFEST_MISMATCH_"+name;
                Path target=directory.resolve(name);
                Path incoming=directory.resolve(name+".incoming");
                if(Files.isSymbolicLink(target)||Files.isSymbolicLink(incoming))
                    return result="DENIED_DLL_SYMLINK_"+name;
                Files.write(incoming,binary);
                try{
                    Files.move(incoming,target,StandardCopyOption.REPLACE_EXISTING,
                                      StandardCopyOption.ATOMIC_MOVE);
                }catch(java.nio.file.AtomicMoveNotSupportedException ignored){
                    Files.move(incoming,target,StandardCopyOption.REPLACE_EXISTING);
                }
            }
            // Wine recognizes these as Windows-style extra DLL search paths;
            // do not alter the POSIX loader PATH or the Wine installation.
            String wineDir="Z:"+directory.toString().replace('/','\\');
            String previousPath=env.get("WINEPATH");
            env.put("WINEPATH",wineDir+
                    (previousPath==null||previousPath.isEmpty()?"":";"+previousPath));
            String old=env.getOrDefault("WINEDLLOVERRIDES","");
            env.put("WINEDLLOVERRIDES",old+
                    (old.isEmpty()?"":";")+"xinput1_4,xinput1_3,xinput9_1_0=n,b");
            env.put("RM11_V49037_XINPUT_STATE_WINPATH",
                    "Z:"+state.toString().replace('/','\\'));
            Path diagnostics=root.resolve("offline-diagnostics");
            Files.createDirectories(diagnostics);
            Path trace=diagnostics.resolve("last-v49049-universal-xinput.log");
            if(Files.isSymbolicLink(trace))
                return result="DENIED_DIAGNOSTIC_SYMLINK";
            Files.deleteIfExists(trace);
            env.put("RM11_V49038_XINPUT_TRACE_WINPATH",
                    "Z:"+trace.toString().replace('/','\\'));
            result="GLOBAL_XINPUT_WINDOWS_PATH_CONFIGURED_NEEDS_GAME_POLL";
            return result;
        }catch(Exception error){
            return result="DENIED_"+error.getClass().getSimpleName();
        }finally{
            if(ctx!=null)OfflineDiagnosticJournal.record(ctx,
                    "v49049-universal-xinput",
                    "RM11_V49049_XINPUT_ROUTE="+result+"\n"+
                    "RM11_V49049_KEYBOARD_MAPPING=DISABLED\n"+
                    "RM11_V49049_ORIGINAL_GAME_FILES_UNCHANGED=true\n"+
                    "RM11_V49049_WINEBUS_DIRECTINPUT_ROUTE_PRESERVED=true\n"+
                    "RM11_V49049_GAME_ACK=REQUIRES_NATIVE_GETSTATE_READS");
        }
    }
}
