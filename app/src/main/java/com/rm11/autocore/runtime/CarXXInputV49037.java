package com.rm11.autocore.runtime;

import android.content.Context;
import com.rm11.autocore.RM11VirtualXInputV49037;
import com.rm11.autocore.diagnostics.OfflineDiagnosticJournal;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.util.Locale;
import java.util.Map;

/** Place signed PE XInput DLLs beside private CarX copy, never original game. */
public final class CarXXInputV49037 {
    private CarXXInputV49037(){}
    private static final String ASSET_ROOT="rm11-v49037-xinput/";
    private static final String[] PE_NAMES={
        "xinput1_4.dll","xinput1_3.dll","xinput9_1_0.dll"
    };
    private static String hex(byte[] data){
        StringBuilder result=new StringBuilder();
        for(byte b:data)result.append(String.format(Locale.ROOT,"%02x",b&255));
        return result.toString();
    }
    public static String install(Context ctx,Path exe,Map<String,String> env) {
        String outcome="NOT_SELECTED";
        try {
            if(ctx==null||env==null||exe==null
                ||!CarXAppLocalDxvkV49034.exactGame(exe)
                ||!exe.getParent().getFileName().toString()
                        .equals("carx-app-local-v49034"))
                return "SKIPPED_NOT_PRIVATE_CARX";
            Path state=RM11VirtualXInputV49037.statePath(ctx);
            if(!Files.isRegularFile(state,LinkOption.NOFOLLOW_LINKS)
                    ||Files.isSymbolicLink(state)||Files.size(state)!=64)
                return "DENIED_SHARED_INPUT_STATE_MISSING";
            String checks;
            try(InputStream stream=ctx.getAssets().open(ASSET_ROOT+"SHA256SUMS")){
                byte[] buf=new byte[1000];
                int n=stream.read(buf);
                if(n<=0)throw new java.io.IOException("XINPUT_MANIFEST_EMPTY");
                checks=new String(buf,0,n,java.nio.charset.StandardCharsets.UTF_8);
            }
            Path stage=exe.getParent();
            for(String name:PE_NAMES){
                String expected=null;
                for(String entry:checks.split("\\n")){
                    String[] cols=entry.trim().split(" +",2);
                    if(cols.length==2 && cols[1].equals(name))expected=cols[0];
                }
                if(expected==null||!expected.matches("[0-9a-f]{64}"))
                    return "DENIED_UNSIGNED_XINPUT_"+name;
                Path target=stage.resolve(name),tmp=stage.resolve(name+".incoming");
                if(Files.isSymbolicLink(target)||Files.isSymbolicLink(tmp))
                    return "DENIED_XINPUT_DLL_SYMLINK";
                MessageDigest md=MessageDigest.getInstance("SHA-256");
                byte[] binary;
                try(InputStream in=ctx.getAssets().open(ASSET_ROOT+name);
                    java.io.ByteArrayOutputStream out=new java.io.ByteArrayOutputStream()){
                    byte[] chunk=new byte[32768];int n;
                    while((n=in.read(chunk))!=-1){
                        if(out.size()+n>5_000_000)
                            throw new java.io.IOException("XINPUT_DLL_OVERSIZE");
                        md.update(chunk,0,n);out.write(chunk,0,n);
                    }
                    binary=out.toByteArray();
                }
                if(binary.length<4096||!hex(md.digest()).equals(expected))
                    return "DENIED_XINPUT_APK_HASH_MISMATCH_"+name;
                Files.write(tmp,binary);
                Files.move(tmp,target,StandardCopyOption.REPLACE_EXISTING);
            }
            String old=env.getOrDefault("WINEDLLOVERRIDES","");
            env.put("WINEDLLOVERRIDES",old+
                (old.isEmpty()?"":";")+"xinput1_4,xinput1_3,xinput9_1_0=n,b");
            env.put("RM11_V49037_XINPUT_STATE_WINPATH",
                    "Z:"+state.toString().replace('/','\\'));
            outcome="APP_LOCAL_XINPUT_NATIVE_REQUESTED_RUNTIME_PROOF_PENDING";
            return outcome;
        } catch(Exception error) {
            outcome="DENIED_"+error.getClass().getSimpleName();
            return outcome;
        } finally {
            if(ctx!=null)OfflineDiagnosticJournal.record(ctx,"v49037-xinput-route",
                "RM11_V49037_XINPUT_STAGE="+outcome+"\n"
                +"RM11_V49037_PRIVATE_GAME_ONLY=true\n"
                +"RM11_V49037_ORIGINAL_GAME_UNMODIFIED=true\n"
                +"RM11_V49037_ACTUAL_GAME_XINPUT_POLL=UNVERIFIED");
        }
    }
}
