package com.rm11.autocore.runtime;

import android.content.Context;
import org.json.JSONObject;
import java.io.InputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.util.Map;

/** Test-only DXVK PE provider staging, no game/prefix mutation and no driver injection. */
public final class MiniDxvkRouteV49021 {
    private MiniDxvkRouteV49021() {}
    private static final String ROOT="engine/providers/dxvk/x64/";
    private static String hex(byte[] bytes) {
        StringBuilder b=new StringBuilder();
        for(byte v:bytes)b.append(String.format(java.util.Locale.ROOT,"%02x",v&255));
        return b.toString();
    }
    public static String configure(Context ctx, Map<String,String> env) {
        try {
            JSONObject doc;
            try(InputStream in=ctx.getAssets().open("engine/engine-bundle-manifest.json")) {
                java.io.ByteArrayOutputStream output=new java.io.ByteArrayOutputStream();
                byte[] buf=new byte[8192];int n;
                while((n=in.read(buf))!=-1)output.write(buf,0,n);
                doc=new JSONObject(output.toString("UTF-8"));
            }
            if(!"rm11.engine.bundle.v1".equals(doc.optString("schema"))
                    ||!"com.rm11.autocore".equals(doc.optString("android_package")))
                return "SKIPPED_UNVERIFIED_MANIFEST";
            JSONObject pe=doc.getJSONObject("dxvk").getJSONObject("pe_files");
            Path out=ctx.getFilesDir().toPath().resolve("mini-dxvk-v49021");
            Files.createDirectories(out);
            for(String dll:new String[]{"d3d11.dll","dxgi.dll"}){
                JSONObject entry=pe.getJSONObject(dll);
                String expected=entry.getString("sha256");
                if(!("assets/"+ROOT+dll).equals(entry.getString("apk_path"))
                        || expected.length()!=64)return "SKIPPED_INVALID_PROVIDER_ENTRY";
                Path tmp=out.resolve(dll+".tmp");
                MessageDigest digest=MessageDigest.getInstance("SHA-256");
                long total=0;
                try(InputStream input=ctx.getAssets().open(ROOT+dll);
                    java.io.OutputStream output=Files.newOutputStream(tmp)){
                    byte[] buf=new byte[65536];int n;
                    while((n=input.read(buf))!=-1){
                        total+=n;
                        if(total>64L*1024*1024)throw new IOException("DXVK_PE_SIZE_LIMIT");
                        digest.update(buf,0,n);output.write(buf,0,n);
                    }
                }
                if(total<1024||!hex(digest.digest()).equalsIgnoreCase(expected)){
                    Files.deleteIfExists(tmp);return "SKIPPED_PROVIDER_SHA_MISMATCH";
                }
                Files.move(tmp,out.resolve(dll),StandardCopyOption.REPLACE_EXISTING);
            }
            String prev=env.get("WINEDLLPATH");
            env.put("WINEDLLPATH",out.toString()+(prev==null||prev.isEmpty()?"":":"+prev));
            env.put("WINEDLLOVERRIDES","d3d11,dxgi=n");
            return "MINI_ONLY_DXVK_NATIVE_DLL_SEARCH_REQUESTED_NOT_LOADED_PROOF";
        }catch(Exception e) {
            return "SKIPPED_"+e.getClass().getSimpleName();
        }
    }
}
