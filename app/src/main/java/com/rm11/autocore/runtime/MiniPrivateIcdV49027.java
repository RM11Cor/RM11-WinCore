package com.rm11.autocore.runtime;

import android.content.Context;
import com.rm11.autocore.diagnostics.OfflineDiagnosticJournal;
import org.json.JSONObject;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Map;

/**
 * Source-signed Turnip ICD direct-load experiment, restricted to the two
 * pre-existing miniature D3D11 Windows tests. No global Vulkan, no other games.
 */
public final class MiniPrivateIcdV49027 {
    private MiniPrivateIcdV49027() {}
    private static final char[] HEX="0123456789abcdef".toCharArray();
    private static String hex(byte[] bytes){
        char[] out=new char[bytes.length*2];
        for(int i=0;i<bytes.length;i++){
            out[i*2]=HEX[(bytes[i]&255)>>>4];
            out[i*2+1]=HEX[bytes[i]&15];
        }
        return new String(out);
    }
    public static boolean configure(Context ctx, RuntimeLayout layout,
                                    Map<String,String> env,boolean mini) {
        if(!mini || ctx==null || layout==null || env==null)return false;
        String stage="UNKNOWN";
        try {
            Path driver=layout.apkNativeLibs.resolve("libvulkan_freedreno.so");
            Path bridge=layout.apkNativeLibs.resolve("librm11_v49027_private_icd.so");
            if(!Files.isRegularFile(driver,LinkOption.NOFOLLOW_LINKS)
                    ||!Files.isRegularFile(bridge,LinkOption.NOFOLLOW_LINKS)
                    ||Files.isSymbolicLink(driver)||Files.isSymbolicLink(bridge)
                    ||Files.size(driver)<4096||Files.size(driver)>180L*1024*1024
                    ||Files.size(bridge)<4096) {
                stage="SIGNED_NATIVE_LIBS_UNAVAILABLE";return false;
            }
            JSONObject bundle;
            try(InputStream in=ctx.getAssets().open("engine/engine-bundle-manifest.json")){
                byte[] buffer=new byte[32769];
                int n=0,read;
                while(n<buffer.length && (read=in.read(buffer,n,buffer.length-n))>0)n+=read;
                if(n>=buffer.length)throw new java.io.IOException("OVERSIZED_MANIFEST");
                bundle=new JSONObject(new String(buffer,0,n,
                        java.nio.charset.StandardCharsets.UTF_8));
            }
            JSONObject gpu=bundle.getJSONObject("gpu");
            if(!"rm11.engine.bundle.v1".equals(bundle.optString("schema"))
                    ||!"com.rm11.autocore".equals(bundle.optString("android_package"))
                    ||!"lib/arm64-v8a/libvulkan_freedreno.so".equals(gpu.optString("apk_library")))
            {
                stage="MANIFEST_IDENTITY_MISMATCH";return false;
            }
            String expected=gpu.getString("sha256");
            if(!expected.matches("[0-9a-f]{64}")) {
                stage="MANIFEST_HASH_INVALID";return false;
            }
            MessageDigest sha=MessageDigest.getInstance("SHA-256");
            try(InputStream stream=Files.newInputStream(driver)){
                byte[] block=new byte[1024*1024];
                int read;
                while((read=stream.read(block))!=-1)sha.update(block,0,read);
            }
            if(!expected.equals(hex(sha.digest()))) {
                stage="SIGNED_TURNIP_SHA256_MISMATCH";return false;
            }
            env.put("RM11_V49027_PRIVATE_ICD_ENABLED","1");
            env.put("RM11_V49027_NATIVE_LIB_DIR",layout.apkNativeLibs.toString());
            env.put("RM11_V49027_PRIVATE_LOADER_LIBRARY",bridge.toString());
            String prior=env.get("LD_PRELOAD");
            env.put("LD_PRELOAD",bridge.toString()
                    +(prior==null||prior.isEmpty()?"":" "+prior));
            stage="DIRECT_ICD_BRIDGE_REQUESTED_NOT_GPU_PROOF";
            return true;
        }catch(Exception e) {
            stage="SETUP_ERROR_"+e.getClass().getSimpleName();
            return false;
        }finally {
            OfflineDiagnosticJournal.record(ctx,"v49027-private-icd-gate",
                    "RM11_V49027_STAGE="+stage+"\\n"
                    +"RM11_V49027_ONLY_TWO_D3D11_MINI_TESTS=true\\n"
                    +"RM11_V49027_SYSTEM_VULKAN_UNCHANGED=true\\n"
                    +"RM11_V49027_HARDWARE_PRESENTATION_UNVERIFIED=true");
        }
    }
}
