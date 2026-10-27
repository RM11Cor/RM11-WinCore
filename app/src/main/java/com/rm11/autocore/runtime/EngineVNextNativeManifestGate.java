package com.rm11.autocore.runtime;

import android.content.Context;
import android.content.res.AssetManager;
import com.rm11.autocore.engine.EngineDataStager;
import org.json.JSONException;
import org.json.JSONObject;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;

/**
 * Only read a manifest packed INSIDE the APK signed by Android PackageManager.
 * Never read a manifest from user games, imagefs, Wine prefix or storage.
 *
 * Keeps vNext OFF until the full FEX/DXVK/Turnip Android frame proof exists.
 * This is intentionally not used by the legacy Wine game launcher.
 */
public final class EngineVNextNativeManifestGate {
    public static final String ASSET="engine/engine-native-manifest.json";
    private static final String DISABLED="DISABLED_UNTIL_HARDWARE_WINE_FRAME_PROOF";
    private static final String APP_ID="com.rm11.autocore";
    private EngineVNextNativeManifestGate(){}

    public static final class Verified {
        public final Path signedNativeDirectory;
        public final String supervisorSha256;
        public final String wineLoaderSha256;
        public final String wineServerSha256;
        public final boolean activationAllowed;
        private Verified(Path root,String supervisor,String loader,String server){
            signedNativeDirectory=root;
            supervisorSha256=supervisor;
            wineLoaderSha256=loader;
            wineServerSha256=server;
            activationAllowed=false;
        }
    }

    private static String entry(JSONObject components,String key,
                                String library,Path signedRoot)
            throws IOException,JSONException {
        JSONObject e=components.getJSONObject(key);
        if(!library.equals(e.getString("native_library")) ||
                !("lib/arm64-v8a/"+library).equals(e.getString("apk_path")))
            throw new IOException("ENGINE_MANIFEST_NATIVE_PATH_MISMATCH:"+key);
        String expected=e.getString("sha256");
        if(!expected.matches("[0-9a-f]{64}"))
            throw new IOException("ENGINE_MANIFEST_INVALID_HASH:"+key);
        Path target=signedRoot.resolve(library);
        if(!Files.isRegularFile(target,LinkOption.NOFOLLOW_LINKS)
                ||Files.isSymbolicLink(target))
            throw new IOException("ENGINE_APK_NATIVE_FILE_MISSING:"+key);
        if(!expected.equals(EngineDataStager.sha256(target)))
            throw new IOException("ENGINE_SIGNED_NATIVE_HASH_MISMATCH:"+key);
        return expected;
    }

    public static Verified inspect(Context context)throws IOException {
        if(context==null || context.getApplicationInfo()==null)
            throw new IOException("ENGINE_CONTEXT_MISSING");
        if(!APP_ID.equals(context.getPackageName()))
            throw new IOException("ENGINE_UNEXPECTED_ANDROID_PACKAGE");
        JSONObject manifest;
        try(InputStream raw=context.getAssets().open(ASSET,AssetManager.ACCESS_STREAMING)){
            // Small trusted asset, fixed read limit. Reject oversized input.
            java.io.ByteArrayOutputStream buf=new java.io.ByteArrayOutputStream();
            byte[] chunk=new byte[4096];int n;
            while((n=raw.read(chunk))!=-1){
                if(n<=0)continue;
                if(buf.size()+n>16384)throw new IOException("ENGINE_MANIFEST_TOO_LARGE");
                buf.write(chunk,0,n);
            }
            manifest=new JSONObject(new String(buf.toByteArray(),
                    java.nio.charset.StandardCharsets.UTF_8));
        }catch(JSONException invalid){
            throw new IOException("ENGINE_SIGNED_MANIFEST_INVALID",invalid);
        }
        try{
            if(!"rm11.engine.native-manifest.v1".equals(manifest.getString("schema"))
                    || !APP_ID.equals(manifest.getString("android_package"))
                    || !"arm64-v8a".equals(manifest.getString("arch"))
                    || !DISABLED.equals(manifest.getString("activation"))
                    || !manifest.getBoolean("legacy_wine_only")
                    || manifest.getBoolean("safe_to_release_as_game_fix"))
                throw new IOException("ENGINE_MANIFEST_RELEASE_GATE_UNSAFE");
            Path root=Path.of(context.getApplicationInfo().nativeLibraryDir)
                    .toRealPath();
            JSONObject components=manifest.getJSONObject("components");
            String supervisor=entry(components,"supervisor",
                    "librm11_engine_supervisor.so",root);
            String wine=entry(components,"wine_loader","libwineprobe.so",root);
            String server=entry(components,"wine_server",
                    "libwineserverrm11.so",root);
            // Wine/FEX ZIP identity is also verified at source-APK CI,
            // before PackageManager installs this signed asset.
            return new Verified(root,supervisor,wine,server);
        }catch(JSONException bad){
            throw new IOException("ENGINE_SIGNED_MANIFEST_FIELDS_INVALID",bad);
        }
    }

    /** Explicit guard: never accidentally start a Wine game from new
     * prototype just because the asset hashes matched. */
    public static void requireActivation(Verified verified)throws IOException {
        if(verified==null||!verified.activationAllowed)
            throw new IOException("ENGINE_VNEXT_NOT_ACTIVATED_OR_RENDERER_UNVERIFIED");
    }
}
