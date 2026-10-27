package com.rm11.autocore.runtime;

import android.content.Context;
import android.content.res.AssetManager;
import com.rm11.autocore.engine.EngineDataStager;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Locale;
import org.json.JSONException;
import org.json.JSONObject;

/**
 * Read-only, fail-closed integrity gate for source-pinned graphics providers.
 *
 * This checks the installed APK-native libraries and APK-embedded DXVK PE
 * bytes against metadata from the APK's own signed assets. It does NOT load
 * Turnip, modify a Wine prefix, set DLL overrides, hook dlopen, or prove a
 * rendered Android frame. vNext launch activation remains hard-disabled.
 */
public final class EngineVNextGraphicsManifestGate {
    private static final String MANIFEST="engine/engine-bundle-manifest.json";
    private static final String PACKAGE="com.rm11.autocore";
    private static final String OFF="DISABLED_UNTIL_HARDWARE_WINE_FRAME_PROOF";
    private static final String DXVK_SOURCE="c3dd74be6baec53786d4e064a572185b70347a17";
    private static final String MESA_ARCHIVE=
            "efd4bb08cdb7c365a812cd4e6c9202ab55b2f22cdcd13c7d6c4f9647b799a4ef";
    private static final String[] NATIVE={
        "libvulkan_freedreno.so", "libadrenotools.so", "libhook_impl.so",
        "libmain_hook.so", "libfile_redirect_hook.so", "libgsl_alloc_hook.so",
        "libc++_shared.so",
    };
    private static final String[] PE={"d3d11.dll","dxgi.dll"};
    private EngineVNextGraphicsManifestGate(){}

    public static final class Verified {
        public final Path signedNativeDirectory;
        public final int hashVerifiedComponents;
        public final boolean hardwareFrameProven;
        private Verified(Path root) {
            signedNativeDirectory=root;
            hashVerifiedComponents=9;
            hardwareFrameProven=false;
        }
    }

    private static String expectedHash(JSONObject entry,String path)
            throws JSONException,IOException {
        if(!path.equals(entry.getString("apk_path")))
            throw new IOException("ENGINE_GRAPHICS_SIGNED_PATH_MISMATCH");
        String hash=entry.getString("sha256");
        if(!hash.matches("[0-9a-f]{64}"))
            throw new IOException("ENGINE_GRAPHICS_INVALID_SHA256");
        return hash;
    }

    private static String assetSha256(AssetManager assets,String path)
            throws IOException {
        try {
            MessageDigest md=MessageDigest.getInstance("SHA-256");
            long length=0;
            try(InputStream input=assets.open(path,AssetManager.ACCESS_STREAMING)) {
                byte[] chunk=new byte[64*1024];
                for(int n;(n=input.read(chunk))!=-1;)if(n>0) {
                    length+=n;
                    if(length>180L*1024*1024)
                        throw new IOException("ENGINE_GRAPHICS_ASSET_SIZE_LIMIT");
                    md.update(chunk,0,n);
                }
            }
            if(length<512)throw new IOException("ENGINE_GRAPHICS_ASSET_TOO_SMALL");
            StringBuilder hex=new StringBuilder(64);
            for(byte b:md.digest())hex.append(String.format(
                    Locale.ROOT,"%02x",b&255));
            return hex.toString();
        } catch(NoSuchAlgorithmException missing) {
            throw new IOException("ENGINE_GRAPHICS_SHA256_UNAVAILABLE",missing);
        }
    }

    private static byte[] manifestBytes(AssetManager assets)throws IOException {
        try(InputStream input=assets.open(MANIFEST,AssetManager.ACCESS_STREAMING)) {
            java.io.ByteArrayOutputStream bytes=new java.io.ByteArrayOutputStream();
            byte[] chunk=new byte[4096];
            for(int n;(n=input.read(chunk))!=-1;)if(n>0) {
                if(bytes.size()+n>32768)
                    throw new IOException("ENGINE_GRAPHICS_MANIFEST_TOO_LARGE");
                bytes.write(chunk,0,n);
            }
            return bytes.toByteArray();
        }
    }

    public static Verified inspect(Context context)throws IOException {
        if(context==null || context.getApplicationInfo()==null
                || !PACKAGE.equals(context.getPackageName()))
            throw new IOException("ENGINE_GRAPHICS_UNEXPECTED_APP_CONTEXT");
        try {
            JSONObject manifest=new JSONObject(new String(
                    manifestBytes(context.getAssets()),
                    java.nio.charset.StandardCharsets.UTF_8));
            if(!"rm11.engine.bundle.v1".equals(manifest.getString("schema"))
                    ||!PACKAGE.equals(manifest.getString("android_package"))
                    ||!OFF.equals(manifest.getString("activation"))
                    ||manifest.getBoolean("safe_to_release")
                    ||manifest.getBoolean("wine_child_vulkan_loader_invoked")
                    ||!"UNVERIFIED".equals(manifest.getString(
                        "device_hardware_frame_proof")))
                throw new IOException("ENGINE_GRAPHICS_ACTIVATION_UNSAFE");
            JSONObject dxvk=manifest.getJSONObject("dxvk");
            JSONObject gpu=manifest.getJSONObject("gpu");
            if(!DXVK_SOURCE.equals(dxvk.getString("source_commit"))
                    ||!MESA_ARCHIVE.equals(gpu.getString("source_archive_sha256"))
                    ||!"turnip".equals(gpu.getString("driver"))
                    ||!"bionic".equals(gpu.getString("libc")))
                throw new IOException("ENGINE_GRAPHICS_SOURCE_ID_MISMATCH");
            Path signedRoot=Path.of(context.getApplicationInfo()
                    .nativeLibraryDir).toRealPath();
            JSONObject nativeFiles=manifest.getJSONObject("native_components");
            if(nativeFiles.length()!=NATIVE.length)
                throw new IOException("ENGINE_GRAPHICS_NATIVE_CLOSURE_INCOMPLETE");
            for(String name:NATIVE) {
                String expected=expectedHash(nativeFiles.getJSONObject(name),
                        "lib/arm64-v8a/"+name);
                Path file=signedRoot.resolve(name);
                if(!Files.isRegularFile(file,LinkOption.NOFOLLOW_LINKS)
                        ||Files.isSymbolicLink(file)
                        ||Files.size(file)<512
                        ||!expected.equals(EngineDataStager.sha256(file)))
                    throw new IOException("ENGINE_GRAPHICS_NATIVE_BYTES_MISMATCH:"+name);
            }
            JSONObject peFiles=dxvk.getJSONObject("pe_files");
            if(peFiles.length()!=PE.length)
                throw new IOException("ENGINE_GRAPHICS_DXVK_CLOSURE_INCOMPLETE");
            for(String name:PE) {
                String relative="engine/providers/dxvk/x64/"+name;
                String expected=expectedHash(peFiles.getJSONObject(name),
                        "assets/"+relative);
                if(!expected.equals(assetSha256(context.getAssets(),relative)))
                    throw new IOException("ENGINE_GRAPHICS_DXVK_BYTES_MISMATCH:"+name);
            }
            return new Verified(signedRoot);
        }catch(JSONException invalid){
            throw new IOException("ENGINE_GRAPHICS_SIGNED_MANIFEST_INVALID",invalid);
        }
    }
}
