package com.rm11cor.carxstreet.portlab;

import android.content.ContentResolver;
import android.net.Uri;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.InputStream;
import java.util.List;
import java.util.Map;

/** Targeted header-only inspection of documents already selected by the user.
 * No native engine, bundle decompression, DRM bypass, network or asset copies.
 */
public final class UnityDeepProbe {
    private static final int MAX_BUNDLE_HEADERS=12;
    private UnityDeepProbe() {}

    public static JSONObject inspect(ContentResolver resolver,
                                     Map<String,Uri> docs,
                                     List<Uri> bundleDocuments,
                                     List<String> bundlePaths,
                                     int windowsBundleCount, long windowsBundleBytes)
            throws Exception {
        JSONObject report=new JSONObject();
        report.put("schema","rm11carx.unity-header-audit.v1");
        report.put("read_only",true);
        report.put("native_game_runtime_available",false);
        report.put("exe_is_android_arm64_compatible",false);
        report.put("windows64_bundle_count",windowsBundleCount);
        report.put("windows64_bundle_known_total_bytes",windowsBundleBytes);
        report.put("windows_bundles_android_compatibility_unproven",true);
        report.put("asset_rebuild_or_reauthoring_may_be_needed",windowsBundleCount>0);

        JSONObject metadata=new JSONObject();
        metadata.put("present",docs.containsKey("il2cpp_metadata"));
        if (docs.containsKey("il2cpp_metadata")) {
            try {
                byte[] head=readPrefix(resolver,docs.get("il2cpp_metadata"),64);
                UnityFormatProbe.Metadata parsed=UnityFormatProbe.metadata(head);
                metadata.put("classic_il2cpp_magic",parsed.classicMagic);
                metadata.put("header_bytes_read",head.length);
                metadata.put("metadata_version",parsed.classicMagic?parsed.rawVersion:-1);
                metadata.put("version_plausible",parsed.plausibleVersion);
                metadata.put("source_code_or_arm64_binary_recovered",false);
            } catch(Exception e) {
                metadata.put("read_error",e.getClass().getSimpleName());
            }
        }
        report.put("global_metadata",metadata);

        JSONObject boot=new JSONObject();
        boot.put("present",docs.containsKey("boot_config"));
        if(docs.containsKey("boot_config")) {
            try {
                byte[] head=readPrefix(resolver,docs.get("boot_config"),4096);
                String conf=new String(head,java.nio.charset.StandardCharsets.UTF_8);
                JSONArray keys=new JSONArray();
                for(String line:conf.split("\\r?\\n")) {
                    String trimmed=line.trim();
                    int eq=trimmed.indexOf('=');
                    if(eq>0 && eq<80 && keys.length()<50) {
                        String key=trimmed.substring(0,eq).trim();
                        if(key.matches("[A-Za-z0-9_.-]+")) keys.put(key);
                    }
                }
                boot.put("key_names_only",keys);
                boot.put("bytes_sampled",head.length);
                boot.put("values_excluded",true);
            } catch(Exception e) {
                boot.put("read_error",e.getClass().getSimpleName());
            }
        }
        report.put("boot_config",boot);

        JSONObject catalog=new JSONObject();
        catalog.put("present",docs.containsKey("addressables_catalog"));
        if(docs.containsKey("addressables_catalog")) {
            try {
                byte[] head=readPrefix(resolver,docs.get("addressables_catalog"),16384);
                String preview=new String(head,java.nio.charset.StandardCharsets.UTF_8);
                catalog.put("sample_bytes",head.length);
                catalog.put("json_prefix_detected",preview.trim().startsWith("{"));
                catalog.put("mentions_internal_ids",preview.contains("m_InternalIds"));
                catalog.put("mentions_windows64_in_prefix",
                        preview.toLowerCase(java.util.Locale.ROOT).contains("standalonewindows64"));
                catalog.put("full_catalog_parsed",false);
                catalog.put("full_asset_dependencies_verified",false);
            } catch(Exception e) {
                catalog.put("read_error",e.getClass().getSimpleName());
            }
        }
        report.put("addressables_catalog_prefix",catalog);

        JSONArray sampled=new JSONArray();
        JSONArray versions=new JSONArray();
        int valid=0;
        int limit=Math.min(Math.min(bundleDocuments.size(),bundlePaths.size()),MAX_BUNDLE_HEADERS);
        for(int i=0;i<limit;i++) {
            JSONObject item=new JSONObject();
            item.put("relative_path",bundlePaths.get(i));
            try {
                byte[] head=readPrefix(resolver,bundleDocuments.get(i),512);
                UnityFormatProbe.Bundle b=UnityFormatProbe.bundle(head);
                item.put("signature",b.signature);
                item.put("recognized_unity_container",b.recognized);
                item.put("header_complete",b.headerComplete);
                item.put("bundle_format_version",b.formatVersion);
                item.put("unity_version_string",b.unityVersion);
                item.put("unity_revision_string",b.unityRevision);
                item.put("sample_bytes",head.length);
                if(b.recognized && b.headerComplete) {
                    valid++;
                    if(!b.unityVersion.isEmpty()) {
                        boolean already=false;
                        for(int j=0;j<versions.length();j++) {
                            if(b.unityVersion.equals(versions.optString(j))) {already=true;break;}
                        }
                        if(!already)versions.put(b.unityVersion);
                    }
                }
            } catch(Exception e) {
                item.put("read_error",e.getClass().getSimpleName());
            }
            sampled.put(item);
        }
        report.put("sampled_windows_bundle_headers",sampled);
        report.put("sampled_unity_container_headers_valid",valid);
        report.put("sampled_bundle_unity_versions",versions);
        report.put("unity_player_exact_version_verified",false);
        report.put("game_logic_on_android_arm64_proven",false);
        report.put("actual_android_unity_asset_load_proven",false);
        report.put("renderer_first_frame_proven",false);
        report.put("next_gate",
                "Obtain lawful ARM64 game code/runtime AND verify Android-target asset bundles; " +
                "sampled Windows UnityFS headers and IL2CPP metadata alone cannot start the game");
        return report;
    }

    private static byte[] readPrefix(ContentResolver resolver,Uri uri,int maxBytes)
            throws Exception {
        try(InputStream in=resolver.openInputStream(uri)) {
            if(in==null)throw new java.io.IOException("content resolver returned no stream");
            java.io.ByteArrayOutputStream out=new java.io.ByteArrayOutputStream(maxBytes);
            byte[] temp=new byte[2048];
            int remaining=maxBytes;
            while(remaining>0) {
                int got=in.read(temp,0,Math.min(remaining,temp.length));
                if(got<0)break;
                if(got==0)continue;
                out.write(temp,0,got);
                remaining-=got;
            }
            return out.toByteArray();
        }
    }
}
