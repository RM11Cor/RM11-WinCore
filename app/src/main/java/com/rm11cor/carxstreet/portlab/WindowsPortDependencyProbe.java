package com.rm11cor.carxstreet.portlab;

import android.content.ContentResolver;
import android.net.Uri;
import android.os.ParcelFileDescriptor;
import android.system.ErrnoException;
import android.system.Os;
import android.util.JsonReader;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

/**
 * App-native, scoped-storage SAF source audit for the original PC binaries.
 * Uses the user's already-approved DOCUMENT TREE, avoiding Termux file access,
 * root permissions, copied game binaries, and the inability to traverse
 * Android 16 / Android/data paths. This does NOT run native CarX game code.
 */
public final class WindowsPortDependencyProbe {
    private WindowsPortDependencyProbe() {}
    private static final int MAX_CATALOG_BYTES=32_000_000;
    private static final int MAX_INTERNAL_IDS=100_000;

    public static JSONObject inspect(ContentResolver resolver,Map<String,Uri> docs,
                                     Map<String,Long> sizes,
                                     Iterable<String> physicalWindowsBundleNames,
                                     boolean sourceFileListingComplete) throws Exception {
        JSONObject result=new JSONObject();
        result.put("schema","rm11carx.android-saf-windows-gamecode-asset-gate.v1");
        result.put("read_only",true);
        result.put("storage_access_method","Android ACTION_OPEN_DOCUMENT_TREE persisted SAF read grant");
        result.put("requires_termux",false);
        result.put("copies_game_files",false);
        result.put("uploads_game_files",false);
        result.put("executes_windows_game_binaries",false);
        result.put("android_arm64_carx_game_logic_proven",false);
        result.put("original_game_frame_rendered",false);

        JSONObject code=new JSONObject();
        for(String key:new String[]{"game_assembly","unity_player"}) {
            JSONObject item=new JSONObject();
            Uri doc=docs.get(key);
            long length=sizes.getOrDefault(key,-1L);
            item.put("present",doc!=null);
            item.put("document_size_bytes",length);
            if(doc!=null) {
                try(ParcelFileDescriptor fd=resolver.openFileDescriptor(doc,"r")) {
                    if(fd==null)throw new IOException("SAF document descriptor unavailable");
                    if(length<=0)length=fd.getStatSize();
                    final long fileSize=length;
                    PeImportProbe.Reader reader=(long offset,int count)->{
                        if(offset<0||count<1||offset+count>fileSize)
                            throw new IOException("invalid bounded source PE read");
                        byte[] bytes=new byte[count];
                        int pos=0;
                        while(pos<count) {
                            int read;
                            try {
                                read=Os.pread(fd.getFileDescriptor(),bytes,pos,count-pos,
                                        offset+pos);
                            } catch(ErrnoException e) {
                                throw new IOException("SAF source not random-seekable: "+
                                        e.errno,e);
                            }
                            if(read<=0)throw new IOException("short SAF source read");
                            pos+=read;
                        }
                        return bytes;
                    };
                    PeImportProbe.Result parsed=PeImportProbe.inspect(reader,fileSize);
                    item.put("pe_header_valid",parsed.valid);
                    item.put("machine_architecture",parsed.architecture);
                    item.put("source_binary_format",parsed.format);
                    item.put("sections",parsed.sections);
                    item.put("pe_import_directory_present",parsed.importDirectoryPresent);
                    item.put("pe_import_directory_complete",parsed.importDirectoryFullyRead);
                    item.put("saf_random_read_supported",parsed.randomReadSupported);
                    JSONArray dlls=new JSONArray();
                    JSONArray win=new JSONArray();
                    JSONArray steam=new JSONArray();
                    JSONArray eos=new JSONArray();
                    JSONArray anticheat=new JSONArray();
                    for(String dll:parsed.importedDlls) {
                        dlls.put(dll);
                        if(dll.equals("kernel32.dll")||dll.equals("kernelbase.dll")||
                                dll.equals("ntdll.dll")||dll.equals("user32.dll")||
                                dll.equals("gdi32.dll")||dll.equals("d3d11.dll")||
                                dll.equals("d3d12.dll")||dll.equals("dxgi.dll")||
                                dll.equals("advapi32.dll")||dll.equals("ws2_32.dll"))
                            win.put(dll);
                        if(dll.contains("steam"))steam.put(dll);
                        if(dll.contains("eos"))eos.put(dll);
                        if(dll.contains("easyanticheat")||dll.startsWith("eac"))
                            anticheat.put(dll);
                    }
                    item.put("static_import_library_names",dlls);
                    item.put("win32_runtime_imports",win);
                    item.put("steam_related_import_names",steam);
                    item.put("eos_related_import_names",eos);
                    item.put("anticheat_related_import_names",anticheat);
                    item.put("static_imports_are_not_complete_runtime_dependency_graph",true);
                    if(!parsed.error.isEmpty())
                        item.put("bounded_parse_error",parsed.error);
                }catch(Exception e) {
                    item.put("pe_import_directory_complete",false);
                    item.put("read_error",e.getClass().getSimpleName());
                }
            }
            item.put("android_elf_bionic_game_binary",false);
            code.put(key,item);
        }
        result.put("pc_executable_dependencies",code);

        BundleCatalogReconciler reconciler=new BundleCatalogReconciler();
        for(String name:physicalWindowsBundleNames)reconciler.addPhysicalWindowsBundle(name);
        JSONObject catalog=new JSONObject();
        Uri source=docs.get("addressables_catalog");
        catalog.put("present",source!=null);
        catalog.put("full_file_parsed",false);
        catalog.put("underlying_original_asset_bundle_files_opened",false);
        if(source!=null) {
            try {
                catalog.put("byte_limit",MAX_CATALOG_BYTES);
                Map<String,Integer> counts=parseAddressables(resolver,source,reconciler);
                for(Map.Entry<String,Integer> e:counts.entrySet())
                    catalog.put(e.getKey(),e.getValue());
                catalog.put("full_file_parsed",true);
            } catch(Exception e) {
                catalog.put("parse_error",e.getClass().getSimpleName()+": "+
                        e.getMessage());
            }
        }
        catalog.put("android_target_bundle_shaders_compatible_proven",false);
        catalog.put("original_pc_windows_bundle_conversion_proven",false);
        result.put("addressables_platform_references",catalog);
        BundleCatalogReconciler.Summary compared=reconciler.summarize(
                sourceFileListingComplete,catalog.optBoolean("full_file_parsed"));
        JSONObject diff=new JSONObject();
        diff.put("schema","rm11carx.physical-vs-catalog-windows64-bundle-names.v1");
        diff.put("fully_comparable",compared.fullReconciliationValid);
        diff.put("audit_status",compared.status);
        diff.put("physical_windows64_bundle_entries",compared.physicalEntries);
        diff.put("distinct_physical_windows64_filenames",compared.distinctPhysicalFilenames);
        diff.put("casefold_duplicate_physical_names",compared.physicalDuplicateCasefoldNames);
        diff.put("catalog_windows64_reference_entries",compared.catalogWindowsReferences);
        diff.put("distinct_catalog_windows64_bundle_names",compared.distinctCatalogReferencedFilenames);
        diff.put("duplicate_catalog_reference_entries",compared.catalogDuplicateReferenceEntries);
        diff.put("ambiguous_windows64_reference_names",compared.invalidOrNonlocalWindowsReferences);
        diff.put("exact_filename_matches",compared.filenameMatches);
        diff.put("physical_files_not_in_catalog_count",compared.unreferencedPhysicalCount);
        diff.put("catalog_names_missing_from_physical_files_count",compared.notPresentOnDiskCount);
        diff.put("physical_only_name_examples",new JSONArray(compared.unreferencedPhysicalExamples));
        diff.put("catalog_only_name_examples",new JSONArray(compared.notPresentOnDiskExamples));
        diff.put("android_word_reference_count",compared.androidNamedCount);
        diff.put("android_target_path_reference_count",compared.androidPlatformPathCount);
        diff.put("android_reference_safe_filename_examples",new JSONArray(compared.androidNameExamples));
        diff.put("android_target_asset_compatibility_proven",false);
        diff.put("original_windows_unity_assetbundle_contents_inspected",false);
        diff.put("match_granularity","casefolded_basenames_only_not_hashes_or_asset_dependencies");
        diff.put("note","808 vs 807 total entries alone never proves missing data; compare distinct source filenames.");
        result.put("windows64_asset_bundle_filename_reconciliation",diff);
        result.put("native_android_carx_game_code_gate","BLOCKED_NO_PROVEN_ANDROID_ARM64_IL2CPP_BINARY");
        result.put("native_android_carx_asset_gate","BLOCKED_NO_PROVEN_ANDROID_PLATFORM_GAME_ASSETS");
        result.put("next_gate","Original Windows PE and AssetBundle catalog source evidence. An actual authorized Android ARM64 gameplay build and Android-target assets are still necessary. Do not claim playable CarX.");
        return result;
    }

    static final class LimitedStream extends FilterInputStream {
        private int remaining;
        LimitedStream(InputStream in,int maxBytes) {
            super(in);remaining=maxBytes;
        }
        @Override public int read()throws IOException {
            if(remaining<=0)throw new IOException("JSON catalog exceeds read bound");
            int b=super.read();
            if(b>=0)remaining--;
            return b;
        }
        @Override public int read(byte[] data,int off,int len)throws IOException {
            if(remaining<=0)throw new IOException("JSON catalog exceeds read bound");
            int read=super.read(data,off,Math.min(len,remaining));
            if(read>0)remaining-=read;
            return read;
        }
    }

    private static Map<String,Integer> parseAddressables(ContentResolver resolver,Uri uri,
                     BundleCatalogReconciler reconciler)
            throws Exception {
        HashMap<String,Integer> counts=new HashMap<>();
        for(String key:new String[]{
                "internal_id_count","standalone_windows64_references",
                "standalone_linux64_references","standalone_osx_references",
                "android_named_references","bundle_extension_references",
                "shader_name_references"})counts.put(key,0);

        try(InputStream input=resolver.openInputStream(uri)) {
            if(input==null)throw new IOException("SAF catalog source stream unavailable");
            try(JsonReader reader=new JsonReader(new InputStreamReader(
                    new LimitedStream(input,MAX_CATALOG_BYTES),StandardCharsets.UTF_8))) {
                reader.setLenient(false);
                reader.beginObject();
                boolean foundIds=false;
                while(reader.hasNext()) {
                    String key=reader.nextName();
                    if(key.equals("m_InternalIds")) {
                        if(foundIds)throw new IOException("ambiguous duplicate m_InternalIds");
                        foundIds=true;
                        reader.beginArray();
                        while(reader.hasNext()) {
                            String path=reader.nextString();
                            if(path.length()>8192)
                                throw new IOException("unbounded addressables entry");
                            int total=counts.get("internal_id_count")+1;
                            if(total>MAX_INTERNAL_IDS)
                                throw new IOException("too many Addressables internal IDs");
                            counts.put("internal_id_count",total);
                            reconciler.addCatalogInternalId(path);
                            String p=path.toLowerCase(Locale.ROOT);
                            addIf(counts,"standalone_windows64_references",
                                    p.contains("standalonewindows64"));
                            addIf(counts,"standalone_linux64_references",
                                    p.contains("standalonelinux64"));
                            addIf(counts,"standalone_osx_references",
                                    p.contains("standaloneosx"));
                            addIf(counts,"android_named_references",
                                    p.contains("android"));
                            addIf(counts,"bundle_extension_references",
                                    p.endsWith(".bundle")||p.endsWith(".unity3d")||
                                            p.endsWith(".assetbundle"));
                            addIf(counts,"shader_name_references",p.contains("shader"));
                        }
                        reader.endArray();
                    } else reader.skipValue();
                }
                reader.endObject();
                if(!foundIds)throw new IOException("Addressables m_InternalIds missing");
            }
        }
        return counts;
    }

    private static void addIf(Map<String,Integer> counts,String name,boolean predicate) {
        if(predicate)counts.put(name,counts.get(name)+1);
    }
}
