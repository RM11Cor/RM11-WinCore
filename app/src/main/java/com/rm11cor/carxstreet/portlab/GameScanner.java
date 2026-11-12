package com.rm11cor.carxstreet.portlab;

import android.app.ActivityManager;
import android.content.ContentResolver;
import android.content.Context;
import android.content.pm.FeatureInfo;
import android.content.pm.PackageManager;
import android.database.Cursor;
import android.net.Uri;
import android.os.Build;
import android.os.CancellationSignal;
import android.provider.DocumentsContract;
import android.provider.DocumentsContract.Document;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Read-only document-provider scanner for a user-selected legally obtained
 * CarX Street PC folder. No extraction, execution, DRM bypass or network.
 * This scans Unity IL2CPP packaging; it does not port Windows code to ARM.
 */
public final class GameScanner {
    private static final int FILE_LIMIT = 150_000;
    private static final int DEPTH_LIMIT = 18;
    private static final int EVIDENCE_LIMIT = 64;
    private static final long SAMPLE_BYTES = 65_536L;
    private GameScanner() {}

    public interface Progress {
        void onCount(int files, int directories);
        boolean cancelled();
    }

    private static final class Node {
        final String id;
        final String path;
        final int depth;
        Node(String id, String path, int depth) {
            this.id=id; this.path=path; this.depth=depth;
        }
    }

    public static JSONObject inspect(Context context, Uri tree, Progress progress) throws Exception {
        final ContentResolver resolver=context.getContentResolver();
        final String rootId=DocumentsContract.getTreeDocumentId(tree);
        final ArrayDeque<Node> stack=new ArrayDeque<>();
        final Set<String> visited=new HashSet<>();
        final HashMap<String,String> found=new HashMap<>();
        final HashMap<String,Uri> documentsToProbe=new HashMap<>();
        final HashMap<String,Long> sourceDocumentSizes=new HashMap<>();
        final ArrayList<Uri> bundleSampleUris=new ArrayList<>();
        final ArrayList<String> bundleSamplePaths=new ArrayList<>();
        final ArrayList<String> physicalWindowsBundleNames=new ArrayList<>();
        int windowsBundleCount=0;
        long windowsBundleBytes=0;
        final JSONArray evidence=new JSONArray();
        final ArrayList<String> warnings=new ArrayList<>();
        final String rootName=displayName(resolver,DocumentsContract.buildDocumentUriUsingTree(tree,rootId));
        final long start=System.nanoTime();
        stack.push(new Node(rootId,"",0));
        int files=0,dirs=0;
        long totalBytes=0,unknownSizes=0;
        String exeMachine="not-inspected",assemblyMachine="not-inspected";
        String exePath="",assemblyPath="";
        String exeSample="",assemblySample="";
        boolean hitLimit=false;
        boolean hasRootData=false,hasUnity=false,hasAssembly=false,hasMeta=false;
        boolean hasAddressables=false,hasWindowsAssets=false,hasEAC=false,hasCarXExe=false;
        boolean hasResources=false,hasManager=false;
        while(!stack.isEmpty()) {
            if(progress.cancelled()) throw new InterruptedException("scan cancelled");
            Node node=stack.pop();
            if(!visited.add(node.id)) continue;
            if(node.depth>DEPTH_LIMIT) {
                warnings.add("Maximum directory depth exceeded at "+node.path);
                continue;
            }
            Uri children=DocumentsContract.buildChildDocumentsUriUsingTree(tree,node.id);
            try(Cursor cursor=resolver.query(children,new String[] {
                    Document.COLUMN_DOCUMENT_ID,Document.COLUMN_DISPLAY_NAME,
                    Document.COLUMN_MIME_TYPE,Document.COLUMN_SIZE},null,null,null)) {
                if(cursor==null) {
                    warnings.add("Document provider did not return listing for "+node.path);
                    continue;
                }
                final int doc=cursor.getColumnIndexOrThrow(Document.COLUMN_DOCUMENT_ID);
                final int name=cursor.getColumnIndexOrThrow(Document.COLUMN_DISPLAY_NAME);
                final int mime=cursor.getColumnIndexOrThrow(Document.COLUMN_MIME_TYPE);
                final int size=cursor.getColumnIndexOrThrow(Document.COLUMN_SIZE);
                while(cursor.moveToNext()) {
                    if(progress.cancelled()) throw new InterruptedException("scan cancelled");
                    String id=cursor.getString(doc),n=cursor.getString(name),m=cursor.getString(mime);
                    if(id==null||n==null||n.isEmpty()) continue;
                    String relative=node.path.isEmpty()?n:node.path+"/"+n;
                    String lower=relative.toLowerCase(Locale.ROOT);
                    boolean directory=Document.MIME_TYPE_DIR.equals(m);
                    if(directory) {
                        dirs++;
                        if(n.toLowerCase(Locale.ROOT).equals("carx street_data") ||
                            lower.endsWith("/carx street_data")) hasRootData=true;
                        if(lower.contains("streamingassets/aa/standalonewindows64")) hasWindowsAssets=true;
                        if(lower.contains("easyanticheat")) hasEAC=true;
                        stack.push(new Node(id,relative,node.depth+1));
                    } else {
                        files++;
                        long length=cursor.isNull(size)?-1:cursor.getLong(size);
                        if(length>=0) totalBytes+=length; else unknownSizes++;
                        String basename=n.toLowerCase(Locale.ROOT);
                        // Select only source file descriptors, never copy 22+ GB.
                        // Android SAF works even when Termux cannot search /sdcard.
                        if(basename.equals("gameassembly.dll") ||
                                basename.equals("unityplayer.dll")) {
                            String key=basename.equals("gameassembly.dll")?
                                    "game_assembly":"unity_player";
                            documentsToProbe.put(key,
                                    DocumentsContract.buildDocumentUriUsingTree(tree,id));
                            sourceDocumentSizes.put(key,length);
                        }
                        // Select bounded Unity headers; no game file transfer.
                        if(basename.equals("global-metadata.dat")) {
                            documentsToProbe.put("il2cpp_metadata",
                                DocumentsContract.buildDocumentUriUsingTree(tree,id));
                        }
                        if(basename.equals("globalgamemanagers")) {
                            documentsToProbe.put("globalgamemanagers",
                                DocumentsContract.buildDocumentUriUsingTree(tree,id));
                        }
                        if(basename.equals("resources.assets")) {
                            documentsToProbe.put("unity_resources",
                                DocumentsContract.buildDocumentUriUsingTree(tree,id));
                        }
                        if(basename.equals("boot.config")) {
                            documentsToProbe.put("boot_config",
                                DocumentsContract.buildDocumentUriUsingTree(tree,id));
                        }
                        if(basename.equals("catalog.json") &&
                           lower.contains("streamingassets/aa/")) {
                            documentsToProbe.put("addressables_catalog",
                                DocumentsContract.buildDocumentUriUsingTree(tree,id));
                        }
                        if(basename.endsWith(".bundle") &&
                           lower.contains("standalonewindows64")) {
                            if(physicalWindowsBundleNames.size()<12000)
                                physicalWindowsBundleNames.add(n);
                            else warnings.add("Windows64 physical bundle filename limit exceeded");
                            windowsBundleCount++;
                            if(length>=0)windowsBundleBytes+=length;
                            if(bundleSampleUris.size()<12) {
                                bundleSampleUris.add(
                                    DocumentsContract.buildDocumentUriUsingTree(tree,id));
                                bundleSamplePaths.add(relative);
                            }
                        }
                        if(basename.equals("unityplayer.dll")) {
                            hasUnity=true; found.put("unity_player",relative);
                        }
                        if(basename.equals("gameassembly.dll")) {
                            hasAssembly=true; found.put("il2cpp_windows_assembly",relative);
                            if(assemblyPath.isEmpty()) {
                                assemblyPath=relative;
                                Uri f=DocumentsContract.buildDocumentUriUsingTree(tree,id);
                                assemblyMachine=peMachine(resolver,f);
                                assemblySample=shaSample(resolver,f);
                            }
                        }
                        if(basename.equals("global-metadata.dat")) {
                            hasMeta=true; found.put("il2cpp_metadata",relative);
                        }
                        if(basename.equals("globalgamemanagers")) {
                            hasManager=true; found.put("unity_manager",relative);
                        }
                        if(basename.equals("resources.assets")) {
                            hasResources=true; found.put("unity_resources",relative);
                        }
                        if(lower.contains("streamingassets/aa/") &&
                            (basename.equals("catalog.json")||basename.endsWith(".bundle"))) {
                            hasAddressables=true; found.put("unity_addressables",relative);
                        }
                        if(lower.contains("standalonewindows64")) hasWindowsAssets=true;
                        if(lower.contains("easyanticheat")) hasEAC=true;
                        if(basename.endsWith(".exe")&&
                           (basename.contains("carx")||basename.contains("street"))) {
                            hasCarXExe=true;
                            found.put("game_exe",relative);
                            if(exePath.isEmpty()) {
                                exePath=relative;
                                Uri f=DocumentsContract.buildDocumentUriUsingTree(tree,id);
                                exeMachine=peMachine(resolver,f);
                                exeSample=shaSample(resolver,f);
                            }
                        }
                        if(interesting(basename,lower) && evidence.length()<EVIDENCE_LIMIT) {
                            JSONObject item=new JSONObject();
                            item.put("path",relative);
                            item.put("bytes",length);
                            evidence.put(item);
                        }
                    }
                    if((files+dirs)%200==0) progress.onCount(files,dirs);
                    if(files+dirs>=FILE_LIMIT) { hitLimit=true; break; }
                }
            } catch(SecurityException se) {
                warnings.add("No access to "+node.path+": "+se.getClass().getSimpleName());
            }
            if(hitLimit)break;
        }
        progress.onCount(files,dirs);
        JSONArray notes=new JSONArray();
        for(String warning:warnings)notes.put(warning);
        if(hitLimit)notes.put("Scan stopped after "+FILE_LIMIT+" entries; counts incomplete");
        if(unknownSizes>0)notes.put(unknownSizes+" files with unknown byte size");
        if(!hasCarXExe)notes.put("CarX Street Windows EXE not found in selected root");
        if(!hasRootData)notes.put("Expected CarX Street_Data folder not found");
        if(!hasAssembly)notes.put("GameAssembly.dll missing; source PC build may differ");
        if(!hasUnity)notes.put("UnityPlayer.dll missing; source PC build may differ");
        if(hasWindowsAssets)notes.put("Windows asset bundles may require conversion for Android graphics and shaders");
        if(hasEAC)notes.put("Easy Anti-Cheat detected; no bypass is implemented or authorized");
        JSONObject flags=new JSONObject();
        flags.put("carx_pc_exe",hasCarXExe);
        flags.put("carx_street_data_directory",hasRootData);
        flags.put("unity_player_windows",hasUnity);
        flags.put("il2cpp_game_assembly_windows",hasAssembly);
        flags.put("il2cpp_global_metadata",hasMeta);
        flags.put("unity_global_managers",hasManager);
        flags.put("unity_resource_assets",hasResources);
        flags.put("unity_addressables",hasAddressables);
        flags.put("windows64_asset_bundles",hasWindowsAssets);
        flags.put("easy_anticheat_presence",hasEAC);
        JSONObject sizes=new JSONObject();
        sizes.put("files",files);
        sizes.put("folders",dirs);
        sizes.put("known_total_bytes",totalBytes);
        sizes.put("unknown_size_files",unknownSizes);
        sizes.put("scan_incomplete",hitLimit);
        sizes.put("elapsed_ms",(System.nanoTime()-start)/1_000_000L);
        JSONObject machine=new JSONObject();
        machine.put("carx_exe",exeMachine);
        machine.put("carx_exe_first64kb_sha256",exeSample);
        machine.put("carx_exe_relative_path",exePath);
        machine.put("gameassembly_dll",assemblyMachine);
        machine.put("gameassembly_first64kb_sha256",assemblySample);
        machine.put("gameassembly_relative_path",assemblyPath);
        JSONObject report=new JSONObject();
        report.put("schema","rm11carx.pc-port-readonly-inspector.v1");
        report.put("inspector_version","0.9.0");
        report.put("source_game","CarX Street PC (Unity IL2CPP)");
        report.put("user_selected_folder_name",rootName);
        report.put("game_files_transmitted",false);
        report.put("read_only",true);
        report.put("runtime_present",false);
        report.put("game_executed",false);
        report.put("native_ARM64_port_proven",false);
        report.put("detect",flags);
        report.put("counts",sizes);
        report.put("machine",machine);
        JSONObject paths=new JSONObject();
        for(Map.Entry<String,String> e:found.entrySet())paths.put(e.getKey(),e.getValue());
        report.put("relative_path_evidence",paths);
        report.put("sample_files",evidence);
        report.put("unity_deep_probe",UnityDeepProbe.inspect(
                resolver,documentsToProbe,bundleSampleUris,bundleSamplePaths,
                windowsBundleCount,windowsBundleBytes));
        report.put("notes",notes);
        report.put("windows_source_dependency_probe",
                WindowsPortDependencyProbe.inspect(
                        resolver,documentsToProbe,sourceDocumentSizes,
                        physicalWindowsBundleNames,!hitLimit && warnings.isEmpty()));
        report.put("device",device(context));
        report.put("native_arm64_vulkan_preflight",NativeVulkanProbe.inspect());
        report.put("next_gate","Independent ARM64 Vulkan offscreen GPU clear/readback is tested. It is NOT a displayed game frame or original CarX logic. Native Android game code, platform-correct Unity assets, and gameplay remain unproven.");
        return report;
    }

    private static boolean interesting(String base,String path) {
        return base.endsWith(".exe")||base.equals("gameassembly.dll")||
                base.equals("unityplayer.dll")||base.equals("global-metadata.dat")||
                base.equals("globalgamemanagers")||base.equals("resources.assets")||
                base.equals("boot.config")||base.equals("catalog.json")||
                base.equals("settings.json")||base.equals("splash.png")||
                (base.endsWith(".bundle")&&path.contains("standalonewindows64"));
    }

    private static String displayName(ContentResolver resolver,Uri doc) {
        try(Cursor c=resolver.query(doc,new String[]{Document.COLUMN_DISPLAY_NAME},null,null,null)) {
            if(c!=null&&c.moveToFirst())return c.getString(0);
        }catch(Exception ignored){}
        return "selected-game-folder";
    }

    private static String peMachine(ContentResolver resolver,Uri doc) {
        try(InputStream in=resolver.openInputStream(doc)) {
            if(in==null)return "cannot-open";
            byte[] b=new byte[4096];
            int count=0,n;
            while(count<b.length && (n=in.read(b,count,b.length-count))>0)count+=n;
            if(count<0x40||b[0]!='M'||b[1]!='Z')return "not-Windows-PE";
            int off=(b[0x3c]&255)|((b[0x3d]&255)<<8)|
                   ((b[0x3e]&255)<<16)|((b[0x3f]&255)<<24);
            if(off<0||off+6>=count)return "PE-header-out-of-sample";
            if(b[off]!='P'||b[off+1]!='E'||b[off+2]!=0||b[off+3]!=0)return "invalid-PE-signature";
            int m=(b[off+4]&255)|((b[off+5]&255)<<8);
            if(m==0x8664)return "Windows-PE-x86_64";
            if(m==0xAA64)return "Windows-PE-ARM64";
            if(m==0x14c)return "Windows-PE-x86";
            return "Windows-PE-other-0x"+Integer.toHexString(m);
        }catch(Exception ex){return "PE-read-error-"+ex.getClass().getSimpleName();}
    }

    /** Small sample hashes, NOT a whole-file integrity check. */
    private static String shaSample(ContentResolver resolver,Uri doc) {
        try(InputStream in=resolver.openInputStream(doc)) {
            if(in==null)return "";
            MessageDigest d=MessageDigest.getInstance("SHA-256");
            byte[] b=new byte[8192];
            long total=0;
            int n;
            while(total<SAMPLE_BYTES && (n=in.read(b,0,(int)Math.min(b.length,SAMPLE_BYTES-total)))>0) {
                d.update(b,0,n);total+=n;
            }
            StringBuilder s=new StringBuilder();
            for(byte val:d.digest())s.append(String.format(Locale.ROOT,"%02x",val&255));
            return s.toString();
        }catch(Exception ex){return "";}
    }

    private static JSONObject device(Context context) throws JSONException {
        JSONObject j=new JSONObject();
        j.put("brand",Build.BRAND);
        j.put("model",Build.MODEL);
        j.put("android_sdk",Build.VERSION.SDK_INT);
        j.put("abi",new JSONArray(Build.SUPPORTED_ABIS));
        if(Build.VERSION.SDK_INT>=31)j.put("soc_model",Build.SOC_MODEL);
        ActivityManager am=(ActivityManager)context.getSystemService(Context.ACTIVITY_SERVICE);
        if(am!=null) {
            ActivityManager.MemoryInfo mi=new ActivityManager.MemoryInfo();
            am.getMemoryInfo(mi);
            j.put("total_ram_bytes",mi.totalMem);
        }
        PackageManager pm=context.getPackageManager();
        JSONArray vk=new JSONArray();
        for(FeatureInfo f:pm.getSystemAvailableFeatures()) {
            if(f.name!=null&&f.name.startsWith("android.hardware.vulkan")) {
                JSONObject feature=new JSONObject();
                feature.put("feature",f.name);
                feature.put("version_code",f.version);
                vk.put(feature);
            }
        }
        j.put("vulkan_features",vk);
        return j;
    }
}
