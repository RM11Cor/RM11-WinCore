package com.rm11.autocore.runtime;

import android.content.Context;
import com.rm11.autocore.diagnostics.OfflineDiagnosticJournal;
import org.json.JSONObject;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.util.Locale;
import java.util.Map;

/**
 * Exactly one user-selected x64 game. The original CarX Street EXE and assets
 * remain in their existing directory, and the shared Wine prefix/registry,
 * wineserver, and other games are never changed.
 *
 * The independent v49031 device test proved continuous no-VSync presentation.
 * This route requests that same authenticated private X11 Vulkan closure for
 * CarX Street. It does NOT assert that Wine resolves these native DLLs: the
 * actual game's DXVK logs and loaded-DLL records must establish that.
 */
public final class CarXStreetDxvkV49032 {
    private CarXStreetDxvkV49032(){}
    private static final String ROOT="engine/providers/dxvk/x64/";
    private static final String SUCCESS="CARX_PRIVATE_X11_DXVK_WINEPATH_REQUESTED_LOAD_UNVERIFIED";

    /** Case-insensitive exact known launcher, or named game EXE in CarX folder. */
    public static boolean isSelectedCarXStreet(Path game) {
        if(game==null || game.getFileName()==null)return false;
        String exe=game.getFileName().toString().toLowerCase(Locale.ROOT);
        if("carx street launcher.exe".equals(exe))return true;
        if(!("carxstreet.exe".equals(exe)
                ||"carx street.exe".equals(exe)
                ||"carxstreet-win64-shipping.exe".equals(exe)))return false;
        for(Path item=game.getParent();item!=null;item=item.getParent()) {
            if(item.getFileName()==null)continue;
            String folder=item.getFileName().toString()
                    .toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]","");
            if(folder.startsWith("carxstreet")&&folder.length()<=30)return true;
        }
        return false;
    }

    private static String hex(byte[] bytes) {
        StringBuilder text=new StringBuilder(bytes.length*2);
        for(byte b:bytes)text.append(String.format(Locale.ROOT,"%02x",b&255));
        return text.toString();
    }
    private static JSONObject manifest(Context app)throws Exception {
        try(InputStream in=app.getAssets().open("engine/engine-bundle-manifest.json")){
            java.io.ByteArrayOutputStream output=new java.io.ByteArrayOutputStream();
            byte[] bytes=new byte[8192];int n;
            while((n=in.read(bytes))!=-1){
                if(output.size()+n>200000)throw new java.io.IOException("MANIFEST_OVERSIZE");
                output.write(bytes,0,n);
            }
            JSONObject doc=new JSONObject(output.toString("UTF-8"));
            if(!"rm11.engine.bundle.v1".equals(doc.optString("schema"))
                    ||!"com.rm11.autocore".equals(doc.optString("android_package")))
                throw new java.io.IOException("MANIFEST_UNTRUSTED");
            return doc;
        }
    }

    /** Never stage game files: only authenticated provider DLLs from this APK. */
    private static Path stageProvider(Context app)throws Exception {
        JSONObject pe=manifest(app).getJSONObject("dxvk").getJSONObject("pe_files");
        Path target=app.getFilesDir().toPath().resolve("carx-dxvk-v49032");
        if(Files.isSymbolicLink(target))throw new java.io.IOException("DXVK_DIR_SYMLINK");
        Files.createDirectories(target);
        for(String dll:new String[]{"d3d11.dll","dxgi.dll"}){
            JSONObject entry=pe.getJSONObject(dll);
            String expected=entry.getString("sha256");
            if(!expected.matches("[0-9a-fA-F]{64}")
                    || !("assets/"+ROOT+dll).equals(entry.getString("apk_path")))
                throw new java.io.IOException("DXVK_MANIFEST_INVALID_"+dll);
            Path dest=target.resolve(dll),tmp=target.resolve(dll+".pending");
            if(Files.isSymbolicLink(dest)||Files.isSymbolicLink(tmp))
                throw new java.io.IOException("DXVK_FILE_SYMLINK");
            MessageDigest sha=MessageDigest.getInstance("SHA-256");
            long total=0;
            try(InputStream input=app.getAssets().open(ROOT+dll);
                OutputStream output=Files.newOutputStream(tmp)){
                byte[] buffer=new byte[65536];int n;
                while((n=input.read(buffer))!=-1){
                    total+=n;
                    if(total>64L*1024*1024)throw new java.io.IOException("DXVK_FILE_TOO_LARGE");
                    output.write(buffer,0,n);
                    sha.update(buffer,0,n);
                }
            }
            if(total<4096 || !hex(sha.digest()).equalsIgnoreCase(expected)){
                Files.deleteIfExists(tmp);
                throw new java.io.IOException("DXVK_HASH_MISMATCH_"+dll);
            }
            Files.move(tmp,dest,StandardCopyOption.REPLACE_EXISTING);
        }
        return target;
    }

    public static String configure(Context app,RuntimeLayout layout,
                                   Map<String,String> env,Path originalGame) {
        if(!isSelectedCarXStreet(originalGame))return "SKIPPED_NOT_CARX";
        String result="FAIL_CLOSED";
        try {
            if(app==null||layout==null||env==null)
                return result="DENIED_ARGUMENTS";
            Path stage=stageProvider(app);
            // Do not enable Vulkan until all PE DLLs were hash-validated.
            // Reuse exactly the signed X11 loader and Mesa driver from v49028.
            if(!MiniX11VulkanV49028.configureSelectedCarx(app,layout,env,true))
                return result="DENIED_NO_ATTESTED_X11_VULKAN_LOADER";

            String winPath="Z:"+stage.toString().replace('/','\\');
            String previous=env.get("WINEPATH");
            if(previous!=null && previous.length()>4096)
                return result="DENIED_OVERSIZED_WINEPATH";
            // WINEDLLPATH selects Wine's *builtin* libraries, not native PE
            // libraries. Wine's WINEPATH prepends a Windows-style search path.
            env.put("WINEPATH",winPath+
                    (previous==null||previous.isEmpty()?"":";"+previous));
            // If native DLL search fails, retain WineD3D builtin fallback.
            // This process-only override never updates global Wine registry.
            env.put("WINEDLLOVERRIDES","d3d11,dxgi=n,b");
            env.put("DXVK_CONFIG","dxgi.syncInterval = 0");
            env.put("DXVK_HUD","fps,devinfo");
            env.put("RM11_V458_ANDROID_VULKAN_FALLBACK","0");
            result=SUCCESS;
            return result;
        } catch(Exception e) {
            return result="DENIED_"+e.getClass().getSimpleName()+"_"+e.getMessage();
        } finally {
            OfflineDiagnosticJournal.record(app,"v49032-carx-private-dxvk",
                    "RM11_V49032_SELECTED_CARX="+isSelectedCarXStreet(originalGame)+"\n"
                    +"RM11_V49032_ROUTE="+result+"\n"
                    +"RM11_V49032_SYNC_INTERVAL_ZERO="+SUCCESS.equals(result)+"\n"
                    +"RM11_V49032_WINEPATH_NATIVE_SEARCH_ONLY="+SUCCESS.equals(result)+"\n"
                    +"RM11_V49032_ORIGINAL_EXE_UNMOVED=true\n"
                    +"RM11_V49032_GAME_FILES_UNMODIFIED=true\n"
                    +"RM11_V49032_WINE_PREFIX_UNMODIFIED=true\n"
                    +"RM11_V49032_OTHER_GAMES_UNCHANGED=true\n"
                    +"RM11_V49032_DXVK_LOADED=NOT_PROVEN_BY_ENV_ONLY");
        }
    }
}
