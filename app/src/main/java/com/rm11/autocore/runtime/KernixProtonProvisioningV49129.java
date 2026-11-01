package com.rm11.autocore.runtime;

import android.content.Context;
import android.os.Build;
import com.rm11.autocore.diagnostics.OfflineDiagnosticJournal;
import org.json.JSONObject;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.io.*;

/** App-private Proton/FEX native-guest qualification. Not a graphics proof. */
public final class KernixProtonProvisioningV49129 {
    private KernixProtonProvisioningV49129(){}
    private static final String SCHEMA="kernix.proton.native-guest.v49129";
    private static final String RECEIPT="kernix-proton-native-guest-v49129.json";
    private static final String PREF="kernix_proton_install_v49129";
    // Reject overlapping button presses instead of queuing another full
    // extraction/Wineboot behind a synchronized monitor on a worker thread.
    private static final java.util.concurrent.atomic.AtomicBoolean IN_FLIGHT=
        new java.util.concurrent.atomic.AtomicBoolean(false);
    static boolean tryBeginQualification(){
        return IN_FLIGHT.compareAndSet(false,true);
    }
    static void endQualification(){IN_FLIGHT.set(false);}
    public static boolean qualified(String report) {
        if(report==null||report.length()>16384)return false;
        boolean loader=false,server=false,boot=false,guest=false,mode=false;
        for(String row:report.split("\\r?\\n")){
            if(row.startsWith("P11_LOADER="))
                loader=row.startsWith("P11_LOADER=EXIT_0_OUTPUT_");
            if(row.startsWith("P11_WINESERVER="))
                server=row.startsWith("P11_WINESERVER=EXIT_0_OUTPUT_");
            if(row.startsWith("P11_WINEBOOT_MODE="))
                mode=row.equals("P11_WINEBOOT_MODE=PREPOPULATED_RESTART_NO_FORCED_INF_UPDATE");
            if(row.startsWith("P11_WINEBOOT="))
                boot=row.startsWith("P11_WINEBOOT=EXIT_0_OUTPUT_")
                    ||row.equals("P11_WINEBOOT=ALREADY_COMPLETED_WITH_THIS_NATIVE_BRIDGE");
            if(row.startsWith("P11_FEX_X64_SMOKE="))
                guest=row.equals("P11_FEX_X64_SMOKE=P11_X64_GUEST_EXIT47_AND_MARKER_PASS");
        }
        return loader&&server&&boot&&guest&&mode;
    }
    private static Path file(Context ctx){
        return ctx.getFilesDir().toPath().resolve(RECEIPT);
    }
    private static String bundleSha(Context ctx)throws Exception{
        try(InputStream in=ctx.getAssets().open("runtime/kernix-proton11-fex2610-manifest.json")){
            byte[] data=in.readNBytes(30000);
            if(data.length==30000)throw new IOException("P11_MANIFEST_OVERSIZED");
            JSONObject j=new JSONObject(new String(data,StandardCharsets.UTF_8));
            String sha=j.getString("zip_sha256");
            if(!KernixProtonFexInstallerV49121.SCHEMA.equals(j.optString("schema"))
                ||!sha.matches("[a-f0-9]{64}"))throw new IOException("P11_MANIFEST_INVALID");
            return sha;
        }
    }
    private static long version(Context ctx)throws Exception{
        return ctx.getPackageManager().getPackageInfo(ctx.getPackageName(),0).getLongVersionCode();
    }
    private static void store(Context ctx)throws Exception{
        Path dest=file(ctx),tmp=dest.resolveSibling(RECEIPT+".pending");
        if(Files.isSymbolicLink(dest)||Files.isSymbolicLink(tmp))
            throw new IOException("P11_UNSAFE_NATIVE_RECEIPT");
        JSONObject j=new JSONObject();
        j.put("schema",SCHEMA).put("source",bundleSha(ctx))
            .put("versionCode",version(ctx)).put("sdk",Build.VERSION.SDK_INT)
            .put("device",Build.MODEL).put("guestWin64",true)
            .put("gpuPresent",false)
            .put("prefixUpdateCompleted",false)
            .put("bootstrapMode","PINNED_PREFIX_RESTART_ONLY")
            .put("timestamp",System.currentTimeMillis());
        Files.write(tmp,j.toString().getBytes(StandardCharsets.UTF_8),
            StandardOpenOption.CREATE,StandardOpenOption.TRUNCATE_EXISTING);
        try{Files.move(tmp,dest,StandardCopyOption.ATOMIC_MOVE,StandardCopyOption.REPLACE_EXISTING);}
        catch(java.nio.file.AtomicMoveNotSupportedException e){
            Files.move(tmp,dest,StandardCopyOption.REPLACE_EXISTING);
        }
    }
    private static boolean proof(Context ctx){
        try{
            Path p=file(ctx);
            if(Files.isSymbolicLink(p)||!Files.isRegularFile(p,LinkOption.NOFOLLOW_LINKS)
                ||Files.size(p)>2048)return false;
            JSONObject j=new JSONObject(new String(Files.readAllBytes(p),StandardCharsets.UTF_8));
            return SCHEMA.equals(j.optString("schema"))
                &&bundleSha(ctx).equals(j.optString("source"))
                &&version(ctx)==j.optLong("versionCode",-1)
                &&Build.VERSION.SDK_INT==j.optInt("sdk",-1)
                &&Build.MODEL.equals(j.optString("device"))
                &&j.optBoolean("guestWin64",false)&&!j.optBoolean("gpuPresent",true)
                &&!j.optBoolean("prefixUpdateCompleted",true)
                &&"PINNED_PREFIX_RESTART_ONLY".equals(j.optString("bootstrapMode"))
                &&j.optLong("timestamp",0)>0;
        }catch(Exception e){return false;}
    }
    /** Run off the main thread; never switch the game's live Wine session. */
    public static String installAndQualify(Context ctx){
        if(ctx==null)return "P11_CONTEXT_MISSING";
        if(!tryBeginQualification())return "P11_QUALIFICATION_ALREADY_RUNNING";
        try{
            return installAndQualifyOnce(ctx);
        }finally{
            endQualification();
        }
    }
    private static synchronized String installAndQualifyOnce(Context ctx){
        String install=KernixProtonFexInstallerV49121.prepare(ctx);
        String state;
        try{
            if(!"PROTON_FEX_STAGED_NATIVE_MATCHED_ACTIVATION_PENDING".equals(install))
                state="P11_INSTALL_BLOCKED_"+install;
            else if(KernixProtonPrefixV49126.ready(ctx.getFilesDir().toPath())
                &&proof(ctx))
                state="P11_SAME_APK_NATIVE_GUEST_ALREADY_QUALIFIED";
            else{
                String observed=KernixProtonNativeQualificationV49123.run(ctx);
                if(qualified(observed)){
                    store(ctx);
                    state="P11_NATIVE_WINEBOOT_AND_FEX_X64_GUEST_QUALIFIED";
                }else state="P11_NATIVE_BOOT_OR_X64_GUEST_FAILED";
            }
        }catch(Exception e){state="P11_NATIVE_QUALIFICATION_BLOCKED_"+e.getClass().getSimpleName();}
        if(!state.equals("P11_NATIVE_WINEBOOT_AND_FEX_X64_GUEST_QUALIFIED")
           &&!state.equals("P11_SAME_APK_NATIVE_GUEST_ALREADY_QUALIFIED"))
            try{Files.deleteIfExists(file(ctx));}catch(IOException ignored){}
        ctx.getSharedPreferences(PREF,0).edit().putString("state",state).commit();
        OfflineDiagnosticJournal.record(ctx,"v49129-proton-device-install",
            "P11_INSTALL="+install+"\nP11_NATIVE_GUEST="+state+
            "\nP11_GAME_ENGINE_SWITCHED=false\nP11_X11_GPU_FRAMES_UNVERIFIED=true"+
            "\nP11_OLD_WINE_PREFIX_AND_USER_GAMES_UNCHANGED=true");
        return state;
    }
    public static JSONObject snapshot(Context ctx){
        JSONObject j=new JSONObject();
        if(ctx==null)return j;
        try{
            boolean staged=KernixProtonFexInstallerV49121.staged(ctx);
            boolean prefix=staged&&KernixProtonPrefixV49126.ready(ctx.getFilesDir().toPath());
            j.put("schema","kernix.proton.status.v49129");
            j.put("signedSlot",KernixProtonFexInstallerV49121.SLOT);
            j.put("assetsInstalled",staged);
            j.put("separateWritablePrefix",prefix);
            j.put("nativeWin64GuestQualified",prefix&&proof(ctx));
            j.put("prefixUpdateCompleted",false);
            j.put("bootstrapMode","PINNED_PREFIX_RESTART_ONLY");
            j.put("status",ctx.getSharedPreferences(PREF,0).getString(
                "state","P11_ON_DEVICE_INSTALL_PENDING"));
            j.put("windowsX11VisibleFramesQualified",false);
            j.put("gameEngineActivated",false);
            j.put("gameActivationBlockedReason",
                "PROTON_PREFIX_UPDATE_AND_X11_GPU_FRAMES_NOT_YET_QUALIFIED");
            j.put("legacyGameFilesModified",false);
        }catch(Exception ignored){}
        return j;
    }
}
