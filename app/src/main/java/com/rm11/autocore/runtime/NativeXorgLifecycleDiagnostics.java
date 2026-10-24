package com.rm11.autocore.runtime;

import android.app.ActivityManager;
import android.app.ApplicationExitInfo;
import android.content.Context;
import android.os.Build;
import android.os.Process;
import org.json.JSONArray;
import org.json.JSONObject;
import com.rm11.autocore.diagnostics.DiagnosticSanitizer;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.util.List;

/**
 * V4.0.2: durable, privacy-bounded process evidence for the app's OWN isolated
 * :rm11_xorg service. No shell, root, logcat, or permissions are required.
 * Previous v4 reports showed binder=dead, native UNIX socket=absent, and
 * WineNeverStarted, but could not distinguish native SIGSEGV from startup exit.
 */
public final class NativeXorgLifecycleDiagnostics {
    private static final String FILE_NAME = "native-xorg-service-phase.txt";
    private NativeXorgLifecycleDiagnostics() {}

    public static File evidenceFile(Context context) {
        return new File(new File(context.getFilesDir(), "offline-diagnostics"), FILE_NAME);
    }

    public static void phase(Context context, String phase) {
        try {
            File output=evidenceFile(context);
            File folder=output.getParentFile();
            if(folder == null) return;
            if(!folder.isDirectory() && !folder.mkdirs())return;
            if(Files.isSymbolicLink(output.toPath()) || Files.isSymbolicLink(folder.toPath()))return;
            String safe=phase.replaceAll("[^A-Za-z0-9_:.-]","_");
            String evidence="RM11_V402_NATIVE_XORG_SERVICE_PHASE="+safe+"\n"
                    +"pid="+Process.myPid()+"\n"
                    +"atUnixMs="+System.currentTimeMillis()+"\n";
            try(FileOutputStream stream=new FileOutputStream(output,false)) {
                stream.write(evidence.getBytes(StandardCharsets.UTF_8));
                stream.getFD().sync();
            }
        }catch(Exception ignored) {
            // Do not crash service while trying to describe a native failure.
        }
    }

    public static String readPhase(Context context) {
        try {
            File file=evidenceFile(context);
            if(!Files.isRegularFile(file.toPath(),LinkOption.NOFOLLOW_LINKS)
                    || file.length()>4096)return "RM11_V402_SERVICE_PHASE_MISSING";
            return DiagnosticSanitizer.scrub(
                    new String(Files.readAllBytes(file.toPath()),StandardCharsets.UTF_8),4096);
        }catch(Exception e) {
            return "RM11_V402_SERVICE_PHASE_READ_FAILED="+e.getClass().getSimpleName();
        }
    }

    /**
     * System-reported reason for an EXITED app subprocess, not assumptions
     * inferred from a dead binder. Only RM11's own :rm11_xorg process.
     */
    public static String recentServiceExits(Context context) {
        JSONObject result=new JSONObject();
        try {
            result.put("schema","rm11.native-xorg-exit-evidence.v1");
            result.put("sdk",Build.VERSION.SDK_INT);
            result.put("note","Android reported process exit details, when available.");
            JSONArray details=new JSONArray();
            if(Build.VERSION.SDK_INT>=30) {
                ActivityManager manager=(ActivityManager)context.getSystemService(
                        Context.ACTIVITY_SERVICE);
                if(manager!=null) {
                    List<ApplicationExitInfo> exits=
                            manager.getHistoricalProcessExitReasons(null,0,12);
                    int found=0;
                    for(ApplicationExitInfo info: exits) {
                        String name=info.getProcessName();
                        if(name==null || !name.equals(context.getPackageName()+":rm11_xorg"))
                            continue;
                        JSONObject row=new JSONObject();
                        row.put("timeUnixMs",info.getTimestamp());
                        row.put("pid",info.getPid());
                        row.put("reason",info.getReason());
                        row.put("status",info.getStatus());
                        row.put("importance",info.getImportance());
                        row.put("reasonLabels","0=unknown, 1=exit_self, 2=signaled, 3=low_memory, 4=crash, 5=crash_native, 6=anr, 7=initialization_failure, 8=permission_change");
                        String text=info.getDescription();
                        if(text!=null)
                            row.put("description",DiagnosticSanitizer.scrub(text,500));
                        // Android can expose a native tombstone for its own
                        // crash; read only a bounded trace, never full logcat.
                        try(InputStream trace=info.getTraceInputStream()) {
                            if(trace!=null) {
                                byte[] buf=new byte[8192];
                                int n=trace.read(buf);
                                if(n>0)row.put("traceExcerpt",DiagnosticSanitizer.scrub(
                                        new String(buf,0,n,StandardCharsets.UTF_8),6000));
                            }
                        }catch(Exception ignored) {
                            row.put("traceStatus","not_available");
                        }
                        details.put(row);
                        if(++found>=4)break;
                    }
                }
            }
            result.put("exits",details);
            result.put("exitCount",details.length());
        }catch(Exception e) {
            try{result.put("error",e.getClass().getSimpleName());}catch(Exception ignored){}
        }
        return result.toString();
    }

    public static String snapshot(Context context) {
        return "RM11_V402_NATIVE_XORG_SERVICE_STATE\n"+readPhase(context)
                +"\nRM11_V402_ANDROID_EXIT_INFO\n"+recentServiceExits(context);
    }
}
