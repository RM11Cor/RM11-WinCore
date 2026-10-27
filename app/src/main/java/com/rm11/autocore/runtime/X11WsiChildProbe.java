package com.rm11.autocore.runtime;

import android.content.Context;
import com.rm11.autocore.diagnostics.OfflineDiagnosticJournal;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.concurrent.TimeUnit;

/**
 * v472: check the ACTUAL Bionic Vulkan instance extension set in a separate
 * signed native executable before the game is started, at most once per
 * app-data lifecycle. No GPU initialization occurs in the Android UI process.
 * Failures, native crashes and timeouts cannot propagate to Wine or the UI.
 */
public final class X11WsiChildProbe {
    private X11WsiChildProbe() {}
    private static final String EXE="librm11_x11_wsi_probe_v472.so";
    private static final int MAX_OUTPUT=8192;
    private static final long MAX_RUN_MILLIS=2400;

    public static void inspectOnce(Context context) {
        if(context==null)return;
        Process process=null;
        Path output=null;
        try {
            Path dir=context.getFilesDir().toPath().resolve("offline-diagnostics");
            Files.createDirectories(dir);
            Path durable=dir.resolve("last-v472-wsi.json");
            if(Files.isRegularFile(durable,LinkOption.NOFOLLOW_LINKS))
                return;
            // Persist the attempt even if a driver faults and process quits.
            OfflineDiagnosticJournal.record(context,"v472-x11-wsi-child",
                "RM11_V472_WSI_CHILD=START_REQUESTED\n"
                +"RM11_V472_CHILD_ISOLATED_FROM_ANDROID_UI=true\n"
                +"RM11_V472_CHILD_RUNS_ONCE=true");

            Path executable=context.getApplicationInfo().nativeLibraryDir==null
                ?null:java.nio.file.Paths.get(context.getApplicationInfo().nativeLibraryDir,EXE);
            if(executable==null
                ||!Files.isRegularFile(executable,LinkOption.NOFOLLOW_LINKS)
                ||Files.size(executable)<4096) {
                record(context,"NATIVE_PROBE_NOT_PACKAGED","",null);
                return;
            }
            output=dir.resolve("v472-wsi-child-output.pending");
            if(Files.isSymbolicLink(output)){
                record(context,"UNSAFE_OUTPUT_PATH","",null);
                return;
            }
            // Only the exact packaged, executable ARM64 ELF is invoked.
            // No shell, Termux, user-supplied paths, driver replacement or root.
            ProcessBuilder builder=new ProcessBuilder(executable.toString());
            builder.redirectErrorStream(true);
            builder.redirectOutput(output.toFile());
            process=builder.start();
            boolean ended=process.waitFor(MAX_RUN_MILLIS,TimeUnit.MILLISECONDS);
            if(!ended) {
                process.destroyForcibly();
                process.waitFor(300,TimeUnit.MILLISECONDS);
            }
            String observed="";
            if(Files.isRegularFile(output,LinkOption.NOFOLLOW_LINKS)
                    &&Files.size(output)<=MAX_OUTPUT)
                observed=new String(Files.readAllBytes(output),StandardCharsets.UTF_8);
            String status=ended?"EXITED":"TIMEOUT_TERMINATED";
            Integer exit=ended?process.exitValue():null;
            record(context,status,observed,exit);
        }catch(InterruptedException interrupted) {
            if(process!=null)process.destroyForcibly();
            Thread.currentThread().interrupt();
            record(context,"INTERRUPTED","",null);
        }catch(IOException|SecurityException failure) {
            if(process!=null)process.destroyForcibly();
            record(context,"FAILED_"+failure.getClass().getSimpleName(),"",null);
        }finally {
            if(output!=null) {
                try{Files.deleteIfExists(output);}catch(IOException ignored){}
            }
        }
    }
    private static void record(Context context,String status,String output,Integer exit){
        String result="RM11_V472_WSI_CHILD="+status+"\n"
            +"RM11_V472_WSI_CHILD_EXIT="+(exit==null?"UNVERIFIED":exit)+"\n"
            +"RM11_V472_CHILD_ISOLATED_FROM_ANDROID_UI=true\n"
            +"RM11_V472_X11_WSI_STATUS="+X11WsiProbeVerdict.classify(output)+"\n"
            +"RM11_V472_CHILD_STDOUT:\n"+output;
        OfflineDiagnosticJournal.record(context,"v472-x11-wsi-child",result);
    }
}
