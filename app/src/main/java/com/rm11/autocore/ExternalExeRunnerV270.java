package com.rm11.autocore;

import android.content.Context;
import android.net.Uri;
import com.rm11.autocore.runtime.ExternalExePilotPolicy;
import com.rm11.autocore.runtime.RuntimeLayout;
import com.rm11.autocore.runtime.WineExecutionPlan;
import com.rm11.autocore.runtime.WineGraphicsReadiness;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/** Explicitly authorized, single-file PE64 console pilot; not a general game launcher. */
public final class ExternalExeRunnerV270 {
    private ExternalExeRunnerV270() {}

    private static final class Capture implements Runnable {
        private final Process proc;
        private final ByteArrayOutputStream head=new ByteArrayOutputStream();
        private final byte[] tail=new byte[32768];
        private int cursor, filled;
        private long count;
        Capture(Process p) { proc=p; }
        @Override public void run() {
            try (InputStream in=proc.getInputStream()) {
                byte[] block=new byte[4096]; int n;
                while ((n=in.read(block))!=-1) {
                    synchronized (this) {
                        if (head.size()<4096) {
                            int keep=Math.min(n,4096-head.size());
                            head.write(block,0,keep);
                        }
                        for(int i=0;i<n;i++) {
                            tail[cursor]=block[i];
                            cursor=(cursor+1)%tail.length;
                            if (filled<tail.length) filled++;
                        }
                        count+=n;
                    }
                }
            } catch (IOException ignored) { /* Process may be terminated on timeout. */ }
        }
        synchronized String text() {
            byte[] end=new byte[filled];
            int start=count>=tail.length ? cursor : 0;
            for(int i=0;i<filled;i++) end[i]=tail[(start+i)%tail.length];
            String last=new String(end,java.nio.charset.StandardCharsets.UTF_8);
            if(count<=tail.length) return last;
            return new String(head.toByteArray(),java.nio.charset.StandardCharsets.UTF_8)
                    +"\n[LOG MIDDLE OMITTED]\n"+last;
        }
    }
    private static final class Running {
        final Process proc;
        final Capture capture;
        final Thread reader;
        Running(ProcessBuilder builder, String name) throws IOException {
            builder.redirectErrorStream(true);
            proc=builder.start();
            capture=new Capture(proc);
            reader=new Thread(capture,name);
            reader.setDaemon(true);
            reader.start();
        }
        void stop() {
            if(proc.isAlive()) {
                proc.destroy();
                try {if(!proc.waitFor(2,TimeUnit.SECONDS))proc.destroyForcibly();}
                catch(InterruptedException e){Thread.currentThread().interrupt();proc.destroyForcibly();}
            }
            try{reader.join(1400);}catch(InterruptedException e){Thread.currentThread().interrupt();}
        }
    }

    private static ProcessBuilder launch(java.util.List<String> argv, WineExecutionPlan p) {
        ProcessBuilder pb=new ProcessBuilder(argv);
        pb.directory(p.workingDirectory.toFile());
        Map<String,String> target=pb.environment();
        target.putAll(p.environment);
        return pb;
    }

    private static String hex(byte[] data) {
        StringBuilder out=new StringBuilder();
        for(byte value:data)out.append(String.format(java.util.Locale.ROOT,"%02x",value&255));
        return out.toString();
    }

    public static String run(Context ctx, Uri selected) {
        StringBuilder report=new StringBuilder("RM11 v2.7.1 - External EXE proof and GUI readiness\n");
        report.append("Explicit user selection via Android SAF: YES\n")
              .append("External source file modified: NO\n")
              .append("App-private temporary copy: YES; one file only, max 16 MiB\n")
              .append("Graphics, games and external DLL dependency loading: NOT VERIFIED\n");
        Path staged=null;
        Running server=null, wine=null;
        try {
            RuntimeLayout layout=new RuntimeLayout(ctx.getFilesDir().toPath(),
                    new File(ctx.getApplicationInfo().nativeLibraryDir).toPath());
            if(selected==null || !"content".equals(selected.getScheme()))
                throw new IOException("Selected document is not a readable content URI");
            Path directory=layout.appFiles.resolve("external-exe-pilot");
            Files.createDirectories(directory);
            if(Files.isSymbolicLink(directory) || !directory.toRealPath().startsWith(layout.appFiles.toRealPath()))
                throw new IOException("External EXE pilot staging directory is untrusted");
            staged=Files.createTempFile(directory,"rm11-import-",".exe");
            MessageDigest digest=MessageDigest.getInstance("SHA-256");
            long copied=0;
            try (InputStream input=ctx.getContentResolver().openInputStream(selected);
                 OutputStream output=Files.newOutputStream(staged)) {
                if(input==null)throw new IOException("Android document provider denied reading");
                byte[] buf=new byte[32768];int n;
                while((n=input.read(buf))!=-1) {
                    if(n==0)continue;
                    copied+=n;
                    if(copied>ExternalExePilotPolicy.MAX_EXE_BYTES)
                        throw new IOException("File exceeds 16 MiB pilot limit; no game folders copied");
                    digest.update(buf,0,n);
                    output.write(buf,0,n);
                }
            }
            ExternalExePilotPolicy.validate(layout,staged);
            report.append("Staged Windows PE64 x86-64 header: VALIDATED\n")
                  .append("Input file size bytes: ").append(copied).append('\n')
                  .append("Staged content SHA256: ").append(hex(digest.digest())).append('\n');
            WineExecutionPlan plan=WineExecutionPlan.forSmallUserSelectedExe(layout,staged);
            report.append(WineGraphicsReadiness.report(layout,plan.environment));
            server=new Running(launch(plan.serverCommand,plan),"rm11-pilot-wineserver");
            wine=new Running(launch(plan.wineCommand,plan),"rm11-pilot-client");
            boolean done=wine.proc.waitFor(45,TimeUnit.SECONDS);
            if(!done) {
                report.append("EXTERNAL_EXE_RESULT: TIMEOUT_45_SECONDS\n");
            } else {
                report.append("External Wine client exit code: ").append(wine.proc.exitValue()).append('\n');
            }
            wine.stop();
            String output=wine.capture.text();
            // Place evidence summary BEFORE detailed Wine trace. Offline journal
            // retains only first ~11 KB of each report, so a marker that appears
            // in the log tail must still be independently represented.
            boolean consoleMarker=output.contains("RM11_EXTERNAL_EXE_TEST_OK");
            boolean guiMarker=output.contains("RM11_EXTERNAL_GUI_WINDOW_CREATED");
            boolean consolePassed=done && wine.proc.exitValue()==47 && consoleMarker;
            boolean guiPassed=done && wine.proc.exitValue()==48 && guiMarker;
            report.append("Raw external console marker captured: ").append(consoleMarker?"YES":"NO").append('\n')
                  .append("Raw external GUI CreateWindow marker captured: ").append(guiMarker?"YES":"NO").append('\n')
                  .append("Log head/tail cap: 4096+32768 bytes; middle may be omitted\n");
            if(consolePassed) report.append("EXTERNAL_EXE_RESULT: VERIFIED_EXTERNAL_WIN64_EXECUTION\n");
            else if(guiPassed)
                report.append("EXTERNAL_EXE_RESULT: VERIFIED_GUI_API_CALLS_ONLY_NOT_VISIBLE_WINDOW\n");
            else if(done)
                report.append("EXTERNAL_EXE_RESULT: PROCESS_EXITED; application behavior NOT independently verified\n");
            report.append("Wine client output (bounded):\n").append(output).append('\n');
            return report.toString();
        } catch (Exception e) {
            report.append("EXTERNAL_EXE_RESULT: BLOCKED_OR_ERROR\n")
                  .append("Error type: ").append(e.getClass().getSimpleName()).append('\n')
                  .append("Error: ").append(e.getMessage()==null?"No message":e.getMessage()).append('\n');
            if(wine!=null)report.append("Wine client output (bounded):\n").append(wine.capture.text()).append('\n');
            return report.toString();
        } finally {
            if(wine!=null)wine.stop();
            if(server!=null)server.stop();
            if(staged!=null) {
                try {Files.deleteIfExists(staged);}catch(IOException ignored) {
                    // Fail closed: report no cleanup guarantee if Android FS rejects deletion.
                }
            }
        }
    }
}
