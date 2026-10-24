package com.rm11.autocore;

import android.content.Context;
import com.rm11.autocore.runtime.*;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * Fullscreen app-owned Wine desktop session, WITHOUT an EXE file picker or
 * fake dialog. The actual Wine Explorer desktop and Winefile.exe run inside
 * RM11's bundled X11 Android ScreenView via DISPLAY=127.0.0.1:2.
 *
 * The activity owns the session and controls its shutdown. All child Wine
 * processes are sourced from the signed APK and trusted app-private Wine
 * distribution. No native executable is executed from writable ImageFs.
 * Native FreeType experiments default OFF to preserve GUI stability.
 */
public final class WineAutoDesktopRunner {
    private WineAutoDesktopRunner() {}

    public interface StatusSink { void update(String message); }

    public static final class Session {
        private volatile boolean closed;
        public void close() { closed=true; }
        public boolean isClosed() { return closed; }
    }

    private static final class Child {
        final Process process;
        final Thread reader;
        private final ByteArrayOutputStream data=new ByteArrayOutputStream(8192);
        private long seen;
        Child(ProcessBuilder builder,String name) throws IOException {
            builder.redirectErrorStream(true);
            process=builder.start();
            reader=new Thread(()->{
                try(InputStream in=process.getInputStream()) {
                    byte[] block=new byte[4096];
                    int n;
                    while((n=in.read(block))!=-1) {
                        synchronized(data) {
                            if(seen<24000) data.write(block,0,Math.min(n,(int)(24000-seen)));
                            seen+=n;
                        }
                    }
                } catch(IOException ignored) {
                    /* Explicit Activity shutdown may close this process. */
                }
            },"rm11-desktop-"+name);
            reader.setDaemon(true);
            reader.start();
        }
        String log() {
            synchronized(data) {
                return data.toString(java.nio.charset.StandardCharsets.UTF_8);
            }
        }
        void stop() {
            if(process.isAlive()) {
                process.destroy();
                try {
                    if(!process.waitFor(2,TimeUnit.SECONDS))process.destroyForcibly();
                } catch(InterruptedException e) {
                    Thread.currentThread().interrupt();
                    process.destroyForcibly();
                }
            }
            try{reader.join(600);}catch(InterruptedException e){Thread.currentThread().interrupt();}
        }
    }

    private static ProcessBuilder command(java.util.List<String> argv, WineExecutionPlan plan) {
        ProcessBuilder p=new ProcessBuilder(argv);
        p.directory(plan.workingDirectory.toFile());
        Map<String,String> env=p.environment();
        env.putAll(plan.environment);
        // NEVER opt in experimental glyph hooks from auto-start. Previous
        // device reports tie native FreeType use to wineserver IPC crashes.
        env.put("RM11_NATIVE_FREETYPE_DLOPEN_REDIRECT","0");
        return p;
    }

    public static String run(Context context, Session session, StatusSink sink) {
        StringBuilder report=new StringBuilder(2200);
        report.append("RM11_V303_FULLSCREEN_DESKTOP_AUTOBOOT\n");
        report.append("User selected EXE or test dialog: NO\n");
        report.append("Main Android app visual surface: EMBEDDED_X11_SCREEN\n");
        report.append("Only overlay: DIAGNOSTICS_AND_LOGS\n");
        report.append("Experimentally unstable Wine FreeType redirection: DISABLED\n");
        report.append("Source of desktop: ORIGINAL_SIGNED_WINE_AND_APP_PRIVATE_IMAGEFS\n");
        Child server=null, explorer=null, fileManager=null;
        try {
            RuntimeLayout layout=new RuntimeLayout(context.getFilesDir().toPath(),
                    Path.of(context.getApplicationInfo().nativeLibraryDir));
            RuntimeAssessment.inspect(layout).requireReady();
            WineX11EndpointProbe.Result probe=null;
            for(int attempt=0;attempt<4&&!session.isClosed();attempt++) {
                probe=WineX11EndpointProbe.probeEmbeddedDisplay2();
                if(probe.accepted)break;
                Thread.sleep(400);
            }
            if(probe==null || !probe.accepted)
                throw new IOException("RM11_V303_EMBEDDED_X11_NOT_ACCEPTING_CONNECTION");
            report.append(probe.reportForDisplay(WineX11EndpointProbe.EMBEDDED_DISPLAY));
            report.append(WineGuiImportBridge.prepare(layout));
            report.append(WineX11DriverBridge.prepare(layout));
            report.append(WineFontFilesBridge.prepare(layout));
            WineExecutionPlan plan=WineExecutionPlan.forEmbeddedGraphicalDesktop(layout);
            if(session.isClosed())return report.append("CLOSED_BEFORE_START\n").toString();
            sink.update("جاري تشغيل سطح مكتب Wine...");
            server=new Child(command(plan.serverCommand,plan),"wineserver");
            java.util.List<String> explorerCmd=WineExecutionPlan.trustedEmbeddedExplorerCommand(layout);
            explorer=new Child(command(explorerCmd,plan),"explorer");
            report.append("RM11_V303_WINE_EXPLORER_AUTOSTARTED\n");
            // Start the ORIGINAL Wine graphical file manager, rather than
            // showing a blank desktop until the user picks a diagnostic EXE.
            fileManager=new Child(command(plan.wineCommand,plan),"winefile");
            report.append("RM11_V303_WINEFILE_GRAPHICAL_MANAGER_AUTOSTARTED\n");
            sink.update("واجهة Wine مفتوحة. افتح الملفات والبرامج من مدير ملفات Windows. التشخيص من الزر العلوي.");
            boolean fileReported=false;
            while(!session.isClosed()) {
                if(!server.process.isAlive()) {
                    report.append("RM11_V303_WINESERVER_EXITED: ")
                          .append(server.process.exitValue()).append('\n');
                    sink.update("تعطل خادم Wine. افتح التشخيص للاطلاع على سبب العطل.");
                    break;
                }
                if(!explorer.process.isAlive()) {
                    report.append("RM11_V303_EXPLORER_EXITED: ")
                          .append(explorer.process.exitValue()).append('\n');
                    sink.update("خرج سطح مكتب Wine. افتح التشخيص لقراءة السجل.");
                    break;
                }
                if(!fileReported && !fileManager.process.isAlive()) {
                    fileReported=true;
                    report.append("RM11_V303_WINEFILE_EARLY_EXIT: ")
                          .append(fileManager.process.exitValue()).append('\n');
                    sink.update("سطح مكتب Wine يعمل، لكن مدير الملفات أغلق. تفاصيل السبب في التشخيص.");
                }
                Thread.sleep(300);
            }
            report.append("RM11_V303_USER_OR_ACTIVITY_CLOSED_DESKTOP: ")
                  .append(session.isClosed()?"YES":"NO").append('\n');
        } catch(InterruptedException e) {
            Thread.currentThread().interrupt();
            report.append("RM11_V303_ACTIVITY_CANCELLED\n");
        } catch(Exception e) {
            report.append("RM11_V303_DESKTOP_START_ERROR: ")
                  .append(e.getClass().getSimpleName()).append(": ")
                  .append(e.getMessage()).append('\n');
            sink.update("تعذر فتح واجهة Wine. افتح التشخيص للاطلاع على التفاصيل.");
        } finally {
            // Stop only children owned by THIS Android foreground session.
            if(fileManager!=null)fileManager.stop();
            if(explorer!=null)explorer.stop();
            if(server!=null)server.stop();
            if(server!=null)
                report.append("RM11_V303_WINESERVER_LOG:\n").append(server.log()).append('\n');
            if(explorer!=null)
                report.append("RM11_V303_EXPLORER_LOG:\n").append(explorer.log()).append('\n');
            if(fileManager!=null)
                report.append("RM11_V303_WINEFILE_LOG:\n").append(fileManager.log()).append('\n');
        }
        return report.toString();
    }
}
