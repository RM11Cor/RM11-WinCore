package com.rm11.autocore;

import android.content.Context;
import com.rm11.autocore.runtime.*;
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
        private volatile String diagnostics="RM11_V303_DESKTOP_INITIALIZING";
        public void close() { closed=true; }
        public boolean isClosed() { return closed; }
        public String diagnostics() { return diagnostics; }
        private void updateDiagnostics(String value) { diagnostics=value; }
    }

    private static final class Child {
        final Process process;
        final Thread reader;
        private final WineDesktopLogCapture capture=new WineDesktopLogCapture();
        Child(ProcessBuilder builder,String name) throws IOException {
            builder.redirectErrorStream(true);
            process=builder.start();
            reader=new Thread(()->{
                try(InputStream in=process.getInputStream()) {
                    byte[] block=new byte[4096];
                    int n;
                    while((n=in.read(block))!=-1) {
                        capture.append(block,0,n);
                    }
                } catch(IOException ignored) {
                    /* Explicit Activity shutdown may close this process. */
                }
            },"rm11-desktop-"+name);
            reader.setDaemon(true);
            reader.start();
        }
        String log() { return capture.snapshot(); }
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

    private static String last(String text,int max) {
        return text.length()<=max ? text : text.substring(text.length()-max);
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

    public static String run(Context context, Session session, StatusSink sink,
                             int screenWidth,int screenHeight) {
        StringBuilder report=new StringBuilder(2200);
        report.append("RM11_V304_PERSISTENT_WINE_DESKTOP_SESSION\n");
        report.append("RM11_V303_FULLSCREEN_DESKTOP_AUTOBOOT\n");
        report.append("User selected EXE or test dialog: NO\n");
        report.append("Main Android app visual surface: EMBEDDED_X11_SCREEN\n");
        report.append("Only overlay: DIAGNOSTICS_AND_LOGS\n");
        report.append("Experimentally unstable Wine FreeType redirection: DISABLED\n");
        report.append("Source of desktop: ORIGINAL_SIGNED_WINE_AND_APP_PRIVATE_IMAGEFS\n");
        Child server=null, explorer=null, fileManager=null;
        StringBuilder preservedFailure=new StringBuilder(5000);
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
            report.append(WineDesktopPathAudit.inspect(layout));
            // Read-only Android-side FreeType glyph sanity check. This does
            // NOT turn on the Wine process native FreeType bridge that broke
            // wineserver in prior device tests.
            report.append("RM11_V305_WINE_GLYPH_ISOLATED_READINESS\n");
            String glyphProof=WineNativeFontProbe.inspect(layout);
            report.append(glyphProof);
            boolean safeFontProof=glyphProof.contains(
                    "RM11_V302_FONT_PROBE_NATIVE_GLYPH_A_RENDER_OK");
            // Font proof must be from Android's independent signed NDK ELF,
            // NOT from an unstable previous Wine client or from a user file.
            report.append("RM11_V306_ISOLATED_ANDROID_GLYPH_A_READY: ")
                  .append(safeFontProof?"YES":"NO").append('\n')
                  .append("RM11_V306_WINESERVER_EXPLORER_FREETYPE_HOOK: OFF\n");
            report.append("RM11_V305_WINE_FREETYPE_INJECTION_STILL_DISABLED_BY_DEFAULT\n");
            WineExecutionPlan plan=WineExecutionPlan.forEmbeddedGraphicalDesktop(layout);
            if(session.isClosed())return report.append("CLOSED_BEFORE_START\n").toString();
            sink.update("جاري تشغيل سطح مكتب Wine...");
            // One bounded recovery for unexpected IPC server termination.
            // The foreground Activity owns the session; never restart after
            // the user closes it or after the second failure.
            for (int attempt=0; attempt<2 && !session.isClosed(); attempt++) {
            report.append("RM11_V305_DESKTOP_START_ATTEMPT: ").append(attempt+1).append('\n');
            server=new Child(command(plan.serverCommand,plan),"wineserver");
            java.util.List<String> explorerCmd=
                    WineExecutionPlan.trustedEmbeddedExplorerCommand(layout,
                            screenWidth,screenHeight);
            explorer=new Child(command(explorerCmd,plan),"explorer");
            report.append("RM11_V303_WINE_EXPLORER_AUTOSTARTED\n");
            // v3.0.6 only: first attempt may run FreeType in the signed
            // original Winefile child when Android's independent glyph proof
            // succeeded. Wine server/Explorer ALWAYS retain their stable
            // FreeType-disabled process environments. Attempt #2 is a
            // guaranteed rollback without the font hook.
            boolean scopedFonts=WineDesktopFontLaunchPolicy.enableForWinefile(
                    safeFontProof,session.isClosed(),attempt+1);
            ProcessBuilder winefileBuilder=command(plan.wineCommand,plan);
            if(scopedFonts)
                winefileBuilder.environment().put(
                    "RM11_NATIVE_FREETYPE_DLOPEN_REDIRECT","1");
            fileManager=new Child(winefileBuilder,"winefile");
            final long winefileStartNanos=System.nanoTime();
            report.append("RM11_V303_WINEFILE_GRAPHICAL_MANAGER_AUTOSTARTED\n")
                  .append("RM11_V306_WINEFILE_FREETYPE_SCOPED_ATTEMPT: ")
                  .append(scopedFonts?"ENABLED":"DISABLED").append('\n')
                  .append("RM11_V306_WINE_SERVER_NATIVE_FONT_HOOK: DISABLED\n");
            sink.update(scopedFonts
                    ? "تجربة خطوط Wine داخل مدير الملفات فقط؛ عند أي انهيار سيتم الرجوع للإعداد المستقر."
                    : "واجهة Wine تعمل بخطوط التجربة معطّلة لحماية الخادم.");
            boolean fileReported=false, explorerReported=false, fontReported=false;
            boolean restartAfterServerDeath=false;
            report.append("RM11_V304_FOREGROUND_OWNS_DESKTOP_LIFETIME\n");
            while(true) {
                WineDesktopSessionPolicy.Decision decision=
                        WineDesktopSessionPolicy.decide(session.isClosed(),
                                server.process.isAlive(), explorer.process.isAlive(),
                                fileManager.process.isAlive());
                if(decision==WineDesktopSessionPolicy.Decision.CLOSE_REQUESTED) {
                    report.append("RM11_V304_USER_OR_ACTIVITY_CLOSE_REQUESTED\n");
                    break;
                }
                if(decision==WineDesktopSessionPolicy.Decision.SERVER_STOPPED) {
                    int serverExit=server.process.exitValue();
                    report.append("RM11_V304_WINESERVER_EXITED: ")
                          .append(serverExit).append('\n');
                    report.append("RM11_V305_SERVER_DIED_WITHOUT_ACTIVITY_CLOSE\n");
                    preservedFailure.append("RM11_V307_FIRST_FAILURE: WINESERVER_EXIT=").append(serverExit).append('\n')
                        .append("RM11_V307_SERVER_TAIL:\n").append(last(server.log(),2400)).append('\n')
                        .append("RM11_V307_WINEFILE_TAIL:\n").append(last(fileManager.log(),2400)).append('\n');
                    report.append("RM11_V305_SERVER_DEATH_LOG_TAIL:\n")
                          .append(last(server.log(),2200)).append('\n');
                    if(WineDesktopRecoveryPolicy.mayRestartAfterServerDeath(session.isClosed(),attempt+1)) {
                        restartAfterServerDeath=true;
                        report.append("RM11_V305_AUTO_RECOVERY_ONCE_REQUESTED\n");
                        sink.update("خادم Wine توقف؛ استعادة سطح المكتب تلقائياً لمرة واحدة...");
                    } else {
                        report.append("RM11_V305_AUTO_RECOVERY_NOT_REPEATED\n");
                        sink.update("خادم Wine توقف. التشخيص محفوظ دون تكرار غير محدود.");
                    }
                    break;
                }
                // Wine Explorer /desktop is a bootstrap helper that can
                // EXIT SUCCESSFULLY (code 0) after spawning the actual
                // desktop X11 windows. Its exit is not session termination.
                if(!explorerReported && !explorer.process.isAlive()) {
                    explorerReported=true;
                    int code=explorer.process.exitValue();
                    report.append("RM11_V304_EXPLORER_BOOTSTRAP_EXIT_CODE: ")
                          .append(code).append('\n')
                          .append(code==0
                                ? "RM11_V304_EXPLORER_NORMAL_EXIT_DESKTOP_KEPT\n"
                                : "RM11_V304_EXPLORER_FAILURE_DESKTOP_HELD_FOR_DIAGNOSTICS\n");
                    sink.update(code==0
                            ? "سطح مكتب Wine مستمر بعد اكتمال تشغيل Explorer."
                            : "Explorer خرج بخطأ، لكن جلسة Wine باقية لفحص مدير الملفات.");
                }
                if(!fontReported && scopedFonts) {
                    String fileLog=fileManager.log();
                    if(fileLog.contains("RM11_V301_NDK_FREETYPE_DLOPEN_SUCCEEDED")) {
                        fontReported=true;
                        report.append("RM11_V306_WINEFILE_FREETYPE_NATIVE_DLOPEN: SUCCEEDED\n");
                    } else if(fileLog.contains("RM11_V301_NDK_FREETYPE_DLOPEN_FAILED") ||
                              fileLog.contains("Wine cannot find the FreeType")) {
                        fontReported=true;
                        report.append("RM11_V306_WINEFILE_FREETYPE_NATIVE_DLOPEN: FAILED\n");
                    }
                }
                if(!fileReported && !fileManager.process.isAlive()) {
                    fileReported=true;
                    int code=fileManager.process.exitValue();
                    long life=TimeUnit.NANOSECONDS.toMillis(
                            System.nanoTime()-winefileStartNanos);
                    report.append("RM11_V304_WINEFILE_EXIT_CODE: ")
                          .append(code).append('\n')
                          .append("RM11_V306_WINEFILE_LIFETIME_MS: ")
                          .append(life).append('\n');
                    if(scopedFonts &&
                            WineDesktopFontLaunchPolicy.retryAfterEarlyWinefileFailure(
                                    session.isClosed(),attempt+1,code,life)) {
                        restartAfterServerDeath=true;
                        report.append("RM11_V306_WINEFILE_EARLY_ERROR_SAFE_ROLLBACK\n");
                        preservedFailure.append("RM11_V307_FIRST_FAILURE: WINEFILE_EXIT=").append(code)
                            .append(" lifetime_ms=").append(life).append('\n')
                            .append("RM11_V307_WINEFILE_TAIL:\n").append(last(fileManager.log(),2400)).append('\n')
                            .append("RM11_V307_SERVER_TAIL:\n").append(last(server.log(),1200)).append('\n');
                        sink.update("تعطل مدير ملفات Wine أثناء تجربة الخطوط؛ إعادة تشغيله مرة واحدة بدون الحقن.");
                        break;
                    }
                    sink.update("خادم Wine يعمل لكن مدير الملفات خرج. تفاصيل Wine في التشخيص.");
                }
                StringBuilder live=new StringBuilder(report);
                if(preservedFailure.length()>0)live.append("\nRM11_V307_PRESERVED_FIRST_FAILURE_BEGIN\n")
                        .append(preservedFailure).append("RM11_V307_PRESERVED_FIRST_FAILURE_END\n");
                if(server!=null)live.append("\nLIVE WINESERVER:\n").append(last(server.log(),2400));
                if(explorer!=null)live.append("\nLIVE EXPLORER:\n").append(last(explorer.log(),2400));
                if(fileManager!=null)live.append("\nLIVE WINEFILE:\n").append(last(fileManager.log(),2400));
                session.updateDiagnostics(live.toString());
                Thread.sleep(850);
            }
            if(restartAfterServerDeath && !session.isClosed()) {
                if(scopedFonts) report.append(
                        "RM11_V306_SCOPED_FREETYPE_DISABLED_ON_RECOVERY\n");
                // Exit the dead desktop only; preserve device diagnostics and
                // never overwrite the Wine prefix, programs, font files or
                // registry. A fresh Wine server and original winefile follow.
                report.append("RM11_V305_FIRST_ATTEMPT_EXPLORER_TAIL:\n")
                      .append(last(explorer.log(),1100)).append('\n')
                      .append("RM11_V305_FIRST_ATTEMPT_WINEFILE_TAIL:\n")
                      .append(last(fileManager.log(),1600)).append('\n');
                session.updateDiagnostics(last(report.toString(),16000));
                fileManager.stop();
                explorer.stop();
                server.stop();
                fileManager=null; explorer=null; server=null;
                Thread.sleep(750);
                continue;
            }
            break;  // normal user close or final server exit
            }
            report.append("RM11_V303_USER_OR_ACTIVITY_CLOSED_DESKTOP: ")
                  .append(session.isClosed()?"YES":"NO").append('\n')
                  .append("RM11_V306_SCOPE_RESTRICTION_WINESERVER_EXPLORER: ALWAYS_OFF\n");
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
            // The archive has a fixed per-event size limit. Keep decisive
            // current Wine errors near the front of the final report before
            // verbose +x11drv/+process dumps could consume the entire entry.
            if(server!=null)
                report.append("RM11_V304_WINESERVER_LATEST:\n")
                      .append(last(server.log(),1700)).append('\n');
            if(explorer!=null)
                report.append("RM11_V304_EXPLORER_LATEST:\n")
                      .append(last(explorer.log(),1700)).append('\n');
            if(fileManager!=null)
                report.append("RM11_V304_WINEFILE_LATEST:\n")
                      .append(last(fileManager.log(),2600)).append('\n');
            if(server!=null)
                report.append("RM11_V303_WINESERVER_LOG:\n").append(server.log()).append('\n');
            if(explorer!=null)
                report.append("RM11_V303_EXPLORER_LOG:\n").append(explorer.log()).append('\n');
            if(fileManager!=null)
                report.append("RM11_V303_WINEFILE_LOG:\n").append(fileManager.log()).append('\n');
        }
        // Preserve first-failure evidence AFTER verbose final process logs, so
        // bounded diagnostic exports do not lose it during automatic recovery.
        if(preservedFailure.length()>0)report.append("\nRM11_V307_PRESERVED_FIRST_FAILURE_BEGIN\n")
                .append(preservedFailure)
                .append("RM11_V307_PRESERVED_FIRST_FAILURE_END\n");
        session.updateDiagnostics(last(report.toString(),16000));
        return report.toString();
    }
}
