package com.rm11.autocore;

import android.content.Context;
import com.rm11.autocore.runtime.*;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
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
        private volatile boolean fontTestRequested;
        private volatile boolean fontTestConsumed;
        private volatile boolean stableWinefileRunning;
        private volatile String diagnostics="RM11_V303_DESKTOP_INITIALIZING";
        public void close() { closed=true; }
        public boolean isClosed() { return closed; }
        /** Explicit user action only; never test unsafe fonts during autostart. */
        public synchronized boolean requestFontTest() {
            if(closed || !stableWinefileRunning || fontTestConsumed || fontTestRequested)
                return false;
            fontTestRequested=true;
            return true;
        }
        private synchronized boolean consumeFontTest() {
            if(!fontTestRequested || closed || fontTestConsumed)return false;
            fontTestRequested=false;
            fontTestConsumed=true;
            return true;
        }
        public String diagnostics() { return diagnostics; }
        private void updateDiagnostics(String value) { diagnostics=value; }
        private void markStableWinefile(boolean running) {
            stableWinefileRunning=running;
        }
    }

    private static final class Child {
        final Process process;
        final Thread reader;
        private final WineDesktopLogCapture capture=new WineDesktopLogCapture();
        // Capture Wine-specific font init result directly as the child emits it.
        // Ring-buffer tails otherwise overwrite the first FreeType messages.
        private volatile boolean ftVersionObserved;
        private volatile boolean patchedWineClientLoaded;
        private volatile boolean optInEnvObserved;
        private volatile boolean win32uRequestObserved;
        private volatile boolean patchedWineClientFailed;
        private volatile boolean ftLibraryNotFound;
        private volatile boolean ftInitFailed;
        private volatile boolean fontconfigAbsent;
        private volatile boolean fontconfigSignedLoaded;
        private volatile boolean fontconfigSignedFailed;
        private volatile boolean ftSymbolsMissing;
        Child(ProcessBuilder builder,String name) throws IOException {
            builder.redirectErrorStream(true);
            process=builder.start();
            reader=new Thread(()->{
                try(InputStream in=process.getInputStream()) {
                    byte[] block=new byte[4096];
                    int n;
                    String prior="";
                    while((n=in.read(block))!=-1) {
                        capture.append(block,0,n);
                        String window=prior+new String(block,0,n,StandardCharsets.UTF_8);
                        if(window.contains("FreeType version is "))
                            ftVersionObserved=true;
                        if(window.contains("RM11_V407_OPT_IN_FONTCLIENT_PROCESS_ENV_OBSERVED"))
                            optInEnvObserved=true;
                        if(window.contains("RM11_V407_FONTCLIENT_WIN32U_DLOPEN_REQUEST_REACHED_INTERPOSER"))
                            win32uRequestObserved=true;
                        if(window.contains("RM11_V406_PATCHED_WIN32U_WINEFILE_DLOPEN_SUCCEEDED"))
                            patchedWineClientLoaded=true;
                        if(window.contains("RM11_V406_PATCHED_WIN32U_WINEFILE_DLOPEN_FAILED"))
                            patchedWineClientFailed=true;
                        if(window.contains("Wine cannot find the FreeType font library"))
                            ftLibraryNotFound=true;
                        if(window.contains("Can't init FreeType library"))
                            ftInitFailed=true;
                        if(window.contains("Wine cannot find the fontconfig library"))
                            fontconfigAbsent=true;
                        if(window.contains("RM11_V409_FONTCONFIG_NATIVE_DLOPEN_SUCCESS"))
                            fontconfigSignedLoaded=true;
                        if(window.contains("RM11_V409_FONTCONFIG_NATIVE_DLOPEN_FAILED"))
                            fontconfigSignedFailed=true;
                        if(window.contains("Wine cannot find certain functions") &&
                           window.contains("FreeType"))
                            ftSymbolsMissing=true;
                        prior=window.length()>350 ?
                                window.substring(window.length()-350):window;
                    }
                } catch(IOException ignored) {
                    /* Explicit Activity shutdown may close this process. */
                }
            },"rm11-desktop-"+name);
            reader.setDaemon(true);
            reader.start();
        }
        String log() { return capture.snapshot(); }
        boolean fontMissing() {return ftLibraryNotFound;}
        boolean isolatedClientLoaded() {return patchedWineClientLoaded;}
        boolean isolatedClientFailed() {return patchedWineClientFailed;}
        boolean ftVersionObserved() {return ftVersionObserved;}
        String fontEvidence() {
            return "RM11_V407_OPT_IN_ENV_OBSERVED="+optInEnvObserved
                    +"\nRM11_V407_WIN32U_REQUEST_OBSERVED="+win32uRequestObserved
                    +"\nRM11_V406_PATCHED_CLIENT_LOADED="+patchedWineClientLoaded
                    +"\nRM11_V406_PATCHED_CLIENT_FAILED="+patchedWineClientFailed
                    +"\nRM11_V404_WINE_PROCESS_FT_VERSION_OBSERVED="+ftVersionObserved
                    +"\nRM11_V404_WINE_PROCESS_FT_LIBRARY_NOT_FOUND="+ftLibraryNotFound
                    +"\nRM11_V404_WINE_PROCESS_FT_INIT_FAILED="+ftInitFailed
                    +"\nRM11_V404_WINE_PROCESS_FT_SYMBOLS_MISSING="+ftSymbolsMissing
                    +"\nRM11_V404_WINE_PROCESS_FONTCONFIG_MISSING="+fontconfigAbsent
                    +"\nRM11_V409_FONTCONFIG_NATIVE_LOADED="+fontconfigSignedLoaded
                    +"\nRM11_V409_FONTCONFIG_NATIVE_FAILED="+fontconfigSignedFailed
                    +"\nRM11_V404_GDI_GLYPHS_VISIBLE_ON_DEVICE=UNVERIFIED";
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
            // v3.1.5: prevent Wine GUI clients from racing a server that
            // exits immediately. This does NOT claim full Wine IPC readiness;
            // it isolates early server termination from Explorer/X11 errors.
            Thread.sleep(750);
            if(session.isClosed()) {
                report.append("RM11_V315_START_ABORTED_BY_ACTIVITY_CLOSE\n");
                break;
            }
            if(!server.process.isAlive()) {
                int earlyExit=server.process.exitValue();
                report.append("RM11_V315_SERVER_EXITED_BEFORE_GUI: ")
                      .append(earlyExit).append('\n')
                      .append("RM11_V315_SERVER_EARLY_TAIL:\n")
                      .append(last(server.log(),3200)).append('\n');
                sink.update("خادم Wine توقف قبل بدء النوافذ؛ تم حفظ السبب في السجلات.");
                // Retry once without starting Explorer or Winefile on a dead
                // server. Preserve the first failure in both live/final logs.
                preservedFailure.append("RM11_V315_EARLY_SERVER_EXIT: ")
                        .append(earlyExit).append('\n')
                        .append(last(server.log(),1600)).append('\n');
                server.stop();
                server=null;
                if(attempt==0 && !session.isClosed()) {
                    report.append("RM11_V315_EARLY_SERVER_SINGLE_RETRY\n");
                    Thread.sleep(750);
                    continue;
                }
                report.append("RM11_V315_EARLY_SERVER_RETRY_EXHAUSTED\n");
                break;
            }
            report.append("RM11_V315_SERVER_SURVIVED_STARTUP_BARRIER\n");
            java.util.List<String> explorerCmd=
                    WineExecutionPlan.trustedEmbeddedExplorerCommand(layout,
                            screenWidth,screenHeight);
            explorer=new Child(command(explorerCmd,plan),"explorer");
            report.append("RM11_V303_WINE_EXPLORER_AUTOSTARTED\n");
            // v4.0.13: the real on-device screenshot shows Winefile's X11
            // frame and controls but no text. Previous device logs proved:
            // normal Winefile -> FT_LIBRARY_NOT_FOUND=true; the isolated
            // Winefile -> FreeType loaded but Fontconfig missing. v4.0.9
            // bundled an audited Fontconfig closure without using it in
            // the normal file-manager process. Enable that *scoped* closure
            // only for Winefile on the first attempt. Do not alter
            // wineserver, Explorer, games, or install a global libfreetype.
            boolean scopedFonts=attempt==0 && safeFontProof
                    && WineIsolatedFontClientPolicy.ready(layout)
                    && WineFontconfigBridge.ready(layout);
            Path scopedConfig=null;
            if(scopedFonts) {
                try {
                    scopedConfig=WineFontconfigBridge.prepare(layout);
                    report.append("RM11_V413_REAL_WINEFILE_FONTCONFIG_PREPARED\n");
                } catch(IOException e) {
                    scopedFonts=false;
                    report.append("RM11_V413_REAL_WINEFILE_FONTCONFIG_PREPARE_FAILED=")
                          .append(e.getClass().getSimpleName()).append('\n');
                }
            }
            report.append(WineIsolatedFontClientPolicy.diagnostic(layout))
                  .append("RM11_V413_REAL_WINEFILE_SCOPED_FONTS=")
                  .append(scopedFonts?"ENABLED_FIRST_PROCESS_ONLY":"BASELINE").append('\n')
                  .append("RM11_V413_WINESERVER_AND_EXPLORER_FONTS_UNMODIFIED\n");
            ProcessBuilder winefileBuilder=command(plan.wineCommand,plan);
            // The +font trace produced thousands of log lines in v4.0.8.
            // Capture explicit signed-library loader markers instead.
            winefileBuilder.environment().put("WINEDEBUG","+err,+warn");
            if(scopedFonts) {
                winefileBuilder.environment().put("RM11_WIN32U_ISOLATED_FONTCLIENT","1");
                winefileBuilder.environment().put("RM11_NATIVE_FONTCONFIG_DLOPEN_REDIRECT","1");
                winefileBuilder.environment().put("RM11_NATIVE_FREETYPE_DLOPEN_REDIRECT","0");
                winefileBuilder.environment().put("FONTCONFIG_FILE",scopedConfig.toString());
                winefileBuilder.environment().put("FONTCONFIG_PATH",scopedConfig.getParent().toString());
                winefileBuilder.environment().put("XDG_CACHE_HOME",
                        scopedConfig.getParent().resolve("cache").toString());
            }
            fileManager=new Child(winefileBuilder,"winefile");
            session.markStableWinefile(!scopedFonts);
            long winefileStartNanos=System.nanoTime();
            report.append("RM11_V303_WINEFILE_GRAPHICAL_MANAGER_AUTOSTARTED\n")
                  .append("RM11_V306_WINEFILE_FREETYPE_SCOPED_ATTEMPT: ")
                  .append(scopedFonts?"ENABLED":"DISABLED").append('\n')
                  .append("RM11_V306_WINE_SERVER_NATIVE_FONT_HOOK: DISABLED\n");
            sink.update(scopedFonts
                    ? "يجري فحص خطوط مدير الملفات بمعزل عن خادم Wine، مع رجوع تلقائي عند العطل."
                    : "واجهة Wine تعمل بالمكتبات المستقرة لحماية الخادم.");
            boolean fileReported=false, explorerReported=false, fontReported=false;
            boolean restartAfterServerDeath=false;
            boolean baselineWinefileRetryUsed=false;
            Child isolatedFontTest=null;
            long isolatedTestStartNanos=0;
            boolean isolatedTestCompletionLogged=false;
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
                    if(fileManager.isolatedClientLoaded()) {
                        fontReported=true;
                        report.append("RM11_V406_PATCHED_WINEFILE_WIN32U_DLOPEN: SUCCESS\n");
                    } else if(fileManager.log().contains(
                            "RM11_V406_PATCHED_WIN32U_WINEFILE_DLOPEN_FAILED")) {
                        fontReported=true;
                        report.append("RM11_V406_PATCHED_WINEFILE_WIN32U_DLOPEN: FAILED\n");
                    }
                }
                // v4.0.7: only on explicit user action from Diagnostics.
                // The original working Winefile window is kept alive while a
                // SEPARATE signed Win32u client test runs in the same stable
                // wineserver. If it fails or times out, stop only the test
                // process; never restart explorer/wineserver just for fonts.
                if(isolatedFontTest==null && !session.isClosed() &&
                        server.process.isAlive() && fileManager.process.isAlive() &&
                        session.consumeFontTest()) {
                    if(!WineIsolatedFontClientPolicy.ready(layout) ||
                            !WineFontconfigBridge.ready(layout) || !safeFontProof) {
                        report.append("RM11_V407_USER_FONT_TEST_BLOCKED_NATIVE_NOT_READY\n");
                        sink.update("ملفات اختبار الخطوط غير جاهزة؛ سطح المكتب المستقر مستمر.");
                    } else {
                        ProcessBuilder testBuilder=command(plan.wineCommand,plan);
                        // The v4.0.8 full +font trace floods thousands of lines and
                        // increases CPU/memory during system-font enumeration.
                        // Use explicit signed loader markers instead.
                        testBuilder.environment().put("WINEDEBUG","+err,+warn");
                        testBuilder.environment().put("RM11_WIN32U_ISOLATED_FONTCLIENT","1");
                        testBuilder.environment().put("RM11_NATIVE_FREETYPE_DLOPEN_REDIRECT","0");
                        testBuilder.environment().put("RM11_NATIVE_FONTCONFIG_DLOPEN_REDIRECT","1");
                        try {
                            Path config=WineFontconfigBridge.prepare(layout);
                            testBuilder.environment().put("FONTCONFIG_FILE",config.toString());
                            testBuilder.environment().put("FONTCONFIG_PATH",config.getParent().toString());
                            testBuilder.environment().put("XDG_CACHE_HOME",config.getParent().resolve("cache").toString());
                            report.append("RM11_V409_FONTCONFIG_LIMITED_WINE_FONT_DIRS_READY\n");
                            report.append("RM11_V409_FONT_TRACE_FLOOD_DISABLED\n");
                        }catch(IOException configFailure) {
                            report.append("RM11_V409_FONTCONFIG_PREPARE_FAILED: ")
                                  .append(configFailure.getClass().getSimpleName()).append('\n');
                            sink.update("تعذر تجهيز خطوط Wine المحددة؛ بقيت الجلسة الأصلية.");
                            continue;
                        }
                        try {
                            isolatedFontTest=new Child(testBuilder,"font-test-only");
                            isolatedTestStartNanos=System.nanoTime();
                            report.append("RM11_V407_USER_REQUESTED_FONT_TEST_STARTED\n")
                                  .append("RM11_V407_WINESERVER_EXPLORER_AND_BASELINE_WINEFILE_PRESERVED\n");
                            sink.update("تم تشغيل فحص الخطوط المنفصل؛ نافذة مدير الملفات الأصلية باقية.");
                        }catch(IOException e) {
                            report.append("RM11_V407_USER_FONT_TEST_START_FAILED: ")
                                  .append(e.getClass().getSimpleName()).append('\n');
                            sink.update("لم يبدأ فحص الخطوط؛ مدير الملفات الأصلي باقٍ.");
                        }
                    }
                }
                if(isolatedFontTest!=null && !isolatedTestCompletionLogged) {
                    long aliveMs=TimeUnit.NANOSECONDS.toMillis(
                            System.nanoTime()-isolatedTestStartNanos);
                    boolean testStopped=!isolatedFontTest.process.isAlive();
                    boolean libraryMissing=isolatedFontTest.fontMissing();
                    boolean loaderFailed=isolatedFontTest.isolatedClientFailed();
                    if(testStopped || libraryMissing || loaderFailed || aliveMs>=12000) {
                        report.append("RM11_V407_USER_FONT_TEST_RESULT\n")
                              .append("test_lifetime_ms=").append(aliveMs).append('\n')
                              .append("winefile_extra_exited=").append(testStopped).append('\n')
                              .append(isolatedFontTest.fontEvidence()).append('\n')
                              .append("RM11_V407_BASELINE_SERVER_STILL_ALIVE=")
                              .append(server.process.isAlive()).append('\n')
                              .append("RM11_V407_BASELINE_WINEFILE_STILL_ALIVE=")
                              .append(fileManager.process.isAlive()).append('\n')
                              .append("RM11_V407_TEST_LAST_LINES:\n")
                              .append(last(isolatedFontTest.log(),1800)).append('\n');
                        preservedFailure.append("RM11_V407_USER_FONT_TEST_RECORD\n")
                                .append(isolatedFontTest.fontEvidence()).append('\n');
                        isolatedFontTest.stop();
                        isolatedTestCompletionLogged=true;
                        sink.update("انتهى اختبار الخطوط المنفصل؛ مدير الملفات الأصلي مستمر. احفظ ZIP.");
                    }
                }
                // An isolated Winefile font load failure must NEVER restart
                // healthy wineserver/Explorer. Roll back just the client
                // process and keep the same X11 window/session alive.
                if(scopedFonts && server.process.isAlive() &&
                        (fileManager.fontMissing() || fileManager.isolatedClientFailed()
                         || fileManager.fontconfigSignedFailed)) {
                    report.append("RM11_V413_SCOPED_FONT_PROCESS_ONLY_ROLLBACK\n")
                          .append(fileManager.fontEvidence()).append('\n');
                    preservedFailure.append("RM11_V413_SCOPED_WINEFILE_FONT_FAILURE\n")
                            .append(last(fileManager.log(),2100)).append('\n');
                    fileManager.stop();
                    scopedFonts=false;
                    fileManager=new Child(command(plan.wineCommand,plan),"winefile-original-font-rollback");
                    session.markStableWinefile(true);
                    winefileStartNanos=System.nanoTime();
                    fileReported=false;
                    baselineWinefileRetryUsed=true;
                    sink.update("تمت إعادة مدير الملفات وحده إلى المكتبات الأصلية؛ خادم Windows باقٍ.");
                    continue;
                }
                if(!fileReported && !fileManager.process.isAlive()) {
                    session.markStableWinefile(false);
                    fileReported=true;
                    int code=fileManager.process.exitValue();
                    long life=TimeUnit.NANOSECONDS.toMillis(
                            System.nanoTime()-winefileStartNanos);
                    report.append("RM11_V304_WINEFILE_EXIT_CODE: ")
                          .append(code).append('\n')
                          .append("RM11_V306_WINEFILE_LIFETIME_MS: ")
                          .append(life).append('\n');
                    if(scopedFonts && code!=0 && server.process.isAlive() &&
                            !session.isClosed()) {
                        report.append("RM11_V413_SCOPED_WINEFILE_EXIT_ROLLBACK_ONLY\n")
                              .append(fileManager.fontEvidence()).append('\n');
                        preservedFailure.append("RM11_V413_SCOPED_WINEFILE_EXIT=")
                                .append(code).append(" lifetime_ms=").append(life).append('\n')
                                .append(last(fileManager.log(),2400)).append('\n');
                        fileManager.stop();
                        scopedFonts=false;
                        fileManager=new Child(command(plan.wineCommand,plan),
                                "winefile-original-after-scoped-exit");
                        session.markStableWinefile(true);
                        winefileStartNanos=System.nanoTime();
                        fileReported=false;
                        baselineWinefileRetryUsed=true;
                        sink.update("مدير ملفات Wine رجع للنسخة الأصلية دون إعادة تشغيل Windows.");
                        continue;
                    }
                    // v4.0.7: if the stable (unmodified) Winefile alone
                    // exits, retry only Winefile ONE time in the SAME server.
                    // Do not kill Explorer or restart the graphical desktop.
                    if(!baselineWinefileRetryUsed && code!=0 &&
                            server.process.isAlive() && !session.isClosed()) {
                        baselineWinefileRetryUsed=true;
                        report.append("RM11_V407_STABLE_WINEFILE_ONLY_SINGLE_RETRY\n")
                              .append("RM11_V407_FIRST_BASELINE_WINEFILE_EXIT=")
                              .append(code).append('\n');
                        preservedFailure.append("RM11_V407_FIRST_BASELINE_WINEFILE_TAIL:\n")
                              .append(last(fileManager.log(),1800)).append('\n');
                        if(isolatedFontTest!=null && !isolatedTestCompletionLogged){
                            isolatedFontTest.stop();
                            isolatedTestCompletionLogged=true;
                        }
                        fileManager.stop();
                        fileManager=new Child(command(plan.wineCommand,plan),"winefile-stable-retry");
                        session.markStableWinefile(true);
                        winefileStartNanos=System.nanoTime();
                        fileReported=false;
                        sink.update("إعادة فتح مدير الملفات الأصلي مرة واحدة دون إعادة تشغيل Windows.");
                        continue;
                    }
                    report.append("RM11_V407_STABLE_WINEFILE_FINAL_FAILURE_NO_RESTART\n");
                    sink.update("خادم Wine يعمل لكن مدير الملفات خرج. تفاصيل Wine في التشخيص.");
                }
                StringBuilder live=new StringBuilder(report);
                if(preservedFailure.length()>0)live.append("\nRM11_V307_PRESERVED_FIRST_FAILURE_BEGIN\n")
                        .append(preservedFailure).append("RM11_V307_PRESERVED_FIRST_FAILURE_END\n");
                if(server!=null)live.append("\nLIVE WINESERVER:\n").append(last(server.log(),2400));
                if(explorer!=null)live.append("\nLIVE EXPLORER:\n").append(last(explorer.log(),2400));
                if(isolatedFontTest!=null) {
                    live.append("\nRM11_V407_USER_FONT_TEST_STATE\n")
                        .append(isolatedFontTest.fontEvidence())
                        .append("\nRM11_V407_TEST_OUTPUT_TAIL:\n")
                        .append(last(isolatedFontTest.log(),1800));
                }
                if(fileManager!=null) {
                    live.append("\nRM11_V413_REAL_WINEFILE_CURRENT_SCOPED_FONTS=")
                        .append(scopedFonts).append('\n')
                        .append(fileManager.fontEvidence());
                    live.append("\nLIVE WINEFILE:\n").append(last(fileManager.log(),2400));
                }
                session.updateDiagnostics(live.toString());
                Thread.sleep(850);
            }
            if(isolatedFontTest!=null)isolatedFontTest.stop();
            if(restartAfterServerDeath && !session.isClosed()) {
                if(scopedFonts) report.append(
                        "RM11_V406_PRIVATE_FONTCLIENT_DISABLED_ON_STABLE_RECOVERY\n");
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
            session.markStableWinefile(false);
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
                report.append(fileManager.fontEvidence()).append('\n');
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
