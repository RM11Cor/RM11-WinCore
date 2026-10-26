package com.rm11.autocore;

import android.content.Context;
import com.rm11.autocore.diagnostics.OfflineDiagnosticJournal;
import com.rm11.autocore.runtime.NativeDesktopVisualEvidence;
import com.rm11.autocore.runtime.PhoneDriveBridge;
import com.rm11.autocore.runtime.RuntimeAssessment;
import com.rm11.autocore.runtime.RuntimeLayout;
import com.rm11.autocore.runtime.WineExecutionPlan;
import com.rm11.autocore.runtime.WineGuiImportBridge;
import com.rm11.autocore.runtime.WineX11DriverBridge;
import com.rm11.autocore.runtime.WineFontFilesBridge;
import com.rm11.autocore.runtime.WineX11EndpointProbe;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * Real Wine SHELL mode: explorer.exe /desktop=shell,WxH.
 * Only a bounded, evidence-gated Winefile fallback; no imitation shell or window-size key
 * injection. The signed native Wine binaries and pre-existing private prefix
 * are retained. Child processes are session-owned and stopped on exit.
 * Mouse input is routed by Lorie Activity directly to the X11 framebuffer.
 */
public final class WineShellDesktopRunner {
    private WineShellDesktopRunner(){}

    private static final class Child {
        final Process process;
        final Thread reader;
        final StringBuffer buffer=new StringBuffer();
        Child(List<String> command,WineExecutionPlan plan,String name) throws IOException {
            ProcessBuilder builder=new ProcessBuilder(command);
            builder.directory(plan.workingDirectory.toFile());
            builder.environment().putAll(plan.environment);
            // Prevent the prior FreeType crash path in server and explorer.
            builder.environment().put("RM11_NATIVE_FREETYPE_DLOPEN_REDIRECT","0");
            builder.redirectErrorStream(true);
            process=builder.start();
            reader=new Thread(()->{
                try(InputStream in=process.getInputStream()){
                    byte[] bytes=new byte[2048];
                    int n;
                    while((n=in.read(bytes))>=0){
                        synchronized(buffer) {
                            buffer.append(new String(bytes,0,n,StandardCharsets.UTF_8));
                            if(buffer.length()>10000)buffer.delete(0,buffer.length()-7000);
                        }
                    }
                }catch(IOException ignored){}
            },"rm11-v451-"+name+"-log");
            reader.setDaemon(true);
            reader.start();
        }
        String tail(){
            synchronized(buffer){return buffer.toString();}
        }
        void stop(){
            if(process.isAlive()){
                process.destroy();
                try{
                    if(!process.waitFor(2,TimeUnit.SECONDS))process.destroyForcibly();
                }catch(InterruptedException interrupted){
                    Thread.currentThread().interrupt();
                    process.destroyForcibly();
                }
            }
            reader.interrupt();
        }
    }

    public static String run(Context context,WineAutoDesktopRunner.Session session,
                             WineAutoDesktopRunner.StatusSink sink,
                             int width,int height){
        StringBuilder report=new StringBuilder(2500);
        report.append("RM11_V451_REAL_WINE_SHELL_MODE=true\n")
                .append("RM11_V451_NO_NATIVE_FAKE_DESKTOP=true\n")
                .append("RM11_V454_WINEFILE_FALLBACK_ONLY=true\n")
                .append("RM11_V451_NATIVE_FREETYPE_EXPERIMENT_OFF=true\n")
                .append("RM11_V451_WINE_TEXT_RENDERING_UNVERIFIED=true\n");
        Child server=null;
        Child shell=null;
        Child fileManager=null;
        try{
            RuntimeLayout layout=new RuntimeLayout(context.getFilesDir().toPath(),
                    Path.of(context.getApplicationInfo().nativeLibraryDir));
            RuntimeAssessment.inspect(layout).requireReady();
            report.append("RM11_V451_PHONE_DRIVE=")
                    .append(PhoneDriveBridge.mountIfAuthorized(context,layout)).append('\n');
            WineX11EndpointProbe.Result display=WineX11EndpointProbe.probeEmbeddedDisplay2();
            if(!display.accepted)
                throw new IOException("RM11_V451_EMBEDDED_X11_UNAVAILABLE");
            report.append(display.reportForDisplay(WineX11EndpointProbe.EMBEDDED_DISPLAY));
            report.append(WineGuiImportBridge.prepare(layout));
            report.append(WineX11DriverBridge.prepare(layout));
            report.append(WineFontFilesBridge.prepare(layout));
            WineExecutionPlan plan=WineExecutionPlan.forEmbeddedGraphicalDesktop(layout);
            List<String> shellArgv=WineExecutionPlan.trustedEmbeddedShellDesktopCommand(
                    layout,width,height);
            report.append("RM11_V451_WINE_SHELL_COMMAND=")
                    .append(shellArgv.get(shellArgv.size()-1)).append('\n');
            if(session.isClosed())return report.append("CLOSED_BEFORE_SHELL\n").toString();
            sink.update("تشغيل خادم Wine الحقيقي...");
            server=new Child(plan.serverCommand,plan,"wineserver");
            Thread.sleep(950);
            if(!server.process.isAlive()){
                report.append("RM11_V451_WINESERVER_EXITED_EARLY=")
                      .append(server.process.exitValue()).append('\n');
                return report.toString();
            }
            if(session.isClosed())return report.append("CLOSED_BEFORE_EXPLORER\n").toString();
            sink.update("تشغيل سطح المكتب الحقيقي: Wine Explorer /desktop=shell");
            shell=new Child(shellArgv,plan,"explorer-shell");
            OfflineDiagnosticJournal.record(context,"v452-explorer-start",
                    "RM11_V452_EXPLORER_STARTED=true\n"
                    +"RM11_V452_NATIVE_WINE_CLIENT_ALIVE="+shell.process.isAlive()+"\n"
                    +"RM11_V452_NATIVE_WINESERVER_ALIVE="+server.process.isAlive());
            // Explorer can spawn a taskbar/window and exit successfully.
            // Keep Wine session alive as long as wineserver exists, rather than
            // using winefile.exe lifetime as a proxy for desktop readiness.
            boolean recordedWindow=false,reportedShellExit=false;
            boolean fileManagerAttempted=false,fileManagerExitLogged=false,windowReadyLogged=false;
            long lastLiveSample=0L;
            int consecutiveNoWindows=0;
            long shellStartedAt=android.os.SystemClock.elapsedRealtime();
            while(!session.isClosed()&&!Thread.currentThread().isInterrupted()){
                if(!server.process.isAlive()){
                    report.append("RM11_V451_WINESERVER_EXITED=")
                          .append(server.process.exitValue()).append('\n');
                    sink.update("خادم Wine توقف؛ تم حفظ تشخيص سطح المكتب.");
                    break;
                }
                if(!shell.process.isAlive()&&!reportedShellExit){
                    reportedShellExit=true;
                    int status=shell.process.exitValue();
                    report.append("RM11_V451_EXPLORER_LAUNCHER_EXIT=").append(status).append('\n');
                    OfflineDiagnosticJournal.record(context,"v452-explorer-exit",
                            "RM11_V452_EXPLORER_EXIT_CODE="+status+"\n"
                            +"RM11_V452_EXPLORER_STDERR_TAIL="+shell.tail());
                    if(status!=0){
                        report.append("RM11_V452_EXPLORER_NONZERO_EXIT=true\n");
                        sink.update("Explorer توقف؛ فحص نوافذ X11 ومحاولة إنقاذ محدودة.");
                        // A desktop helper failing is not grounds to kill a live
                        // wineserver. The fallback below is guarded by X11 evidence.
                    }
                    // Exit 0 may indicate explorer has created background
                    // Wine desktop windows. Do not collapse X11 or restart.
                }
                long now=android.os.SystemClock.elapsedRealtime();
                if(now-lastLiveSample>=3500L){
                    lastLiveSample=now;
                    String x11=NativeDesktopVisualEvidence.auditX11();
                    String live="RM11_V452_SHELL_ELAPSED_MS="+(now-shellStartedAt)
                            +"\nRM11_V452_EXPLORER_ALIVE="+shell.process.isAlive()
                            +"\nRM11_V452_WINESERVER_ALIVE="+server.process.isAlive()
                            +"\nRM11_V452_X11_STATUS:\n"+x11
                            +"\nRM11_V452_EXPLORER_TAIL:\n"+shell.tail();
                    OfflineDiagnosticJournal.record(context,"v452-live-shell",live);
                    if(!recordedWindow){
                        report.append("RM11_V452_INITIAL_X11:\n").append(x11).append('\n');
                        recordedWindow=true;
                    }
                    if(x11.contains("RM11_V410_X11_ROOT_WINDOW_QUERY_OK")
                            && x11.contains("x11_children_viewable=0\n")
                            && x11.contains("x11_attribute_errors=0\n"))
                        consecutiveNoWindows++;
                    else consecutiveNoWindows=0;
                    if(!windowReadyLogged
                            && x11.contains("RM11_V410_X11_ROOT_WINDOW_QUERY_OK")
                            && x11.matches("(?s).*x11_children_viewable=[1-9][0-9]*\\n.*")){
                        windowReadyLogged=true;
                        OfflineDiagnosticJournal.record(context,"v454-real-x11-window",
                                "RM11_V454_REAL_WINE_WINDOW_VIEWABLE=true\n"+x11);
                    }
                    if(WineShellStartupPolicy.shouldLaunchFileManager(
                            x11, now-shellStartedAt, consecutiveNoWindows,
                            fileManagerAttempted)) {
                        fileManagerAttempted=true;
                        // Winlator boots a dedicated Windows file manager alongside
                        // explorer. RM11 does not ship Winlator's wfm.exe, so use
                        // our already verified, bundled Wine ARM64EC winefile.exe
                        // only when explorer leaves the X11 desktop empty.
                        try {
                            java.nio.file.Path winefile=layout.wineDllRoot.resolve(
                                    "aarch64-windows/winefile.exe");
                            fileManager=new Child(java.util.Arrays.asList(
                                    plan.wineCommand.get(0),winefile.toString()),
                                    plan,"fallback-winefile");
                            report.append("RM11_V454_WINEFILE_FALLBACK_LAUNCHED=true\n");
                            OfflineDiagnosticJournal.record(context,
                                    "v454-winefile-fallback",
                                    "RM11_V454_WINEFILE_FALLBACK_LAUNCHED=true\n"+x11);
                            sink.update("بدء مدير ملفات Wine الأصلي لإنقاذ سطح المكتب الفارغ.");
                        } catch(Exception recoveryFailure) {
                            report.append("RM11_V454_WINEFILE_FALLBACK_ERROR=")
                                    .append(recoveryFailure).append('\n');
                            OfflineDiagnosticJournal.record(context,
                                    "v454-winefile-fallback",
                                    "RM11_V454_WINEFILE_FALLBACK_ERROR="+recoveryFailure);
                        }
                    }
                    if(fileManager!=null && !fileManager.process.isAlive()
                            && !fileManagerExitLogged) {
                        fileManagerExitLogged=true;
                        String log="RM11_V454_WINEFILE_FALLBACK_EXIT="
                                +fileManager.process.exitValue()
                                +"\nRM11_V454_WINEFILE_STDERR:\n"+fileManager.tail();
                        report.append(log).append('\n');
                        OfflineDiagnosticJournal.record(context,"v454-winefile-exit",log);
                    }
                    if(fileManagerAttempted && fileManagerExitLogged
                            && !shell.process.isAlive()
                            && consecutiveNoWindows>=3
                            && now-shellStartedAt>=30000L) {
                        report.append("RM11_V454_NO_USABLE_WINDOWS_AFTER_FALLBACK=true\n");
                        sink.update("فشل سطح Wine الحقيقي بعد محاولة الإنقاذ؛ تم حفظ التقرير.");
                        break;
                    }
                    // Winlator-style shell lifecycle: an empty X11 desktop is
                    // not evidence that Wine has died. On slow devices explorer
                    // may map its windows after the initial startup window.
                    // Keep the server/session alive and collect evidence rather
                    // than killing the only Wine desktop process on timeout.
                    if(consecutiveNoWindows==3 && now-shellStartedAt>=14000L){
                        report.append("RM11_V453_NO_X11_WINDOWS_AT_STARTUP=true\n");
                        OfflineDiagnosticJournal.record(context,"v453-shell-window-delay",
                                "RM11_V453_SHELL_ALIVE="+shell.process.isAlive()
                                +"\nRM11_V453_WINESERVER_ALIVE="+server.process.isAlive()
                                +"\nRM11_V453_X11_STATUS:\n"+x11);
                        sink.update("نوافذ Wine متأخرة؛ الجلسة مستمرة والتشخيص محفوظ.");
                    }
                }
                Thread.sleep(850);
            }
            if(session.isClosed())report.append("RM11_V451_USER_CLOSED_DESKTOP=true\n");
        }catch(InterruptedException ex){
            Thread.currentThread().interrupt();
            report.append("RM11_V451_SESSION_INTERRUPTED\n");
        }catch(Exception ex){
            report.append("RM11_V451_SHELL_START_FAILED=")
                  .append(ex.getClass().getSimpleName()).append(": ")
                  .append(ex.getMessage()).append('\n');
            sink.update("تعذر تشغيل سطح Wine الحقيقي؛ راجع التشخيص.");
        }finally{
            if(fileManager!=null){
                report.append("RM11_V454_WINEFILE_TAIL:\n")
                        .append(fileManager.tail()).append('\n');
                fileManager.stop();
            }
            if(shell!=null){
                report.append("RM11_V451_EXPLORER_TAIL:\n").append(shell.tail()).append('\n');
                shell.stop();
            }
            if(server!=null){
                report.append("RM11_V451_WINESERVER_TAIL:\n").append(server.tail()).append('\n');
                server.stop();
            }
            OfflineDiagnosticJournal.record(context,"v451-real-wine-shell",
                    report.substring(0,Math.min(report.length(),8000)));
        }
        return report.toString();
    }

    /**
     * v4.0.55: A separate user-requested GAME mode. Keep native X11/Lorie and
     * wineserver and only the nogui explorer driver bootstrap: no visible shell, taskbar or winefile.
     * The Android file manager stays the home screen. Existing Wine prefix,
     * selected game data and original signed native binaries are untouched.
     */
    public static String runDirectGame(Context context,
            WineAutoDesktopRunner.Session session,
            WineAutoDesktopRunner.StatusSink sink,int width,int height,
            java.nio.file.Path selectedExe,
            java.util.function.Supplier<String> relayHealth) {
        StringBuilder report=new StringBuilder(3500);
        report.append("RM11_V455_GAME_FIRST=true\n")
              .append("RM11_V455_VISIBLE_DESKTOP_SHELL_DISABLED=true\n")
              .append("RM11_V455_NO_WINEFILE_AUTOSTART=true\n");
        Child server=null;
        Child noguiBootstrap=null;
        Process game=null;
        java.util.concurrent.atomic.AtomicReference<String> gameLog=
                new java.util.concurrent.atomic.AtomicReference<>("GAME_OUTPUT_PENDING");
        final com.rm11.autocore.runtime.WineFirstExceptionEvidence firstSeh=
                new com.rm11.autocore.runtime.WineFirstExceptionEvidence();
        final com.rm11.autocore.runtime.WineAssertionEvidence wineAssertion=
                new com.rm11.autocore.runtime.WineAssertionEvidence();
        final com.rm11.autocore.runtime.GameExecutableMapSnapshot gameMaps=
                new com.rm11.autocore.runtime.GameExecutableMapSnapshot();
        try {
            RuntimeLayout layout=new RuntimeLayout(context.getFilesDir().toPath(),
                    java.nio.file.Path.of(context.getApplicationInfo().nativeLibraryDir));
            RuntimeAssessment.inspect(layout).requireReady();
            boolean phoneAuthorized=PhoneDriveBridge.authorized();
            com.rm11.autocore.runtime.NovaWineExeLauncher.Check gameCheck=
                    com.rm11.autocore.runtime.NovaWineExeLauncher.validate(
                            layout,selectedExe,phoneAuthorized);
            // Direct phone-file execution needs a real Wine D: drive mapping;
            // SAF permission alone cannot make a content URI executable.
            String mount=PhoneDriveBridge.mountIfAuthorized(context,layout);
            report.append("RM11_V455_PHONE_DRIVE=").append(mount).append('\n');
            java.nio.file.Path phoneRoot=android.os.Environment
                    .getExternalStorageDirectory().getCanonicalFile().toPath();
            if(gameCheck.path.startsWith(phoneRoot)
                    && !PhoneDriveBridge.status(context,layout)
                        .contains("RM11_V415_PHONE_DRIVE_VERIFIED_D_STORAGE"))
                throw new IOException("PHONE_D_DRIVE_NOT_READY");
            WineX11EndpointProbe.Result display=WineX11EndpointProbe.probeEmbeddedDisplay2();
            if(!display.accepted)
                throw new IOException("GAME_X11_UNAVAILABLE");
            report.append(display.reportForDisplay(WineX11EndpointProbe.EMBEDDED_DISPLAY));
            report.append(WineGuiImportBridge.prepare(layout));
            report.append(WineX11DriverBridge.prepare(layout));
            report.append(WineFontFilesBridge.prepare(layout));
            WineExecutionPlan plan=WineExecutionPlan.forEmbeddedGraphicalDesktop(layout);
            if(session.isClosed())return report.append("GAME_SESSION_CLOSED\n").toString();
            sink.update("تشغيل خادم Wine لوضع الألعاب...");
            server=new Child(plan.serverCommand,plan,"game-wineserver");
            Thread.sleep(950);
            if(!server.process.isAlive())
                throw new IOException("GAME_WINESERVER_EXITED_EARLY:"
                        +server.process.exitValue());
            if(session.isClosed())return report.append("GAME_CLOSED_BEFORE_LAUNCH\n").toString();
            // The actual Winlator shortcut launch uses Wine explorer
            // /desktop=nogui rather than /desktop=shell. Wine's win32u/X11
            // driver may require the desktop bootstrap, but nogui must never
            // display a Start menu, taskbar or file manager.
            java.util.List<String> trustedExplorer=
                    WineExecutionPlan.trustedEmbeddedExplorerCommand(layout,width,height);
            noguiBootstrap=new Child(java.util.Arrays.asList(
                    trustedExplorer.get(0),trustedExplorer.get(1),
                    "/desktop=nogui,"+width+"x"+height),plan,"game-nogui");
            report.append("RM11_V455_WINE_NOGUI_BOOTSTRAP_STARTED=true\n");
            OfflineDiagnosticJournal.record(context,"v455-game-nogui",
                    "RM11_V455_NOGUI_DESKTOP_DRIVER_BOOTSTRAP=true");
            Thread.sleep(650);
            if(session.isClosed())return report.append("GAME_CLOSED_AFTER_NOGUI\n").toString();
            sink.update("تشغيل لعبة Windows مباشرة بدون سطح مكتب");
            game=com.rm11.autocore.runtime.NovaWineExeLauncher.start(
                    context,gameCheck.path,phoneAuthorized);
            final Process observed=game;
            // Read-only procfs sampling runs independently of Wine pipe
            // draining. The syscall may be denied by Android SELinux, which
            // is reported explicitly and never blocks or fails the game.
            Thread gameMapsReader=new Thread(()->{
                for(int poll=0;poll<18 && observed.isAlive();poll++) {
                    if(poll<5 || poll%3==0)gameMaps.sample(observed.pid());
                    try {Thread.sleep(180);}
                    catch(InterruptedException stop) {
                        Thread.currentThread().interrupt();
                        return;
                    }
                }
            },"rm11-v463-native-exec-map");
            gameMapsReader.setDaemon(true);
            gameMapsReader.start();
            Thread gameReader=new Thread(()->{
                try(java.io.InputStream input=observed.getInputStream()) {
                    com.rm11.autocore.runtime.WineGameOutputTail.drain(input,
                            gameLog::set,chunk->{
                                firstSeh.accept(chunk);
                                wineAssertion.accept(chunk);
                            });
                    int exit=observed.waitFor();
                    gameLog.set("RM11_V457_GAME_EXIT="+exit+"\n"+gameLog.get());
                    OfflineDiagnosticJournal.record(context,"v457-game-exit",
                            gameLog.get());
                }catch(InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                }catch(IOException error) {
                    gameLog.set("RM11_V457_GAME_LOG_ERROR="+error.getClass().getSimpleName()
                            +": "+error.getMessage()+"\n"+gameLog.get());
                }
            },"rm11-v457-game-live-output");
            gameReader.setDaemon(true);
            gameReader.start();
            report.append("RM11_V455_GAME_PROCESS_CREATED=true\n")
                  .append("RM11_V455_GAME_EXE=").append(gameCheck.path).append('\n')
                  .append("RM11_V457_NOGUI_ALIVE_AT_GAME_START=")
                  .append(noguiBootstrap.process.isAlive()).append('\n')
                  .append("RM11_V457_NOGUI_BOOTSTRAP_TAIL=")
                  .append(noguiBootstrap.tail()).append('\n');
            OfflineDiagnosticJournal.record(context,"v455-game-start",
                    "RM11_V455_DESKTOP_NOT_LAUNCHED=true\n"
                    +"RM11_V455_DIRECT_EXE="+gameCheck.path);
            long begun=android.os.SystemClock.elapsedRealtime();
            long lastSample=0;
            boolean mappedWindow=false;
            boolean pendingNoticeSent=false;
            while(!session.isClosed() && !Thread.currentThread().isInterrupted()) {
                if(!server.process.isAlive()) {
                    report.append("RM11_V455_GAME_WINESERVER_EXITED=")
                            .append(server.process.exitValue()).append('\n');
                    break;
                }
                long elapsed=android.os.SystemClock.elapsedRealtime()-begun;
                if(elapsed-lastSample>=3500) {
                    lastSample=elapsed;
                    String x11=NativeDesktopVisualEvidence.auditX11();
                    boolean x11QueryOk=x11.contains("RM11_V410_X11_ROOT_WINDOW_QUERY_OK");
                    boolean x11QueryFailed=!x11QueryOk;
                    boolean visible=x11QueryOk && x11.matches(
                            "(?s).*x11_children_viewable=[1-9][0-9]*\\n.*");
                    String relayReport;
                    try {relayReport=relayHealth.get();}
                    catch(Exception auditFailure) {
                        relayReport="RM11_V458_RELAY_HEALTH_AUDIT_FAILED="
                                +auditFailure.getClass().getSimpleName();
                    }
                    if(visible) {
                        mappedWindow=true;
                        if(pendingNoticeSent) {
                            sink.update("RM11_V457_GAME_WINDOW_APPEARED");
                            pendingNoticeSent=false;
                        }
                    } else if(!mappedWindow && elapsed>=16000L && !pendingNoticeSent) {
                        pendingNoticeSent=true;
                        OfflineDiagnosticJournal.record(context,"v457-game-no-window",
                                "RM11_V457_NO_X11_WINDOW_AFTER_16S=true\n"
                                +"RM11_V458_X11_QUERY_FAILED="+x11QueryFailed+"\n"
                                +"RM11_V458_RELAY_HEALTH:\n"+relayReport+"\n"
                                +"RM11_V457_GAME_PROCESS_ALIVE="+game.isAlive()
                                +"\nRM11_V457_NOGUI_ALIVE="+noguiBootstrap.process.isAlive()
                                +"\nRM11_V457_NOGUI_LOG="+noguiBootstrap.tail()
                                +"\nRM11_V457_GAME_OUTPUT="+gameLog.get()
                                +"\n"+x11);
                        sink.update(x11QueryFailed
                                ?"RM11_V458_GAME_X11_CONNECTION_FAILED_16S"
                                :"RM11_V457_NO_GAME_WINDOW_16S");
                    }
                    OfflineDiagnosticJournal.record(context,"v455-game-live",
                            "RM11_V455_GAME_ELAPSED_MS="+elapsed
                            +"\nRM11_V455_GAME_LAUNCHER_ALIVE="+game.isAlive()
                            +"\nRM11_V455_WINESERVER_ALIVE="+server.process.isAlive()
                            +"\nRM11_V455_X11:\n"+x11
                            +"\nRM11_V458_RELAY_HEALTH:\n"+relayReport
                            +"\nRM11_V455_PROCESS_LOG:\n"+gameLog.get());
                    if(!game.isAlive()) {
                        // The output drain may still have a few bytes to read
                        // after process exit. Do not diagnose its final stderr
                        // before the background reader has completed.
                        gameReader.join(450);
                        int exitCode=game.exitValue();
                        String assertionDetail=wineAssertion.snapshot()
                                +"\n"+gameMaps.resolve(wineAssertion.pcHex());
                        OfflineDiagnosticJournal.record(context,"v463-wine-assertion",
                                "RM11_V463_GAME_EXIT="+exitCode+"\n"+assertionDetail);
                        String firstException=firstSeh.snapshot();
                        OfflineDiagnosticJournal.record(context,"v462-first-seh",
                                "RM11_V462_GAME_EXIT="+exitCode+"\n"+firstException);
                        String fingerprint=com.rm11.autocore.runtime.GameFailureFingerprint
                                .inspect(gameLog.get()+"\n"+firstException,relayReport);
                        report.append(fingerprint);
                        OfflineDiagnosticJournal.record(context,
                                "v459-game-failure-fingerprint",
                                "RM11_V459_GAME_EXIT="+exitCode+"\n"+fingerprint
                                +"\nRM11_V459_WINE_LAST_OUTPUT:\n"+gameLog.get());
                        if(exitCode!=0 && !mappedWindow) {
                            report.append("RM11_V455_GAME_NONZERO_EXIT=")
                                    .append(exitCode).append('\n');
                            break;
                        }
                        if(!mappedWindow && elapsed>=30000) {
                            report.append("RM11_V455_GAME_NO_VISIBLE_X11_WINDOW=true\n");
                            break;
                        }
                    }
                    if(!mappedWindow && elapsed>=30000 && elapsed<35000)
                        sink.update("ملف اللعبة اشتغل لكن لم تظهر نافذة بعد؛ افتح التشخيص.");
                }
                Thread.sleep(850);
            }
            if(session.isClosed())report.append("RM11_V455_USER_CLOSED_GAME=true\n");
        }catch(InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            report.append("RM11_V455_GAME_INTERRUPTED\n");
        }catch(Exception error) {
            report.append("RM11_V455_GAME_EXEC_ERROR=")
                    .append(error.getClass().getSimpleName()).append(": ")
                    .append(error.getMessage()).append('\n');
            sink.update("تعذر تشغيل EXE مباشرة؛ افتح التشخيص.");
        }finally {
            report.append("RM11_V462_GAME_SEH_FIRST_EVIDENCE:\n")
                    .append(firstSeh.snapshot()).append('\n');
            OfflineDiagnosticJournal.record(context,"v462-first-seh-final",
                    firstSeh.snapshot());
            OfflineDiagnosticJournal.record(context,"v463-assertion-final",
                    wineAssertion.snapshot()+"\n"+gameMaps.resolve(wineAssertion.pcHex()));
            report.append("RM11_V463_ASSERTION_DIAGNOSTIC_STORED=true\n");
            report.append("RM11_V455_GAME_LOG:\n").append(gameLog.get()).append('\n');
            if(game!=null && game.isAlive())game.destroy();
            if(noguiBootstrap!=null){
                report.append("RM11_V455_NOGUI_BOOTSTRAP_LOG:\n")
                        .append(noguiBootstrap.tail()).append('\n');
                noguiBootstrap.stop();
            }
            if(server!=null) {
                report.append("RM11_V455_WINESERVER_LOG:\n")
                        .append(server.tail()).append('\n');
                server.stop();
            }
            OfflineDiagnosticJournal.record(context,"v455-direct-game",
                    report.substring(0,Math.min(report.length(),8000)));
        }
        return report.toString();
    }

    /**
     * Dedicated x86-64 exception dispatcher regression. This is NOT a
     * Silksong launch and deliberately creates no desktop, DXVK or GL/Vulkan
     * context. The same signed Wine ARM64EC/FEX stack that games use executes
     * a separate signed Win64 PE which raises/catches one private exception.
     */
    public static String runFiberSehProbe(Context context,
            WineAutoDesktopRunner.Session session,
            WineAutoDesktopRunner.StatusSink sink) {
        return runSehProbe(context,session,sink,true);
    }

    public static String runSehProbe(Context context,
            WineAutoDesktopRunner.Session session,
            WineAutoDesktopRunner.StatusSink sink) {
        return runSehProbe(context,session,sink,false);
    }

    private static String runSehProbe(Context context,
            WineAutoDesktopRunner.Session session,
            WineAutoDesktopRunner.StatusSink sink,boolean fiber) {
        StringBuilder report=new StringBuilder();
        report.append("RM11_V461_PROBE_KIND=").append(fiber?"FIBER":"SIMPLE").append('\n');
        Child server=null;
        Process probe=null;
        java.util.concurrent.atomic.AtomicReference<String> output=
                new java.util.concurrent.atomic.AtomicReference<>("");
        try {
            RuntimeLayout layout=new RuntimeLayout(context.getFilesDir().toPath(),
                    Path.of(context.getApplicationInfo().nativeLibraryDir));
            RuntimeAssessment.inspect(layout).requireReady();
            Path exe=fiber?com.rm11.autocore.runtime.FiberSehProbeAsset.stage(context)
                    :com.rm11.autocore.runtime.SehProbeAsset.stage(context);
            boolean genuine=fiber
                    ?com.rm11.autocore.runtime.FiberSehProbeAsset.isAuthentic(context,exe)
                    :com.rm11.autocore.runtime.SehProbeAsset.isAuthentic(context,exe);
            if(!genuine)throw new IOException("RM11_V461_UNTRUSTED_DIAGNOSTIC_EXE");
            WineExecutionPlan plan=WineExecutionPlan.forEmbeddedGraphicalDesktop(layout);
            if(session.isClosed())return "RM11_V460_SESSION_CLOSED";
            sink.update("تشغيل اختبار معالجة استثناءات x64 الحقيقي...");
            server=new Child(plan.serverCommand,plan,"seh-server");
            Thread.sleep(750);
            if(!server.process.isAlive())
                throw new IOException("RM11_V460_WINESERVER_EXITED_EARLY");
            java.util.List<String> command=java.util.Arrays.asList(
                    plan.wineCommand.get(0),exe.toString());
            ProcessBuilder pb=new ProcessBuilder(command);
            pb.directory(layout.appFiles.toFile());
            pb.environment().putAll(plan.environment);
            pb.environment().put("WINEDEBUG","+err,+warn,+seh,+unwind");
            pb.environment().put("RM11_V458_ANDROID_VULKAN_FALLBACK","0");
            pb.environment().put("RM11_NATIVE_FREETYPE_DLOPEN_REDIRECT","0");
            pb.redirectErrorStream(true);
            probe=pb.start();
            final Process readProcess=probe;
            Thread drain=new Thread(()->{
                try(java.io.InputStream in=readProcess.getInputStream()) {
                    com.rm11.autocore.runtime.WineGameOutputTail.drain(in,output::set);
                }catch(IOException e){
                    output.set(com.rm11.autocore.runtime.WineGameOutputTail.append(
                            output.get(),"\nRM11_V460_READ_ERROR="+e));
                }
            },"rm11-v460-seh-drain");
            drain.setDaemon(true);
            drain.start();
            report.append("RM11_V460_SIGNED_SEH_PE_LAUNCHED=true\n");
            boolean finished=probe.waitFor(24000,TimeUnit.MILLISECONDS);
            if(!finished){
                report.append("RM11_V460_SEH_TIMEOUT=true\n");
                probe.destroy();
                probe.waitFor(1500,TimeUnit.MILLISECONDS);
                if(probe.isAlive())probe.destroyForcibly();
            }
            drain.join(600);
            String log=output.get();
            int exit=finished?probe.exitValue():-1;
            boolean pass=fiber
                    ?com.rm11.autocore.runtime.FiberSehProbeVerdict
                        .passed(finished,exit,log)
                    :com.rm11.autocore.runtime.SehProbeVerdict
                        .passed(finished,exit,log);
            report.append("RM11_V460_SEH_PROBE_EXIT=").append(exit).append('\n')
                  .append("RM11_V460_SEH_PASS=").append(pass).append('\n')
                  .append("RM11_V460_SEH_FAILURE_IS_GAME_SPECIFIC=UNDETERMINED\n")
                  .append("RM11_V460_RUNTIME_SEH_TRACE:\n").append(log).append('\n');
            if(fiber){
                report.append("RM11_V461_FIBER_SEH_PASS=").append(pass).append('\n');
            }
            sink.update(pass?"RM11_V460_SEH_TEST_PASSED":"RM11_V460_SEH_TEST_FAILED");
        }catch(InterruptedException interrupted){
            Thread.currentThread().interrupt();
            report.append("RM11_V460_INTERRUPTED=true\n");
        }catch(Exception failure){
            report.append("RM11_V460_SEH_PROBE_LAUNCH_ERROR=")
                    .append(failure.getClass().getSimpleName())
                    .append(": ").append(failure.getMessage()).append('\n');
        }finally{
            if(probe!=null&&probe.isAlive())probe.destroyForcibly();
            if(server!=null)server.stop();
            OfflineDiagnosticJournal.record(context,fiber?"v461-fiber-probe":"v460-seh-probe",
                    report.substring(0,Math.min(10700,report.length())));
        }
        return report.toString();
    }
}
