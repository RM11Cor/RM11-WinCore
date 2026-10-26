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
 * Winlator-style real shell + native Wine file manager; no Android imitation shell.
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
                .append("RM11_V453_WINEFILE_AUTOSTART=true\n")
                .append("RM11_V451_NATIVE_FREETYPE_EXPERIMENT_OFF=true\n")
                .append("RM11_V451_WINE_TEXT_RENDERING_UNVERIFIED=true\n");
        Child server=null;
        Child shell=null;
        Child computer=null;
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
            String menu=WineShellMenuBootstrap.stage(layout);
            report.append(menu).append('\n');
            OfflineDiagnosticJournal.record(context,"v453-shell-menu",menu);
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
            // Winlator's process model runs a guest file manager alongside
            // explorer /desktop=shell. Signed Winefile uses the same prefix,
            // DISPLAY, loader, X server and wineserver as the shell.
            try {
                Thread.sleep(650);
                if(!session.isClosed()) {
                    computer=new Child(plan.wineCommand,plan,"winefile-computer");
                    report.append("RM11_V453_WINEFILE_STARTED=true\n");
                    OfflineDiagnosticJournal.record(context,"v453-winefile-start",
                        "RM11_V453_WINEFILE_ALIVE="+computer.process.isAlive());
                }
            }catch(IOException fileError) {
                report.append("RM11_V453_WINEFILE_START_FAILED=")
                    .append(fileError.getMessage()).append('\n');
            }
            OfflineDiagnosticJournal.record(context,"v452-explorer-start",
                    "RM11_V452_EXPLORER_STARTED=true\n"
                    +"RM11_V452_NATIVE_WINE_CLIENT_ALIVE="+shell.process.isAlive()+"\n"
                    +"RM11_V452_NATIVE_WINESERVER_ALIVE="+server.process.isAlive());
            // Explorer can spawn a taskbar/window and exit successfully.
            // Keep Wine session alive as long as wineserver exists, rather than
            // using winefile.exe lifetime as a proxy for desktop readiness.
            boolean recordedWindow=false,reportedShellExit=false,desktopReady=false;
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
                        sink.update("فشل تشغيل Explorer؛ تم تسجيل السبب بدلاً من إبقاء الشاشة فارغة.");
                        break;
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
                    if(x11.contains("x11_children_viewable=0")) {
                        consecutiveNoWindows++;
                    } else {
                        consecutiveNoWindows=0;
                        if(!desktopReady
                                && x11.matches("(?s).*x11_children_viewable=[1-9][0-9]*.*")) {
                            desktopReady=true;
                            session.markRealDesktopReady(true);
                            OfflineDiagnosticJournal.record(context,"v453-desktop-ready",
                                "RM11_V453_REAL_X11_WINDOW_VISIBLE=true\n"
                                +"RM11_V453_GUEST_EXE_ALLOWED=true");
                        }
                    }
                    if(consecutiveNoWindows>=3 && now-shellStartedAt>=14000){
                        report.append("RM11_V452_NO_X11_VIEWABLE_WINDOWS_AFTER_START=true\n");
                        sink.update("تعذر ظهور نوافذ Wine. راجع التقرير بدل شاشة فارغة.");
                        break;
                    }
                }
                Thread.sleep(850);
            }
            if(session.isClosed())report.append("RM11_V451_USER_CLOSED_DESKTOP=true\n");
            session.markRealDesktopReady(false);
        }catch(InterruptedException ex){
            Thread.currentThread().interrupt();
            report.append("RM11_V451_SESSION_INTERRUPTED\n");
        }catch(Exception ex){
            report.append("RM11_V451_SHELL_START_FAILED=")
                  .append(ex.getClass().getSimpleName()).append(": ")
                  .append(ex.getMessage()).append('\n');
            sink.update("تعذر تشغيل سطح Wine الحقيقي؛ راجع التشخيص.");
        }finally{
            session.markRealDesktopReady(false);
            if(computer!=null){
                report.append("RM11_V453_WINEFILE_TAIL:\n")
                    .append(computer.tail()).append('\n');
                computer.stop();
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
}
