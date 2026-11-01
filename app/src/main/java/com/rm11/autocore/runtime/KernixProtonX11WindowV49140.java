package com.rm11.autocore.runtime;

import android.content.Context;
import android.os.Build;
import android.os.PowerManager;
import com.rm11.autocore.diagnostics.OfflineDiagnosticJournal;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.util.Locale;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import org.json.JSONObject;

/**
 * Explicit, bounded Win64 GDI HWND through the signed Proton+FEX loader and
 * the live app-private X11 TCP relay. Never run on library opening.
 * No legacy Wine, DirectX, Vulkan, user executables or shared game prefixes.
 */
public final class KernixProtonX11WindowV49140 {
    private KernixProtonX11WindowV49140() {}
    private static final String PE_ASSET="runtime/kernix-p11-x11-gdi.exe";
    private static final String MANIFEST="runtime/kernix-p11-x11-gdi.json";
    private static final String SCHEMA="kernix.p11.x11.gdi.v49140";
    private static final int MAX_PE=4*1024*1024;

    static String fileName(String sha){
        if(sha==null||!sha.matches("[0-9a-f]{64}"))
            throw new IllegalArgumentException("P11_X11_SHA_INVALID");
        return "kernix-x11-gdi-"+sha.substring(0,24)+".exe";
    }
    static String command(String sha){
        return "C:\\kernix-probes\\"+fileName(sha);
    }
    private static String sha256(byte[] bytes)throws Exception{
        byte[] digest=MessageDigest.getInstance("SHA-256").digest(bytes);
        StringBuilder out=new StringBuilder(64);
        for(byte b:digest)out.append(String.format(Locale.ROOT,"%02x",b&255));
        return out.toString();
    }
    private static boolean thermalBlocked(Context ctx){
        if(Build.VERSION.SDK_INT<29)return false;
        PowerManager p=(PowerManager)ctx.getSystemService(Context.POWER_SERVICE);
        return p!=null&&p.getCurrentThermalStatus()>=PowerManager.THERMAL_STATUS_SEVERE;
    }
    private static String boundedLog(Path path){
        if(path==null)return "NO_LOG";
        try(java.io.RandomAccessFile log=
                new java.io.RandomAccessFile(path.toFile(),"r")){
            long size=log.length();
            int firstSize=(int)Math.min(size,10000L);
            byte[] first=new byte[firstSize];
            log.readFully(first);
            if(size<=firstSize)return new String(first,StandardCharsets.UTF_8);
            int lastSize=(int)Math.min(size-firstSize,10000L);
            byte[] last=new byte[lastSize];
            log.seek(size-lastSize);
            log.readFully(last);
            return new String(first,StandardCharsets.UTF_8)
                +"\n[OMITTED_MIDDLE]\n"
                +new String(last,StandardCharsets.UTF_8);
        }catch(IOException ignored){return "LOG_UNAVAILABLE";}
    }
    /** This isolated GDI qualification is not a game, and must not inherit
     * experimental ntsync/esync/fsync settings from another container.
     * Apply the same conservative policy to the private WineServer and client. */
    static void disableExperimentalSync(java.util.Map<String,String> env){
        env.put("PROTON_NO_NTSYNC","1");
        env.put("WINENTSYNC","0");
        env.put("WINEESYNC","0");
        env.put("WINEFSYNC","0");
        env.remove("NTSYNC_SHM");
        env.remove("PROTON_NO_KERNEL_NTSYNC");
    }
    // RC319 produced >4 MiB of +process/+loaddll/+module trace in about 3 s.
    // That was our own diagnostic verbosity, NOT an observed server crash.
    // The Wine grammar is class+channel: err+all/warn+all, never +err/+warn.
// Keep only genuine errors/warnings and the probe's flushed stdout
    // stage markers; do not modify Wine debug defaults for ordinary games.
    // RC323 remained trapped in millions of repeated warn:font messages.
    // Preserve errors, omit all warnings for this single isolated GDI probe.
    // Fatal server queue markers are always recorded separately below.
    static final String GDI_DIAGNOSTIC_WINEDEBUG="-all,err+all";
    static void quietGuiGuestLog(java.util.Map<String,String> env){
        if(env==null)throw new IllegalArgumentException("P11_GUI_ENV_MISSING");
        env.put("WINEDEBUG",GDI_DIAGNOSTIC_WINEDEBUG);
    }
    static String guiGuestLogVerdict(boolean serverAlive,
            boolean stageReached,long logBytes,boolean abort){
        if(!serverAlive)return "SERVER_EXIT_DURING_GUEST";
        if(abort)return "GUEST_LOG_LIMIT_"+logBytes;
        return stageReached?"GDI_MAIN_REACHED":"WINDOWS_BOOTSTRAP_BEFORE_GDI_MAIN";
    }
    /** Inspect the actual file, not its 10 KB head/tail summary.
     * Queue failures can occur in the omitted middle of an IPC-heavy log.
     * Scans a bounded 32 MiB and never returns a false 'marker absent'
     * claim when the source is inaccessible or longer than that bound.
     */
    static String serverMarkerState(Path path,String marker){
        if(path==null||marker==null||marker.length()<5||marker.length()>128
            ||!marker.matches("[A-Z0-9_]+"))return "UNAVAILABLE";
        try{
            if(Files.isSymbolicLink(path)||!Files.isRegularFile(path,LinkOption.NOFOLLOW_LINKS))
                return "UNAVAILABLE";
            if(Files.size(path)>32L*1024*1024)return "OVERSIZED_UNKNOWN";
            byte[] wanted=marker.getBytes(StandardCharsets.US_ASCII);
            try(InputStream in=Files.newInputStream(path)){
                byte[] buf=new byte[16384];
                int matched=0,n;
                while((n=in.read(buf))!=-1){
                    for(int i=0;i<n;i++){
                        byte c=buf[i];
                        if(c==wanted[matched]){
                            if(++matched==wanted.length)return "PRESENT";
                        }else matched=c==wanted[0]?1:0;
                    }
                }
            }
            return "ABSENT_IN_COMPLETE_LOG";
        }catch(IOException ignored){return "UNAVAILABLE";}
    }
    static boolean serverCrashed(String log){
        return log!=null && log.contains("wineserver crashed");
    }
    static String gdiStage(String log){
        if(log==null || log.isEmpty()) return "NO_GUEST_OUTPUT";
        for(String stage:new String[]{
             "P11_GDI_STAGE_FINAL_COLORS",
             "P11_GDI_STAGE_WINDOW_DESTROY",
             "P11_GDI_STAGE_CYAN_PAINT",
             "P11_GDI_STAGE_MAGENTA_PAINT",
             "P11_GDI_STAGE_CREATE_SUCCESS",
             "P11_GDI_STAGE_CREATE_ENTER",
             "P11_GDI_STAGE_REGISTER_SUCCESS",
             "P11_GDI_STAGE_REGISTER_ENTER",
             "P11_GDI_STAGE_MAIN_ENTER"})
            if(log.contains(stage))return stage;
        return "WIN64_GDI_MAIN_NOT_REACHED";
    }
    private static final String GUI_INIT_RECEIPT="KERNIX_P11_GUI_PREFIX_INIT_OK";
    static boolean acceptedGuiInit(int exit,boolean serverAlive){
        return exit==0&&serverAlive;
    }
    private static boolean guiPrefixReady(Path receipt)throws IOException{
        if(Files.isSymbolicLink(receipt))
            throw new IOException("P11_GUI_INIT_RECEIPT_SYMLINK");
        if(!Files.exists(receipt,LinkOption.NOFOLLOW_LINKS))return false;
        if(!Files.isRegularFile(receipt,LinkOption.NOFOLLOW_LINKS)
            ||Files.size(receipt)>80)
            throw new IOException("P11_GUI_INIT_RECEIPT_UNTRUSTED");
        if(!GUI_INIT_RECEIPT.equals(new String(Files.readAllBytes(receipt),StandardCharsets.UTF_8).trim()))
            throw new IOException("P11_GUI_INIT_RECEIPT_MISMATCH");
        return true;
    }
    private static String safeLogSummary(Path log,int limit){
        String safe=boundedLog(log).replaceAll("[^A-Za-z0-9. _()+:=-]"," ")
            .replaceAll("\\s+"," ").trim();
        if(safe.length()<=limit)return safe;
        // WineServer fatal lines are commonly at the end: preserve both.
        int head=Math.max(1,(limit-16)/2);
        int tail=Math.max(1,limit-16-head);
        return safe.substring(0,head)+" [TAIL_EVIDENCE] "
            +safe.substring(safe.length()-tail);
    }
    static boolean guestPass(int exit,String log){
        return exit==48&&log!=null
            &&log.contains("KERNIX_P11_X11_GDI_WINDOW_CREATED")
            &&log.contains("KERNIX_P11_X11_GDI_MAGENTA_PAINTED")
            &&log.contains("KERNIX_P11_X11_GDI_CYAN_PAINTED")
            &&log.contains("KERNIX_P11_X11_GDI_BOTH_COLORS=1");
    }
    static boolean completeWindowEvidence(boolean guestPass,
            boolean viewable,boolean magenta,boolean cyan){
        return guestPass&&viewable&&magenta&&cyan;
    }
    /** Only a currently qualified signed Win64 guest may start the GUI probe. */
    public static String run(Context ctx,Runnable guestStarted,
                             AtomicBoolean magentaAndroidPixels,
                             AtomicBoolean cyanAndroidPixels){
        Process guest=null,server=null,guiInit=null;
        Path guestLog=null,serverLog=null,guiInitLog=null;
        KernixProtonNativeQualificationV49123.Plan plan=null;
        String outcome="BLOCKED_NOT_STARTED";
        boolean viewable=false,guestOk=false;
        String x11="X11_NOT_QUERIED";
        String serverStage="NOT_STARTED";
        String serverEnd="NOT_OBSERVED";
        String guiInitStage="NOT_STARTED";
        try{
            if(ctx==null||magentaAndroidPixels==null||cyanAndroidPixels==null)
                throw new IOException("NO_CONTEXT");
            if(thermalBlocked(ctx))return "BLOCKED_THERMAL_SEVERE";
            JSONObject proof=KernixProtonProvisioningV49129.snapshot(ctx);
            if(!proof.optBoolean("nativeWin64GuestQualified",false)
                ||!proof.optBoolean("separateWritablePrefix",false))
                throw new IOException("P11_X64_PROOF_REQUIRED");
            if(!KernixProtonFexInstallerV49121.staged(ctx))
                throw new IOException("P11_SIGNED_SLOT_MISSING");
            Path app=ctx.getFilesDir().toPath();
            Path writable=KernixProtonPrefixV49126.writableRoot(app);
            plan=KernixProtonNativeQualificationV49123.buildPlan(app,
                Path.of(ctx.getApplicationInfo().nativeLibraryDir))
                    .withWritablePrefix(writable);
            try(InputStream input=ctx.getAssets().open(PE_ASSET)){
                byte[] exe=input.readNBytes(MAX_PE+1);
                if(exe.length<=4096||exe.length>MAX_PE
                    ||!KernixProtonFexSmokeV49127.isWin64Pe(exe))
                    throw new IOException("SIGNED_X11_PE_INVALID");
                JSONObject meta;
                try(InputStream m=ctx.getAssets().open(MANIFEST)){
                    meta=new JSONObject(new String(m.readNBytes(8192),
                        StandardCharsets.UTF_8));
                }
                String digest=sha256(exe);
                if(!SCHEMA.equals(meta.optString("schema"))
                    ||meta.optInt("bytes",-1)!=exe.length
                    ||!digest.equals(meta.optString("sha256"))
                    ||meta.optInt("expected_exit",-1)!=48)
                    throw new IOException("SIGNED_X11_PE_ATTESTATION_FAILED");
                Path dir=writable.resolve("drive_c/kernix-probes");
                if(Files.isSymbolicLink(dir))
                    throw new IOException("X11_STAGE_DIR_SYMLINK");
                Files.createDirectories(dir);
                Path staged=dir.resolve(fileName(digest));
                if(Files.isSymbolicLink(staged))
                    throw new IOException("X11_STAGE_FILE_SYMLINK");
                if(!Files.exists(staged,LinkOption.NOFOLLOW_LINKS))
                    Files.write(staged,exe,StandardOpenOption.CREATE_NEW);
                else if(Files.size(staged)!=exe.length
                    ||!digest.equals(sha256(Files.readAllBytes(staged))))
                    throw new IOException("X11_EXISTING_PE_SHA_MISMATCH");
                guestLog=ctx.getCacheDir().toPath().resolve("p11-x11-gdi-guest.txt");
                serverLog=ctx.getCacheDir().toPath().resolve("p11-x11-gdi-server.txt");
                if(Files.isSymbolicLink(guestLog)||Files.isSymbolicLink(serverLog))
                    throw new IOException("X11_LOG_SYMLINK");
                // A warm --restart is not the same as initializing a prefix.
                // The copied Proton template may otherwise auto-spawn
                // wineboot --init inside the first GUI launch, obscuring
                // the actual GDI failure behind a black screen.
                Path identity=KernixProtonNativeQualificationV49123.localMachineId(ctx);
                Path guiReceipt=writable.resolve(".kernix-p11-gui-init-v49144");
                guiInitLog=ctx.getCacheDir().toPath().resolve("p11-gui-prefix-init.txt");
                if(Files.isSymbolicLink(guiInitLog))
                    throw new IOException("P11_GUI_INIT_LOG_SYMLINK");
                Files.deleteIfExists(guestLog);
                Files.deleteIfExists(serverLog);
                Files.deleteIfExists(guiInitLog);
                OfflineDiagnosticJournal.record(ctx,"v49144-p11-gui-checkpoint",
                    "P11_GUI_PHASE=START_PREFIX_AND_SERVER\n"
                    +"P11_GUI_PREVIOUS_INIT_CERTIFIED="+guiPrefixReady(guiReceipt));
                ProcessBuilder serverPb=plan.prefixServerWithIdentity(serverLog,identity);
                // The signed GDI qualification can take several seconds to
                // start FEX. Avoid a 3-second idle WineServer expiration.
                // -d1 records every WineServer request and hides our targeted
                // queue markers among megabytes of IPC. -d0 keeps explicit
                // WineServer fprintf errors and guard marker output.
                serverPb.command(plan.server.toString(),"-f","-p35","-d0");
                disableExperimentalSync(serverPb.environment());
                server=serverPb.start();
                Thread.sleep(350);
                serverStage=server.isAlive()?"ALIVE":"EXIT_"+server.exitValue();
                if(!server.isAlive()){
                    OfflineDiagnosticJournal.record(ctx,"v49144-p11-gui-checkpoint",
                        "P11_GUI_PHASE=SERVER_STARTUP_EARLY_EXIT\n"
                        +"P11_GUI_SERVER_EXIT="+server.exitValue()+"\n"
                        +"P11_GUI_SERVER_LOG="+safeLogSummary(serverLog,2500));
                    throw new IOException("PRIVATE_WINESERVER_DIED_BEFORE_GUEST");
                }
                if(!guiPrefixReady(guiReceipt)){
                    guiInitStage="RUNNING_BOUNDED_FIRST_GUI_INIT";
                    OfflineDiagnosticJournal.record(ctx,"v49144-p11-gui-checkpoint",
                        "P11_GUI_PHASE=PREFIX_INIT_STARTED_EXPLICIT\n"
                        +"P11_GUI_PREFIX_MODE=APP_PRIVATE_ONLY_NO_GAME_FILES");
                    ProcessBuilder initPb=plan.prefixBootCommand(guiInitLog);
                    initPb.command(plan.loader.toString(),
                        "C:\\windows\\system32\\wineboot.exe","--init");
                    initPb.environment().put("RM11_P11_MACHINE_ID_FILE",
                        identity.toString());
                    initPb.environment().put("WINEDEBUG","+err,+warn");
                    disableExperimentalSync(initPb.environment());
                    initPb.environment().remove("DISPLAY");
                    guiInit=initPb.start();
                    boolean completed=false;
                    for(int tick=0;tick<18;tick+=2){
                        if(guiInit.waitFor(2,TimeUnit.SECONDS)){
                            completed=true;break;
                        }
                        if(!server.isAlive()){
                            guiInitStage="BLOCKED_SERVER_EXIT_DURING_PREFIX_INIT";
                            OfflineDiagnosticJournal.record(ctx,
                                "v49144-p11-gui-checkpoint",
                                "P11_GUI_PHASE=PRIVATE_SERVER_DIED_DURING_INIT\n"
                                +"P11_GUI_SERVER_EXIT="+server.exitValue()+"\n"
                                +"P11_GUI_SERVER_LOG="+safeLogSummary(serverLog,2500));
                            throw new IOException(guiInitStage);
                        }
                        if(thermalBlocked(ctx)){
                            guiInitStage="ABORTED_THERMAL_SEVERE";
                            throw new IOException(guiInitStage);
                        }
                    }
                    if(!completed){
                        guiInitStage="BLOCKED_PREFIX_INIT_TIMEOUT_18S";
                        throw new IOException(guiInitStage);
                    }
                    int initExit=guiInit.exitValue();
                    if(!acceptedGuiInit(initExit,server.isAlive())){
                        guiInitStage="BLOCKED_PREFIX_INIT_EXIT_"+initExit;
                        throw new IOException(guiInitStage);
                    }
                    Files.write(guiReceipt,(GUI_INIT_RECEIPT+"\n").getBytes(StandardCharsets.UTF_8),
                        StandardOpenOption.CREATE_NEW);
                    guiInitStage="COMPLETE_PRIVATE_PREFIX_INIT";
                    OfflineDiagnosticJournal.record(ctx,"v49144-p11-gui-checkpoint",
                        "P11_GUI_PHASE=PRIVATE_PREFIX_INIT_SUCCEEDED");
                }else guiInitStage="PREVIOUS_PRIVATE_PREFIX_INIT_CERTIFIED";
                ProcessBuilder pb=plan.prefixBootCommand(guestLog);
                pb.command(plan.loader.toString(),command(digest));
                pb.directory(dir.toFile());
                pb.environment().put("RM11_P11_MACHINE_ID_FILE",identity.toString());
                pb.environment().put("DISPLAY","127.0.0.1:2");
                disableExperimentalSync(pb.environment());
                // Native winex11 must connect through the existing verified
                // TCP-to-UNIX bridge. Never fake an X11 handshake or DISPLAY.
                quietGuiGuestLog(pb.environment());
                guest=pb.start();
                OfflineDiagnosticJournal.record(ctx,"v49144-p11-gui-checkpoint",
                    "P11_GUI_PHASE=SIGNED_GDI_GUEST_STARTED\n"
                    +"P11_GUI_PRIVATE_INIT="+guiInitStage);
                if(guestStarted!=null)guestStarted.run();
                boolean finished=false;
                for(int seconds=0;seconds<24;seconds++){
                    if(guest.waitFor(1,TimeUnit.SECONDS)){
                        finished=true;break;
                    }
                    if(seconds==5||seconds==11||seconds==17){
                        OfflineDiagnosticJournal.record(ctx,"v49144-p11-gui-checkpoint",
                            "P11_GUI_PHASE=GUEST_WAIT_SECONDS_"+(seconds+1)+"\n"
                            +"P11_GUI_PRIVATE_SERVER_ALIVE="+server.isAlive()+"\n"
                            +"P11_GUI_GUEST_LOG_BYTES="+
                            (Files.exists(guestLog)?Files.size(guestLog):0));
                    }
                    if(seconds==3||seconds==8||seconds==14||seconds==19){
                        x11=NativeDesktopVisualEvidence.auditX11();
                        java.util.regex.Matcher m=java.util.regex.Pattern
                            .compile("x11_children_viewable=(\\d+)").matcher(x11);
                        if(m.find()&&Integer.parseInt(m.group(1))>0)
                            viewable=true;
                    }
                    if(guestLog!=null && Files.exists(guestLog) && Files.size(guestLog)>4194304L){
                        outcome="ABORTED_EXCESSIVE_GUEST_LOG";
                        OfflineDiagnosticJournal.record(ctx,"v49144-p11-gui-checkpoint",
                            "P11_GUI_PHASE=GUEST_LOG_EXCEEDED_SAFETY_BUDGET\n"
                            +"P11_GUI_WINEDEBUG="+GDI_DIAGNOSTIC_WINEDEBUG+"\n"
                            +"P11_GUI_GUEST_LOG_BYTES="+Files.size(guestLog)+"\n"
                            +"P11_GUI_STAGE="+gdiStage(boundedLog(guestLog))+"\n"
                            +"P11_GUI_SERVER_ALIVE="+server.isAlive());
                        break;
                    }
                    if(server!=null&&!server.isAlive()){
                        serverEnd="EXIT_"+server.exitValue();
                        outcome="ABORTED_PRIVATE_WINESERVER_EXIT_"+server.exitValue();
                        OfflineDiagnosticJournal.record(ctx,"v49144-p11-gui-checkpoint",
                            "P11_GUI_PHASE=PRIVATE_SERVER_DIED_DURING_GDI\n"
                            +"P11_GUI_SERVER_EXIT="+server.exitValue()+"\n"
                            +"P11_GUI_SERVER_LOG="+safeLogSummary(serverLog,2700)+"\n"
                            +"P11_GUI_CLIENT_LOG="+safeLogSummary(guestLog,1700));
                        break;
                    }
                    if(thermalBlocked(ctx)){
                        outcome="ABORTED_THERMAL_SEVERE";
                        break;
                    }
                    if(Thread.currentThread().isInterrupted()){
                        outcome="ABORTED_INTERRUPTED";
                        break;
                    }
                }
                if(finished){
                    int exit=guest.exitValue();
                    guestOk=guestPass(exit,boundedLog(guestLog));
                    outcome=guestOk?"GUEST_EXIT48_GDI_COLORS_PASS":
                        "GUEST_EXIT_"+exit+"_GDI_PROOF_MISSING";
                }else if(!outcome.startsWith("ABORTED_"))
                    outcome="SAFETY_TIMEOUT_24S";
            }
        }catch(InterruptedException stop){
            Thread.currentThread().interrupt();
            outcome="ABORTED_INTERRUPTED";
        }catch(Exception e){
            outcome="BLOCKED_"+e.getClass().getSimpleName()
                +(e.getMessage()==null?"":":"+e.getMessage());
        }finally{
            // Persist final witness BEFORE WineServer shutdown, allowing
            // diagnostics even if cleanup stalls or Activity is closed.
            if(ctx!=null)OfflineDiagnosticJournal.record(ctx,
                "v49144-p11-gui-checkpoint",
                "P11_GUI_PHASE=FINALLY_BEFORE_CLEANUP\n"
                +"P11_GUI_RESULT="+outcome+"\n"
                +"P11_GUI_INIT_STAGE="+guiInitStage+"\n"
                +"P11_GUI_SERVER_WAS="+serverStage);
            if(guiInit!=null&&guiInit.isAlive()){
                guiInit.destroy();
                try{if(!guiInit.waitFor(1,TimeUnit.SECONDS))
                    guiInit.destroyForcibly();}
                catch(InterruptedException ex){
                    Thread.currentThread().interrupt();
                    guiInit.destroyForcibly();
                }
            }
            if(guest!=null&&guest.isAlive()){
                guest.destroy();
                try{if(!guest.waitFor(1,TimeUnit.SECONDS))guest.destroyForcibly();}
                catch(InterruptedException stop){
                    Thread.currentThread().interrupt();guest.destroyForcibly();
                }
            }
            if(server!=null && !server.isAlive())
                serverEnd="EXIT_"+server.exitValue();
            else if(server!=null)serverEnd="ALIVE_BEFORE_STOP";
            if(plan!=null&&(server!=null||guest!=null))
                KernixProtonNativeQualificationV49123.stopOwnedQualificationServer(ctx,plan);
            if(server!=null&&server.isAlive()){
                server.destroy();
                try{if(!server.waitFor(1,TimeUnit.SECONDS))server.destroyForcibly();}
                catch(InterruptedException stop){
                    Thread.currentThread().interrupt();server.destroyForcibly();
                }
            }
            boolean magenta=magentaAndroidPixels!=null&&magentaAndroidPixels.get();
            boolean cyan=cyanAndroidPixels!=null&&cyanAndroidPixels.get();
            boolean pixels=magenta&&cyan;
            boolean complete=completeWindowEvidence(guestOk,viewable,magenta,cyan);
            boolean recorded=KernixEngineQualificationV49090
                .recordWin32X11VisibleFrame(ctx,guestOk,viewable,pixels);
            String guestText=boundedLog(guestLog);
            String serverText=boundedLog(serverLog);
            long finalGuestBytes=-1L;
            try{if(guestLog!=null&&Files.exists(guestLog))
                finalGuestBytes=Files.size(guestLog);}
            catch(IOException ignored){}
            String trace=guestText.replaceAll("[^A-Za-z0-9. _()+:=-]"," ")
                .replaceAll("\\s+"," ");
            if(trace.length()>2200)trace=trace.substring(0,1100)
                +" [MIDDLE_OMITTED] "+trace.substring(trace.length()-1100);
            String serverTrace=serverText.replaceAll("[^A-Za-z0-9. _()+:=-]"," ")
                .replaceAll("\\s+"," ");
            if(serverTrace.length()>1100)serverTrace=serverTrace.substring(0,550)
                +" [MIDDLE_OMITTED] "+serverTrace.substring(serverTrace.length()-550);
            if(ctx!=null)OfflineDiagnosticJournal.record(ctx,
                "v49140-proton-gdi-x11-window",
                "P11_X11_GDI_RESULT="+outcome+"\n"
                +"P11_X11_PRIVATE_SERVER_STATUS="+serverStage+"\n"
                +"P11_X11_GUI_PREFIX_INIT="+guiInitStage+"\n"
                +"P11_X11_GUEST_WINEDEBUG="+GDI_DIAGNOSTIC_WINEDEBUG+"\n"
                +"P11_X11_GUEST_LOG_BYTES="+finalGuestBytes+"\n"
                +"P11_X11_GUEST_BOOTSTRAP_PHASE="+guiGuestLogVerdict(
                    serverStage.equals("ALIVE")&&!serverCrashed(serverText),
                    !"WIN64_GDI_MAIN_NOT_REACHED".equals(gdiStage(guestText)),
                    finalGuestBytes,"ABORTED_EXCESSIVE_GUEST_LOG".equals(outcome))+"\n"
                +"P11_X11_GUI_INIT_LOG="+safeLogSummary(guiInitLog,900)+"\\n"
                +"P11_X11_PRIVATE_SERVER_EXIT="+serverEnd+"\n"
                +"P11_X11_WINESERVER_SIGSEGV_MARKER="+serverCrashed(serverText)+"\n"
                +"P11_X11_QUEUE_NO_THREAD_DESKTOP="+serverMarkerState(
                    serverLog,"KERNIX_P11_QUEUE_NO_THREAD_DESKTOP")+"\n"
                +"P11_X11_QUEUE_CREATE_FAILED_AT_REQUEST="+serverMarkerState(
                    serverLog,"KERNIX_P11_QUEUE_CREATE_FAILED_AT_REQUEST")+"\n"
                +"P11_X11_QUEUE_HANDLE_ALLOC_FAILED="+serverMarkerState(
                    serverLog,"KERNIX_P11_QUEUE_HANDLE_ALLOC_FAILED")+"\n"
                +"P11_X11_QUEUE_CREATE_FAILED_BEFORE_FD="+serverMarkerState(
                    serverLog,"KERNIX_P11_QUEUE_CREATE_FAILED_BEFORE_FD")+"\n"
                +"P11_X11_WIN64_LAST_GDI_STAGE="+gdiStage(guestText)+"\n"
                +"P11_X11_GDI_SYNC_MODE=CONSERVATIVE_NO_NTSYNC_ESYNC_FSYNC\n"
                +"P11_X11_SIGNED_GUEST_STARTUP_TRACE="+trace+"\n"
                +"P11_X11_WINESERVER_TRACE="+serverTrace+"\n"
                +"P11_X11_GDI_WIN64_EXIT48="+guestOk+"\n"
                +"P11_X11_GDI_VIEWABLE_X11_CHILD="+viewable+"\n"
                +"P11_X11_GDI_ANDROID_MAGENTA_PIXELS="+magenta+"\n"
                +"P11_X11_GDI_ANDROID_CYAN_PIXELS="+cyan+"\n"
                +"P11_X11_GDI_ANDROID_BOTH_PHASES="+pixels+"\n"
                +"P11_X11_GDI_COMPLETE="+complete+"\n"
                +"P11_X11_GDI_STAGE_RECORDED="+recorded+"\n"
                +"P11_X11_GUI_PROBE_ONLY_NO_DXVK_OR_GAMEPLAY=true\n"
                +"P11_X11_RELAY_AUDIT="+x11.replace('\n',' ')+"\n"
                +"P11_X11_GUEST_TRACE="+trace);
            if(guestLog!=null)try{Files.deleteIfExists(guestLog);}
                catch(IOException ignored){}
            if(serverLog!=null)try{Files.deleteIfExists(serverLog);}
                catch(IOException ignored){}
            if(guiInitLog!=null)try{Files.deleteIfExists(guiInitLog);}
                catch(IOException ignored){}
        }
        return outcome;
    }
}
