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
            byte[] b=new byte[(int)Math.min(size,12000L)];
            log.seek(size-b.length);
            log.readFully(b);
            return new String(b,StandardCharsets.UTF_8);
        }catch(IOException ignored){return "LOG_UNAVAILABLE";}
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
        Process guest=null,server=null;
        Path guestLog=null,serverLog=null;
        KernixProtonNativeQualificationV49123.Plan plan=null;
        String outcome="BLOCKED_NOT_STARTED";
        boolean viewable=false,guestOk=false;
        String x11="X11_NOT_QUERIED";
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
                Path identity=KernixProtonNativeQualificationV49123.localMachineId(ctx);
                server=plan.prefixServerWithIdentity(serverLog,identity).start();
                Thread.sleep(300);
                ProcessBuilder pb=plan.prefixBootCommand(guestLog);
                pb.command(plan.loader.toString(),command(digest));
                pb.directory(dir.toFile());
                pb.environment().put("RM11_P11_MACHINE_ID_FILE",identity.toString());
                pb.environment().put("DISPLAY","127.0.0.1:2");
                // Native winex11 must connect through the existing verified
                // TCP-to-UNIX bridge. Never fake an X11 handshake or DISPLAY.
                pb.environment().put("WINEDEBUG","+err,+warn");
                guest=pb.start();
                if(guestStarted!=null)guestStarted.run();
                boolean finished=false;
                for(int seconds=0;seconds<24;seconds++){
                    if(guest.waitFor(1,TimeUnit.SECONDS)){
                        finished=true;break;
                    }
                    if(seconds==3||seconds==8){
                        x11=NativeDesktopVisualEvidence.auditX11();
                        java.util.regex.Matcher m=java.util.regex.Pattern
                            .compile("x11_children_viewable=(\\d+)").matcher(x11);
                        if(m.find()&&Integer.parseInt(m.group(1))>0)
                            viewable=true;
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
            if(guest!=null&&guest.isAlive()){
                guest.destroy();
                try{if(!guest.waitFor(1,TimeUnit.SECONDS))guest.destroyForcibly();}
                catch(InterruptedException stop){
                    Thread.currentThread().interrupt();guest.destroyForcibly();
                }
            }
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
            String trace=boundedLog(guestLog)
                .replaceAll("[^A-Za-z0-9. _()+:=-]"," ")
                .replaceAll("\\s+"," ");
            if(trace.length()>500)trace=trace.substring(0,500);
            if(ctx!=null)OfflineDiagnosticJournal.record(ctx,
                "v49140-proton-gdi-x11-window",
                "P11_X11_GDI_RESULT="+outcome+"\n"
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
        }
        return outcome;
    }
}
