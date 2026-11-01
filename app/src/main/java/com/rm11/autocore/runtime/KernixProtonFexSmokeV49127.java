package com.rm11.autocore.runtime;

import android.content.Context;
import com.rm11.autocore.diagnostics.OfflineDiagnosticJournal;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.util.Locale;
import java.util.concurrent.TimeUnit;
import org.json.JSONObject;

/** Small bounded x64 guest test, NOT a gameplay or DXVK frame proof.
 * Only runs after signed native Wine, WineServer and separate Wineboot pass. */
public final class KernixProtonFexSmokeV49127 {
    private KernixProtonFexSmokeV49127(){}
    private static final String ASSET="runtime/kernix-p11-fex-x64-smoke.exe";
    private static final String MANIFEST="runtime/kernix-p11-fex-x64-smoke.json";
    private static final String MARKER="KERNIX_P11_FEX64_WIN32_OK";
    // A previous signed build may have left a different smoke PE in the
    // owned prefix. Never overwrite it and never mistake it for this build.
    // Bind both the Windows path and filename to the attested SHA-256.
    static String privateProbeFileName(String digest){
        if(digest==null||!digest.matches("[0-9a-f]{64}"))
            throw new IllegalArgumentException("P11_X64_SHA_FORMAT");
        return "kernix-p11-fex-x64-"+digest.substring(0,24)+".exe";
    }
    static String privateGuestCommand(String digest){
        return "C:\\kernix-probes\\"+privateProbeFileName(digest);
    }
    private static String sha(byte[] data)throws Exception{
        byte[] b=MessageDigest.getInstance("SHA-256").digest(data);
        StringBuilder out=new StringBuilder();
        for(byte x:b)out.append(String.format(Locale.ROOT,"%02x",x&255));
        return out.toString();
    }
    private static byte[] readBounded(InputStream raw,int limit)throws IOException{
        try(InputStream in=raw;ByteArrayOutputStream dst=new ByteArrayOutputStream()){
            byte[] buf=new byte[8192];
            for(int n;(n=in.read(buf))!=-1;){
                if(n==0)continue;
                if(dst.size()+n>limit)throw new IOException("P11_SMOKE_ASSET_TOO_LARGE");
                dst.write(buf,0,n);
            }
            return dst.toByteArray();
        }
    }
    /** Read fixed first/last windows, not a potentially huge Wine log. */
    private static String readProbeLog(Path path)throws IOException{
        try(java.io.RandomAccessFile input=
                new java.io.RandomAccessFile(path.toFile(),"r")){
            long len=input.length();
            int first=(int)Math.min(len,8192L);
            byte[] begin=new byte[first];
            input.readFully(begin);
            if(len<=first)return new String(begin,StandardCharsets.UTF_8);
            int last=(int)Math.min(len-first,8192L);
            byte[] end=new byte[last];
            input.seek(len-last);
            input.readFully(end);
            return new String(begin,StandardCharsets.UTF_8)
                +" [TRUNCATED_MIDDLE] "
                +new String(end,StandardCharsets.UTF_8);
        }
    }

    public static boolean isWin64Pe(byte[] data){
        if(data==null||data.length<4096||data[0]!='M'||data[1]!='Z')return false;
        int start=(data[0x3c]&255)|((data[0x3d]&255)<<8)
            |((data[0x3e]&255)<<16)|((data[0x3f]&255)<<24);
        if(start<64||start>data.length-26)return false;
        return data[start]=='P'&&data[start+1]=='E'
            &&data[start+2]==0&&data[start+3]==0
            &&(data[start+4]&255)==0x64&&(data[start+5]&255)==0x86
            &&(data[start+24]&255)==0x0b&&(data[start+25]&255)==0x02;
    }
    public static synchronized String run(Context ctx,
            KernixProtonNativeQualificationV49123.Plan plan){
        String result="P11_X64_NOT_RUN";
        Process process=null;
        Process serverProcess=null;
        Path output=null;
        Path serverOutput=null;
        String serverState="NOT_STARTED";
        try{
            if(ctx==null||plan==null)throw new IOException("P11_X64_NO_CONTEXT");
            KernixProtonPrefixV49126.requireWritable(
                plan.wineRoot,plan.prefix);
            JSONObject manifest=new JSONObject(new String(
                readBounded(ctx.getAssets().open(MANIFEST),8192),
                StandardCharsets.UTF_8));
            if(!"kernix.p11.fex.x64.smoke.v49127".equals(
                    manifest.optString("schema"))
                ||manifest.optInt("exit_code",-1)!=47
                ||!MARKER.equals(manifest.optString("stdout_marker")))
                throw new IOException("P11_X64_SIGNED_MANIFEST_INVALID");
            byte[] exe=readBounded(ctx.getAssets().open(ASSET),4*1024*1024);
            if(!isWin64Pe(exe)||exe.length!=manifest.getInt("bytes")
                ||!sha(exe).equals(manifest.getString("sha256")))
                throw new IOException("P11_X64_PE_ARCH_OR_SHA_MISMATCH");
            String guestSha=manifest.getString("sha256");
            Path dir=plan.prefix.resolve("drive_c/kernix-probes");
            if(Files.isSymbolicLink(dir))
                throw new IOException("P11_X64_PROBE_DIR_SYMLINK");
            Files.createDirectories(dir);
            Path file=dir.resolve(privateProbeFileName(guestSha));
            if(Files.isSymbolicLink(file))
                throw new IOException("P11_X64_PROBE_FILE_SYMLINK");
            if(!Files.exists(file,LinkOption.NOFOLLOW_LINKS))
                Files.write(file,exe,StandardOpenOption.CREATE_NEW);
            else{
                if(Files.size(file)>4L*1024*1024)
                    throw new IOException("P11_X64_UNTRUSTED_STAGED_SIZE");
                byte[] staged=Files.readAllBytes(file);
                if(!sha(staged).equals(manifest.getString("sha256")))
                    throw new IOException("P11_X64_EXISTING_PROBE_NOT_OWNED");
            }
            output=ctx.getCacheDir().toPath().resolve("kernix-p11-fex-probe.txt");
            if(Files.isSymbolicLink(output))
                throw new IOException("P11_X64_LOG_SYMLINK");
            serverOutput=ctx.getCacheDir().toPath().resolve("kernix-p11-fex-server.txt");
            if(Files.isSymbolicLink(serverOutput))
                throw new IOException("P11_X64_SERVER_LOG_SYMLINK");
            Path identity=KernixProtonNativeQualificationV49123.localMachineId(ctx);
            serverProcess=plan.prefixServerWithIdentity(serverOutput,identity).start();
            Thread.sleep(350);
            serverState=serverProcess.isAlive()?"RUNNING_SAME_PREFIX":"EARLY_EXIT_"+serverProcess.exitValue();
            ProcessBuilder pb=plan.prefixBootCommand(output);
            pb.environment().put("RM11_P11_MACHINE_ID_FILE",identity.toString());
            pb.environment().put("WINEDEBUG","+err,+warn,+process,+loaddll,+module");
            // The inherited Proton boot environment contains the exact
            // signed NTDLL bridge, FEX HODLLs and private WINEPREFIX.
            pb.command(plan.loader.toString(),privateGuestCommand(guestSha));
            pb.directory(dir.toFile());
            process=pb.start();
            if(!process.waitFor(16,TimeUnit.SECONDS)){
                process.destroy();
                if(!process.waitFor(1,TimeUnit.SECONDS))process.destroyForcibly();
                result="P11_X64_TIMEOUT";
            }else{
                int exit=process.exitValue();
                String text=readProbeLog(output);
                boolean found=text.contains(MARKER);
                if(exit==47&&found)
                    result="P11_X64_GUEST_EXIT47_AND_MARKER_PASS";
                else{
                    String clue=text.replaceAll("[^A-Za-z0-9. _()+:=-]"," ")
                        .replaceAll("\\s+"," ").trim();
                    if(clue.length()>420)
                        clue=clue.substring(clue.length()-420);
                    result="P11_X64_EXIT_"+exit+"_MARKER_"+found+"_SERVER_"+serverState
                        +"_TRACE_"+(clue.isEmpty()?"EMPTY":clue);
                }
            }
        }catch(Exception ex){
            result="P11_X64_BLOCKED_"+ex.getClass().getSimpleName()
                +(ex.getMessage()==null?"":":"+ex.getMessage());
        }finally{
            if(process!=null&&process.isAlive())process.destroyForcibly();
            if(serverProcess!=null && serverProcess.isAlive()){
                serverProcess.destroy();
                try{
                    if(!serverProcess.waitFor(1,TimeUnit.SECONDS))
                        serverProcess.destroyForcibly();
                }catch(InterruptedException e){
                    Thread.currentThread().interrupt();
                    serverProcess.destroyForcibly();
                }
            }
            if(output!=null)try{Files.deleteIfExists(output);}
                catch(IOException ignored){}
            if(serverOutput!=null)try{Files.deleteIfExists(serverOutput);}
                catch(IOException ignored){}
            if(ctx!=null)OfflineDiagnosticJournal.record(ctx,
                "v49127-proton-fex-x64-guest",
                "P11_FEX_X64_SMOKE="+result+"\n"
                +"P11_X64_SERVER_STAGE="+serverState+"\n"
                +"P11_X64_PE_LAUNCH_PATH=PRIVATE_C_DRIVE\n"
                +"P11_ACTUAL_WIN64_GUEST_GOT_EXIT47="+
                "P11_X64_GUEST_EXIT47_AND_MARKER_PASS".equals(result)+"\n"
                +"P11_GAMEPLAY_PROVEN=false\nP11_GPU_PRESENT_PROVEN=false");
        }
        return result;
    }
}
