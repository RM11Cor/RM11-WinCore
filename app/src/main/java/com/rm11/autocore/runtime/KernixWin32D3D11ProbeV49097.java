package com.rm11.autocore.runtime;

import android.content.Context;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.util.Locale;
import org.json.JSONObject;

/**
 * v49097: app-authored x64 D3D11 900-frame Windows engine test.
 * The exact CI-built MZ/PE32+ source test is SHA-attested before copying
 * to a dedicated app-owned Wine C: folder. Never touch games, user-selected
 * files, shared Windows DLL overrides or global Wine registry.
 *
 * This stages a test binary. It never certifies DXVK/Win32 frames on device:
 * only the actual subsequent Wine/DXVK/X11 run can provide that proof.
 */
public final class KernixWin32D3D11ProbeV49097 {
    private KernixWin32D3D11ProbeV49097() {}
    private static final String NAME="RM11-D3D11-FRAMES.exe";
    private static final String DIR="runtime/engine-probes/";
    private static final int MAX_BYTES=4*1024*1024;

    private static byte[] readBounded(InputStream input)throws Exception{
        ByteArrayOutputStream bytes=new ByteArrayOutputStream();
        byte[] buf=new byte[8192];
        int n;
        while((n=input.read(buf))!=-1){
            if(bytes.size()+n>MAX_BYTES)throw new IllegalStateException("PROBE_OVERSIZE");
            bytes.write(buf,0,n);
        }
        return bytes.toByteArray();
    }
    private static String sha256(byte[] input)throws Exception{
        byte[] sha=MessageDigest.getInstance("SHA-256").digest(input);
        StringBuilder out=new StringBuilder(64);
        for(byte b:sha)out.append(String.format(Locale.ROOT,"%02x",b&255));
        return out.toString();
    }
    private static void checkPe64(byte[] data){
        if(data.length<4096||data[0]!='M'||data[1]!='Z')
            throw new IllegalStateException("D3D11_PROBE_NOT_MZ");
        ByteBuffer b=ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);
        int offset=b.getInt(0x3c);
        if(offset<64||offset>data.length-30
            ||data[offset]!='P'||data[offset+1]!='E'
            ||data[offset+2]!=0||data[offset+3]!=0
            ||(b.getShort(offset+4)&65535)!=0x8664
            ||(b.getShort(offset+24)&65535)!=0x20b)
            throw new IllegalStateException("D3D11_PROBE_NOT_WIN64_PE32PLUS");
    }
    public static Path stage(Context ctx)throws Exception{
        if(ctx==null)throw new IllegalArgumentException("CONTEXT_REQUIRED");
        byte[] data;
        JSONObject receipt;
        try(InputStream in=ctx.getAssets().open(DIR+NAME)){
            data=readBounded(in);
        }
        try(InputStream in=ctx.getAssets().open(DIR+"manifest.json")){
            receipt=new JSONObject(new String(readBounded(in),
                java.nio.charset.StandardCharsets.UTF_8));
        }
        checkPe64(data);
        String actual=sha256(data);
        if(!"kernix.win64-d3d11-ci.v49097".equals(receipt.optString("schema"))
            ||!NAME.equals(receipt.optString("name"))
            ||data.length!=receipt.optInt("bytes",-1)
            ||!actual.equals(receipt.optString("sha256")))
            throw new IllegalStateException("D3D11_PROBE_CI_SHA_MISMATCH");

        RuntimeLayout layout=new RuntimeLayout(ctx.getFilesDir().toPath(),
            java.nio.file.Paths.get(ctx.getApplicationInfo().nativeLibraryDir));
        Path driveC=layout.winePrefix.resolve("drive_c");
        if(!Files.isDirectory(driveC,LinkOption.NOFOLLOW_LINKS)
           ||Files.isSymbolicLink(driveC))
            throw new IllegalStateException("WINE_C_DRIVE_NOT_PREPARED");
        Path base=driveC.resolve("KERNIX").resolve("engine-tests");
        Files.createDirectories(base);
        if(!base.toRealPath().startsWith(ctx.getFilesDir().toPath().toRealPath()))
            throw new IllegalStateException("PROBE_PATH_OUTSIDE_APP");
        Path target=base.resolve(NAME),temp=base.resolve(".kernix-d3d11-"+NAME+".pending");
        if(Files.isSymbolicLink(target)||Files.isSymbolicLink(temp))
            throw new IllegalStateException("PROBE_SYMLINK_REJECTED");
        if(Files.exists(target,LinkOption.NOFOLLOW_LINKS)){
            if(!Files.isRegularFile(target,LinkOption.NOFOLLOW_LINKS)
                ||!sha256(Files.readAllBytes(target)).equals(actual))
                throw new IllegalStateException("PROBE_NAME_OCCUPIED_NOT_OVERWRITTEN");
            return target;
        }
        Files.write(temp,data);
        if(!sha256(Files.readAllBytes(temp)).equals(actual))
            throw new IllegalStateException("PROBE_WRITE_VERIFICATION_FAILED");
        try{Files.move(temp,target,StandardCopyOption.ATOMIC_MOVE);}
        catch(java.nio.file.AtomicMoveNotSupportedException ignored){
            Files.move(temp,target);
        }
        return target;
    }
}
