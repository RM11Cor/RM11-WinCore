package com.rm11.autocore.runtime;

import android.content.Context;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.util.Locale;

/** Immutable SHA-pinned PE64 diagnostic input (not a user-selected game).
 * The package signed asset is the source of truth on every launch. */
public final class FiberSehProbeAsset {
    private static final String ASSET="runtime/rm11-fiber-seh-probe-v461-x64.exe";
    private static final String DIGEST=ASSET+".sha256";
    private static final String FILE="rm11-internal-fiber-seh-probe-v461.exe";
    private FiberSehProbeAsset(){}

    private static byte[] load(Context context,String asset,int max) throws IOException {
        try(InputStream in=context.getAssets().open(asset)) {
            byte[] b=in.readNBytes(max+1);
            if(b.length==0 || b.length>max)throw new IOException("RM11_V461_ASSET_LENGTH_INVALID");
            return b;
        }
    }
    private static String sha(byte[] b) throws IOException {
        try {
            byte[] digest=MessageDigest.getInstance("SHA-256").digest(b);
            StringBuilder out=new StringBuilder(64);
            for(byte v:digest)out.append(String.format(Locale.ROOT,"%02x",v&255));
            return out.toString();
        }catch(java.security.NoSuchAlgorithmException impossible) {
            throw new IOException("SHA-256 unavailable",impossible);
        }
    }
    private static byte[] checkedSource(Context ctx) throws IOException {
        byte[] data=load(ctx,ASSET,350000);
        if(data.length<1024||data[0]!='M'||data[1]!='Z')
            throw new IOException("RM11_V461_NOT_WINDOWS_PE");
        int off=(data[0x3c]&255)|((data[0x3d]&255)<<8)
                |((data[0x3e]&255)<<16)|((data[0x3f]&255)<<24);
        if(off<64||off+26>=data.length||data[off]!='P'||data[off+1]!='E'
                ||data[off+2]!=0||data[off+3]!=0
                ||(data[off+4]&255)!=0x64||(data[off+5]&255)!=0x86
                ||(data[off+24]&255)!=0x0b||(data[off+25]&255)!=0x02)
            throw new IOException("RM11_V461_NOT_PE32PLUS_X64");
        String expected=new String(load(ctx,DIGEST,128),StandardCharsets.US_ASCII).trim();
        if(!sha(data).equalsIgnoreCase(expected))
            throw new IOException("RM11_V461_APK_ASSET_SHA256_MISMATCH");
        return data;
    }
    public static Path stage(Context ctx) throws IOException {
        byte[] data=checkedSource(ctx);
        Path root=ctx.getFilesDir().toPath().toRealPath();
        Path target=root.resolve(FILE);
        if(Files.isSymbolicLink(target))
            throw new IOException("RM11_V461_UNTRUSTED_STAGED_FILE");
        if(Files.isRegularFile(target,LinkOption.NOFOLLOW_LINKS)
                && Files.size(target)==data.length
                && sha(Files.readAllBytes(target)).equals(sha(data)))
            return target;
        Path temporary=Files.createTempFile(root,".seh-v461-", ".part");
        try {
            Files.write(temporary,data);
            Files.move(temporary,target,StandardCopyOption.REPLACE_EXISTING);
        }finally {Files.deleteIfExists(temporary);}
        return target;
    }
    public static boolean isAuthentic(Context ctx,Path candidate) {
        try {
            Path root=ctx.getFilesDir().toPath().toRealPath();
            Path target=root.resolve(FILE);
            if(candidate==null||!candidate.toAbsolutePath().normalize().equals(target)
                    ||Files.isSymbolicLink(target)||!Files.isRegularFile(target))
                return false;
            return sha(Files.readAllBytes(target)).equals(sha(checkedSource(ctx)));
        }catch(Exception bad) {return false;}
    }
}
