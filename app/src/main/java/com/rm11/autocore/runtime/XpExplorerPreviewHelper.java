package com.rm11.autocore.runtime;

import android.content.Context;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.util.Locale;

/** Opt-in prototype only. Safe default remains the already-tested Winefile.
 * Never runs unknown EXEs, and does not alter any Wine system component.
 */
public final class XpExplorerPreviewHelper {
    public static final String PREFS="rm11-xp-shell-v428";
    public static final String KEY="preview-next-boot";
    private static final String ASSET="runtime/rm11-xp-explorer-arm64-v428.exe";
    private XpExplorerPreviewHelper(){}

    private static byte[] asset(Context context,String key,int cap) throws IOException {
        try(InputStream input=context.getAssets().open(key)){
            byte[] data=input.readNBytes(cap+1);
            if(data.length==0||data.length>cap)
                throw new IOException("RM11_V428_PREVIEW_ASSET_SIZE_INVALID");
            return data;
        }
    }
    private static String sha256(byte[] raw) throws IOException {
        try{
            byte[] sum=MessageDigest.getInstance("SHA-256").digest(raw);
            StringBuilder b=new StringBuilder(64);
            for(byte n:sum)b.append(String.format(Locale.ROOT,"%02x",n&255));
            return b.toString();
        }catch(java.security.NoSuchAlgorithmException ex){throw new IOException(ex);}
    }
    public static Path stage(Context context,RuntimeLayout layout) throws IOException {
        byte[] data=asset(context,ASSET,1500000);
        if(data.length<10000||data[0]!='M'||data[1]!='Z')
            throw new IOException("RM11_V428_PREVIEW_NOT_PE");
        int off=(data[0x3c]&255)|((data[0x3d]&255)<<8)
                |((data[0x3e]&255)<<16)|((data[0x3f]&255)<<24);
        if(off<64||off>data.length-26
                ||data[off]!='P'||data[off+1]!='E'||data[off+2]!=0||data[off+3]!=0
                ||(data[off+4]&255)!=0x64||(data[off+5]&255)!=0xaa
                ||(data[off+24]&255)!=0x0b||(data[off+25]&255)!=0x02)
            throw new IOException("RM11_V428_PREVIEW_NOT_ARM64_PE32_PLUS");
        String sum=sha256(data);
        String expected=new String(asset(context,ASSET+".sha256",128),
                java.nio.charset.StandardCharsets.US_ASCII).trim();
        if(!sum.equalsIgnoreCase(expected))
            throw new IOException("RM11_V428_PREVIEW_SHA256_MISMATCH");
        Path root=layout.appFiles.toRealPath();
        Path dest=root.resolve("rm11-xp-explorer-arm64-v428.exe").normalize();
        if(!dest.startsWith(root)||Files.isSymbolicLink(dest))
            throw new IOException("RM11_V428_PREVIEW_UNSAFE_PATH");
        if(Files.isRegularFile(dest,LinkOption.NOFOLLOW_LINKS)){
            byte[] old=Files.readAllBytes(dest);
            if(old.length==data.length && sha256(old).equals(sum))return dest;
        }
        Path temp=Files.createTempFile(root,"rm11-xp-explorer-", ".tmp");
        try{
            Files.write(temp,data);
            Files.move(temp,dest,StandardCopyOption.REPLACE_EXISTING);
        }finally{Files.deleteIfExists(temp);}
        return dest;
    }
}
