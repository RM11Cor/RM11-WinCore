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

/**
 * Stages a trusted APK-bundled PE/ARM64 controller (not a Linux executable).
 * This helper observes only Winefile HWND layout, and never reads phone data.
 * An absent or malformed asset is non-fatal: keep the known-working Winefile.
 */
public final class WinefileSingleWindowHelper {
    private static final String ASSET="runtime/rm11-winefile-one-window-arm64.exe";
    private static final String SUM=ASSET+".sha256";
    private WinefileSingleWindowHelper() {}

    private static String sha256(byte[] bytes) throws IOException {
        try {
            MessageDigest digest=MessageDigest.getInstance("SHA-256");
            byte[] hash=digest.digest(bytes);
            StringBuilder b=new StringBuilder(64);
            for(byte x:hash)b.append(String.format(Locale.ROOT,"%02x",x&255));
            return b.toString();
        }catch(java.security.NoSuchAlgorithmException failure) {
            throw new IOException("SHA256 not available",failure);
        }
    }
    private static byte[] boundedAsset(Context context,String asset,int max)
            throws IOException {
        try(InputStream stream=context.getAssets().open(asset)) {
            byte[] content=stream.readNBytes(max+1);
            if(content.length==0||content.length>max)
                throw new IOException("Window helper asset outside allowed size");
            return content;
        }
    }
    public static Path stage(Context context,RuntimeLayout layout) throws IOException {
        byte[] blob=boundedAsset(context,ASSET,300000);
        if(blob.length<1024||blob[0]!='M'||blob[1]!='Z')
            throw new IOException("Missing MZ Winefile policy header");
        int header=(blob[0x3c]&255)|((blob[0x3d]&255)<<8)
                |((blob[0x3e]&255)<<16)|((blob[0x3f]&255)<<24);
        if(header<64||header>blob.length-26
                ||blob[header]!='P'||blob[header+1]!='E'
                ||blob[header+2]!=0||blob[header+3]!=0
                ||(blob[header+4]&255)!=0x64||(blob[header+5]&255)!=0xaa)
            throw new IOException("Window helper is not trusted PE ARM64");
        String actual=sha256(blob);
        String pinned=new String(boundedAsset(context,SUM,128),
                java.nio.charset.StandardCharsets.US_ASCII).trim();
        if(!actual.equalsIgnoreCase(pinned))
            throw new IOException("Window helper APK SHA256 mismatch");
        Path root=layout.appFiles.toRealPath();
        Path dest=root.resolve("rm11-winefile-one-window-arm64.exe");
        if(Files.isSymbolicLink(dest) || (!dest.normalize().startsWith(root)))
            throw new IOException("Unsafe window helper path");
        if(Files.isRegularFile(dest,LinkOption.NOFOLLOW_LINKS)) {
            byte[] old=Files.readAllBytes(dest);
            if(old.length==blob.length && sha256(old).equals(actual))
                return dest;
        }
        Path temp=Files.createTempFile(root,"winefile-one-window-", ".part");
        try {
            Files.write(temp,blob);
            Files.move(temp,dest,StandardCopyOption.REPLACE_EXISTING);
        }finally {
            Files.deleteIfExists(temp);
        }
        return dest;
    }
}
