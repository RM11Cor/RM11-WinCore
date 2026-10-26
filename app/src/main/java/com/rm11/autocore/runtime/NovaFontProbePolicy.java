package com.rm11.autocore.runtime;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Fail-closed opt-in glyph experiment, limited to the single published,
 * known 4096-byte Win64 GUI MessageBox test. No game EXE, Wine server,
 * Winefile, or general launcher is permitted to activate FreeType here.
 * Original signed core is loaded only in the selected EXE's process.
 */
public final class NovaFontProbePolicy {
    public static final String TEST_NAME="RM11-Win64-Visible-GUI-Test.exe";
    public static final String TEST_SHA256="a1cfe3cd2131185f2547b43d1918c1339f5375b99a03ada6952dc94f2cb1dbfc";
    private NovaFontProbePolicy(){}

    public static boolean isTestName(String name){
        return TEST_NAME.equalsIgnoreCase(name);
    }

    public static boolean matchesKnownDigest(String digest){
        return TEST_SHA256.equalsIgnoreCase(digest);
    }

    public static void requireKnownSignedProbe(Path exe,RuntimeLayout layout)
            throws IOException {
        if(exe==null || exe.getFileName()==null || !isTestName(exe.getFileName().toString())
                || Files.isSymbolicLink(exe)
                || !Files.isRegularFile(exe,LinkOption.NOFOLLOW_LINKS)
                || Files.size(exe)!=4096L)
            throw new IOException("RM11_V438_FONT_TRIAL_ONLY_FOR_VERIFIED_4KB_GUI_PROBE");
        String digest=sha256(exe);
        if(!matchesKnownDigest(digest))
            throw new IOException("RM11_V438_GUI_PROBE_SHA256_MISMATCH");
        Path signedDir=layout.apkNativeLibs.toRealPath();
        checkSignedNative(signedDir,"librm11_freetype_core.so",100000);
        checkSignedNative(signedDir,"librm11_wine_data_redirect.so",1000);
        if(Files.exists(signedDir.resolve("libfreetype.so"),LinkOption.NOFOLLOW_LINKS))
            throw new IOException("RM11_V438_GLOBAL_FREETYPE_ALIAS_DISALLOWED");
    }

    private static void checkSignedNative(Path base,String name,long minimum)
            throws IOException {
        Path entry=base.resolve(name);
        if(Files.isSymbolicLink(entry)||!Files.isRegularFile(entry,LinkOption.NOFOLLOW_LINKS)
                ||!Files.isReadable(entry)||Files.size(entry)<minimum
                ||!entry.toRealPath().startsWith(base))
            throw new IOException("RM11_V438_TRUSTED_NATIVE_FONT_LIB_MISSING: "+name);
        try(InputStream input=Files.newInputStream(entry)){
            byte[] head=new byte[20];
            if(input.read(head)!=head.length
                    ||head[0]!=127||head[1]!='E'||head[2]!='L'||head[3]!='F'
                    ||head[4]!=2||head[5]!=1|| (head[18]&255)!=183)
                throw new IOException("RM11_V438_FONT_LIB_NOT_ARM64_ELF: "+name);
        }
    }

    private static String sha256(Path p)throws IOException{
        try{
            MessageDigest digest=MessageDigest.getInstance("SHA-256");
            try(InputStream stream=Files.newInputStream(p)){
                byte[] buf=new byte[8192];
                for(int n;(n=stream.read(buf))!=-1;){
                    if(n>0)digest.update(buf,0,n);
                }
            }
            StringBuilder result=new StringBuilder(64);
            for(byte value:digest.digest())
                result.append(String.format(java.util.Locale.ROOT,"%02x",value&255));
            return result.toString();
        }catch(NoSuchAlgorithmException impossible){
            throw new IOException("SHA256 unavailable",impossible);
        }
    }
}
