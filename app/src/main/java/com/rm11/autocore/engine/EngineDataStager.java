package com.rm11.autocore.engine;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Enumeration;
import java.util.Locale;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Side-by-side verified Windows PE/data package stager for the future engine.
 *
 * THIS DOES NOT INSTALL OR EXECUTE Linux binaries. Android API 29+ blocks
 * execve() from app-writable data. Native ELF launchers, Turnip and Wine X11
 * must be packaged separately in signed APK nativeLibraryDir.
 *
 * Never touches the legacy Wine prefix, registry, saved games or app shortcuts.
 * The caller must obtain expected SHA-256 from a trusted signed APK manifest,
 * never from an arbitrary ZIP next to a user's EXE.
 */
public final class EngineDataStager {
    private static final long MAX_FILE_BYTES=200L*1024*1024;
    private static final long MAX_TOTAL_BYTES=700L*1024*1024;
    private static final int MAX_ENTRIES=10000;
    private static final Pattern SHA=Pattern.compile("[0-9a-f]{64}");
    private static final Pattern SAFE_PE=Pattern.compile(
            "windows/system32/[A-Za-z0-9_.-]{1,96}\\.(dll|exe|mui)",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern SAFE_DATA=Pattern.compile(
            "runtime/(config|data)/([A-Za-z0-9_.-]{1,100}/){0,4}[A-Za-z0-9_.-]{1,96}\\.(json|cfg|ini|txt|dat|ttf|reg)",
            Pattern.CASE_INSENSITIVE);

    private EngineDataStager(){}

    /** Shared strict entry policy for first install AND on-disk reuse. */
    static boolean isAllowedDataEntry(String name) {
        return name!=null && name.indexOf('\\')<0 && name.indexOf('\0')<0
                &&(SAFE_PE.matcher(name).matches()||SAFE_DATA.matcher(name).matches());
    }

    public static final class Result {
        public final Path installedData;
        public final int installedFiles;
        public final boolean alreadyInstalled;
        private Result(Path p,int n,boolean exists){
            installedData=p;installedFiles=n;alreadyInstalled=exists;
        }
    }

    public static Result stage(Path signedBundleZip,Path appFiles,
                               String expectedSha256) throws IOException {
        if(!SHA.matcher(expectedSha256==null?"":expectedSha256).matches())
            throw new IOException("ENGINE_INVALID_TRUSTED_SHA256");
        if(!Files.isRegularFile(signedBundleZip,LinkOption.NOFOLLOW_LINKS))
            throw new IOException("ENGINE_MISSING_SIGNED_DATA_BUNDLE");
        if(!Files.isDirectory(appFiles,LinkOption.NOFOLLOW_LINKS))
            throw new IOException("ENGINE_APP_FILES_NOT_DIRECTORY");
        Path root=appFiles.toRealPath();
        if(Files.isSymbolicLink(root))
            throw new IOException("ENGINE_APP_FILES_SYMLINK");
        if(!sha256(signedBundleZip).equals(expectedSha256))
            throw new IOException("ENGINE_BUNDLE_HASH_MISMATCH");

        Path stagingRoot=root.resolve("engine-vnext");
        Path versions=stagingRoot.resolve("versions");
        Files.createDirectories(versions);
        if(!versions.toRealPath().startsWith(root))
            throw new IOException("ENGINE_STAGING_ESCAPES_APP");
        Path destination=versions.resolve(expectedSha256);
        if(Files.exists(destination,LinkOption.NOFOLLOW_LINKS)) {
            // Marker alone is not trust: verify every staged byte against
            // the same signed ZIP. Reject modified DLLs or added content.
            try(ZipFile trusted=new ZipFile(signedBundleZip.toFile())){
                if(EngineInstalledTreeVerifier.matches(destination,trusted,
                        expectedSha256))
                    return new Result(destination,0,true);
            }
            throw new IOException("ENGINE_UNTRUSTED_EXISTING_INSTALLATION");
        }

        Path temporary=Files.createTempDirectory(versions,".rm11-stage-");
        boolean promoted=false;
        int files=0;
        long total=0;
        try(ZipFile zip=new ZipFile(signedBundleZip.toFile())){
            Enumeration<? extends ZipEntry> entries=zip.entries();
            int count=0;
            while(entries.hasMoreElements()){
                ZipEntry entry=entries.nextElement();
                if(++count>MAX_ENTRIES)throw new IOException("ENGINE_TOO_MANY_ENTRIES");
                String name=entry.getName();
                if(name==null||name.indexOf('\\')>=0||name.indexOf('\0')>=0)
                    throw new IOException("ENGINE_INVALID_ENTRY_NAME");
                if(entry.isDirectory())continue;
                if(!isAllowedDataEntry(name))
                    throw new IOException("ENGINE_DISALLOWED_DATA_ENTRY");
                long size=entry.getSize();
                if(size<0||size>MAX_FILE_BYTES||total+size>MAX_TOTAL_BYTES)
                    throw new IOException("ENGINE_UNSAFE_ENTRY_SIZE");
                Path target=temporary.resolve(name).normalize();
                if(!target.startsWith(temporary))
                    throw new IOException("ENGINE_PATH_TRAVERSAL");
                if(Files.exists(target,LinkOption.NOFOLLOW_LINKS))
                    throw new IOException("ENGINE_DUPLICATE_DATA_ENTRY");
                Files.createDirectories(target.getParent());
                long copied=0;
                boolean checkMZ=SAFE_PE.matcher(name).matches()
                        &&(name.toLowerCase(Locale.ROOT).endsWith(".dll")
                            ||name.toLowerCase(Locale.ROOT).endsWith(".exe"));
                try(InputStream source=zip.getInputStream(entry);
                    OutputStream dst=Files.newOutputStream(target,
                            StandardOpenOption.CREATE_NEW,StandardOpenOption.WRITE)){
                    byte[] buffer=new byte[32*1024];
                    int n;
                    byte first=0,second=0;
                    while((n=source.read(buffer))!=-1){
                        if(n==0)continue;
                        if(copied==0&&n>=1)first=buffer[0];
                        if(copied==0&&n>=2)second=buffer[1];
                        else if(copied==1&&n>=1)second=buffer[0];
                        dst.write(buffer,0,n);
                        copied+=n;
                        if(copied>MAX_FILE_BYTES)
                            throw new IOException("ENGINE_DECOMPRESSION_LIMIT");
                    }
                    if(checkMZ&&(copied<2||first!='M'||second!='Z'))
                        throw new IOException("ENGINE_INVALID_PE_IMAGE");
                }
                if(size!=copied)throw new IOException("ENGINE_ENTRY_SIZE_CHANGED");
                total+=copied;
                files++;
            }
            if(files==0)throw new IOException("ENGINE_EMPTY_DATA_BUNDLE");
            Files.write(temporary.resolve(".verified-bundle"),
                    (expectedSha256+"\n").getBytes(java.nio.charset.StandardCharsets.UTF_8),
                    StandardOpenOption.CREATE_NEW);
            // Only atomic side-by-side promotion. Never set this new bundle
            // as the active engine or replace the user Wine prefix here.
            try{
                Files.move(temporary,destination,StandardCopyOption.ATOMIC_MOVE);
            }catch(AtomicMoveNotSupportedException unavailable){
                throw new IOException("ENGINE_ATOMIC_PROMOTION_REQUIRED",unavailable);
            }
            promoted=true;
            return new Result(destination,files,false);
        }finally{
            if(!promoted)removeStagingDirectory(temporary);
        }
    }

    private static void removeStagingDirectory(Path dir)throws IOException{
        if(!Files.exists(dir,LinkOption.NOFOLLOW_LINKS))return;
        try(java.util.stream.Stream<Path> paths=Files.walk(dir)){
            for(Path p:(Iterable<Path>)paths.sorted(
                    java.util.Comparator.reverseOrder())::iterator){
                Files.deleteIfExists(p);
            }
        }
    }
    public static String sha256(Path p)throws IOException{
        try{
            MessageDigest hash=MessageDigest.getInstance("SHA-256");
            try(InputStream input=Files.newInputStream(p)){
                byte[] buf=new byte[64*1024];
                for(int n;(n=input.read(buf))!=-1;)if(n>0)hash.update(buf,0,n);
            }
            StringBuilder hex=new StringBuilder(64);
            for(byte b:hash.digest())hex.append(String.format(Locale.ROOT,"%02x",b&255));
            return hex.toString();
        }catch(NoSuchAlgorithmException missing){
            throw new IOException("ENGINE_SHA256_UNAVAILABLE",missing);
        }
    }
}
