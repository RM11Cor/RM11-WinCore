package org.kernix.host;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermission;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Stream;

/**
 * G2-D MIT-only 16KiB-safe imported x86 PLT/DSO guest bytes. Exact signed-APK asset handoff,
 * SHA-only, app-private; no x86 ELF, FEX, ld-linux or Wine execution.
 *
 * An InputProvider must be bound to trusted assets INSIDE the signed APK.
 * A future Android child independently opens O_NOFOLLOW FDs, compares the
 * same SHA-256, and rehashes anonymous byte snapshots (no TOCTOU by path).
 */
final class G2DMitImportGuestAssets {
    static final String ROOT_NAME = "g2d-import-v1";
    static final String[] PATHS = {
        "bin/kernix-g2d-import-app",
        "lib/x86_64-linux-gnu/libkernix-g2d-mit-import.so.1",
        "lib64/ld-kernix-g2d-mit-import-test.so.1"
    };
    static final long[] SIZES = {50504L, 50048L, 50024L};
    static final String[] SHA256 = {
        "a29be66289673e80cef5de115dfce0f05cb04599368f039c44c728ad0b2278a0",
        "8ec9bac9b3a21eeaedb4ec9c7071907a6074cbea9eb41f78591e176f0a27441e",
        "a37ed983c898512082749c5a9ec2cc3c10be8fd1adcffd4eaf09fb7346c068d2"
    };
    static final String STAGED = "KERNIX_G2D_MIT_IMPORT_SIGNED_ASSET_SHA256_STAGED_NO_GUEST_EXEC";
    static final String ALREADY = "KERNIX_G2D_MIT_IMPORT_APP_PRIVATE_ALREADY_ATTESTED_NO_GUEST_EXEC";
    private static final LinkOption[] NO_LINKS = {LinkOption.NOFOLLOW_LINKS};

    @FunctionalInterface interface InputProvider {
        InputStream open(String fixedName) throws IOException;
    }
    private G2DMitImportGuestAssets() {}

    private static void directory(Path path) throws IOException {
        if (Files.isSymbolicLink(path) || !Files.isDirectory(path, NO_LINKS))
            throw new IOException("MIT guest directory missing or redirected");
    }
    private static Path parent(File appFilesDir, boolean create) throws IOException {
        if (appFilesDir == null) throw new IOException("Missing app-private root");
        Path base=appFilesDir.toPath().toAbsolutePath().normalize();
        directory(base);
        Path cursor=base;
        for(String part:new String[]{"kernix","runtime-v1","guest-rootfs"}) {
            cursor=cursor.resolve(part);
            if(create && !Files.exists(cursor,NO_LINKS)) Files.createDirectory(cursor);
            directory(cursor);
        }
        return cursor;
    }
    private static MessageDigest sha() throws IOException {
        try { return MessageDigest.getInstance("SHA-256"); }
        catch (NoSuchAlgorithmException error) { throw new IOException("SHA256 unavailable",error); }
    }
    private static String hex(byte[] bytes) {
        StringBuilder result=new StringBuilder(bytes.length*2);
        for(byte b:bytes) {
            result.append(Character.forDigit((b & 0xff)>>>4,16));
            result.append(Character.forDigit(b & 15,16));
        }
        return result.toString();
    }
    private static void attestTree(Path root) throws IOException {
        directory(root);
        final Set<String> allowed=new HashSet<>(Arrays.asList(
            "", "bin", "lib", "lib/x86_64-linux-gnu", "lib64"));
        allowed.addAll(Arrays.asList(PATHS));
        try(Stream<Path> listing=Files.walk(root)) {
            for(Path path:(Iterable<Path>)listing::iterator) {
                final String relative=root.relativize(path).toString()
                    .replace(File.separatorChar,'/');
                if(!allowed.contains(relative) || Files.isSymbolicLink(path) ||
                   !(Files.isDirectory(path,NO_LINKS) ||
                     Files.isRegularFile(path,NO_LINKS)))
                    throw new IOException("Unknown MIT guest file or symlink");
            }
        }
        for(String dir:new String[]{"bin","lib","lib/x86_64-linux-gnu","lib64"})
            directory(root.resolve(dir));
        byte[] bytes=new byte[8192];
        for(int i=0;i<PATHS.length;i++) {
            Path path=root.resolve(PATHS[i]);
            if(!Files.isRegularFile(path,NO_LINKS) ||
               Files.isSymbolicLink(path) || Files.size(path)!=SIZES[i])
                throw new IOException("MIT G2-D imported ELF missing or wrong size");
            MessageDigest hash=sha();
            try(InputStream stream=Files.newInputStream(path)) {
                int count;
                while((count=stream.read(bytes))!=-1)hash.update(bytes,0,count);
            }
            if(!hex(hash.digest()).equals(SHA256[i]))
                throw new IOException("MIT G2-D imported ELF tampered");
        }
    }
    static String attestAppPrivate(File appFilesDir) throws IOException {
        Path path=parent(appFilesDir,false).resolve(ROOT_NAME);
        attestTree(path);
        return "KERNIX_G2D_MIT_IMPORT_APP_PRIVATE_ALL_THREE_SHA256_VERIFIED_NO_FEX";
    }
    private static void cleanup(Path temp) throws IOException {
        if(temp==null || !Files.exists(temp,NO_LINKS))return;
        try(Stream<Path> paths=Files.walk(temp)) {
            Path[] all=paths.sorted((a,b)->Integer.compare(
                b.getNameCount(),a.getNameCount())).toArray(Path[]::new);
            for(Path path:all) Files.deleteIfExists(path);
        }
    }
    static String stage(File appFilesDir,InputProvider fromSignedApk)
            throws IOException {
        if(fromSignedApk==null)throw new IOException("No signed APK asset source");
        Path base=parent(appFilesDir,true);
        Path destination=base.resolve(ROOT_NAME);
        if(Files.exists(destination,NO_LINKS)) {
            attestTree(destination); // never replace a tampered tree
            return ALREADY;
        }
        Path temporary=null;
        try {
            temporary=Files.createTempDirectory(base,".g2d-mit-import-stage-");
            Path staging=temporary.resolve(ROOT_NAME);
            Files.createDirectory(staging);
            Files.createDirectory(staging.resolve("bin"));
            Files.createDirectory(staging.resolve("lib"));
            Files.createDirectory(staging.resolve("lib/x86_64-linux-gnu"));
            Files.createDirectory(staging.resolve("lib64"));
            byte[] buffer=new byte[8192];
            for(int i=0;i<PATHS.length;i++) {
                final Path output=staging.resolve(PATHS[i]);
                final MessageDigest digest=sha();
                long length=0;
                try(InputStream in=fromSignedApk.open(PATHS[i]);
                    OutputStream out=Files.newOutputStream(output)) {
                    if(in==null) throw new IOException("Bundled guest asset missing");
                    int count;
                    while((count=in.read(buffer))!=-1) {
                        length+=count;
                        if(length>SIZES[i]) throw new IOException("MIT asset too large");
                        digest.update(buffer,0,count);
                        out.write(buffer,0,count);
                    }
                }
                if(length!=SIZES[i] || !hex(digest.digest()).equals(SHA256[i]))
                    throw new IOException("Original MIT signed asset SHA256 mismatch");
                Files.setPosixFilePermissions(output,
                    EnumSet.of(PosixFilePermission.OWNER_READ,
                               PosixFilePermission.GROUP_READ,
                               PosixFilePermission.OTHERS_READ));
            }
            attestTree(staging);
            if(Files.exists(destination,NO_LINKS))
                throw new IOException("MIT guest tree appeared during staging");
            Files.move(staging,destination,StandardCopyOption.ATOMIC_MOVE);
            attestTree(destination);
            return STAGED;
        } finally {
            cleanup(temporary);
        }
    }
}
