package org.kernix.host;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.EnumSet;
import java.util.Set;
import java.util.stream.Stream;

/** CI-only source staging proof; NEVER launches x86, FEX, Wine or games. */
public final class G2EGuestGlibcAssetsTest {
    private static void reject(Action test,String label)throws Exception {
        try { test.run(); }
        catch(IOException expected) { return; }
        throw new AssertionError("Unsafe Linux glibc G2-E input accepted: "+label);
    }
    @FunctionalInterface interface Action { void run() throws Exception; }

    private static void deleteTree(Path temp)throws IOException {
        if(!Files.exists(temp))return;
        try(Stream<Path> paths=Files.walk(temp)) {
            Path[] files=paths.sorted((a,b)->Integer.compare(
                b.getNameCount(),a.getNameCount())).toArray(Path[]::new);
            for(Path p:files)Files.deleteIfExists(p);
        }
    }
    public static void main(String[] args)throws Exception {
        if(args.length!=1)throw new AssertionError("Expected Linux glibc G2-E guest root");
        final Path source=Path.of(args[0]);
        final G2EGuestGlibcAssets.InputProvider provider =
            name -> Files.newInputStream(source.resolve(name));
        Path temp=Files.createTempDirectory("kernix-g2e-glibc-java-");
        try {
            Path app=temp.resolve("files");
            Files.createDirectories(app);
            if(!G2EGuestGlibcAssets.STAGED.equals(
                 G2EGuestGlibcAssets.stage(app.toFile(),provider)))
                throw new AssertionError("First hash-proven asset staging not acknowledged");
            if(!G2EGuestGlibcAssets.ALREADY.equals(
                 G2EGuestGlibcAssets.stage(app.toFile(),provider)))
                throw new AssertionError("Already installed guest not independently verified");
            if(!G2EGuestGlibcAssets.attestAppPrivate(app.toFile())
                    .contains("ALL_THREE_SHA256_VERIFIED"))
                throw new AssertionError("MIT private tree not verified");
            Path root=app.resolve("kernix/runtime-v1/guest-rootfs/g2e-glibc-v1");
            try(Stream<Path> list=Files.walk(root)) {
                if(list.filter(Files::isRegularFile).count()!=3)
                    throw new AssertionError("Expected only 3 pinned ELF files");
            }
            // Simulate existing v0.25 Android app-owned directories with
            // a permissive umask; in-place update must tighten only KERNIX
            // trees, never delete or mutate the verified original guest ELF.
            Path rootParent=app.resolve("kernix/runtime-v1/guest-rootfs");
            Set<PosixFilePermission> ownerOnly=EnumSet.of(
                PosixFilePermission.OWNER_READ,
                PosixFilePermission.OWNER_WRITE,
                PosixFilePermission.OWNER_EXECUTE);
            Set<PosixFilePermission> groupWrite=EnumSet.of(
                PosixFilePermission.OWNER_READ,
                PosixFilePermission.OWNER_WRITE,
                PosixFilePermission.OWNER_EXECUTE,
                PosixFilePermission.GROUP_READ,
                PosixFilePermission.GROUP_WRITE,
                PosixFilePermission.GROUP_EXECUTE);
            Files.setPosixFilePermissions(app,groupWrite); // framework root
            Files.setPosixFilePermissions(rootParent,groupWrite);
            Files.setPosixFilePermissions(root.resolve("lib"),groupWrite);
            if(!G2EGuestGlibcAssets.ALREADY.equals(
                    G2EGuestGlibcAssets.stage(app.toFile(),provider)))
                throw new AssertionError("Previous SHA-attested assets not accepted");
            if(!Files.getPosixFilePermissions(rootParent).equals(ownerOnly) ||
               !Files.getPosixFilePermissions(root.resolve("lib")).equals(ownerOnly) ||
               !Files.getPosixFilePermissions(root).equals(ownerOnly))
                throw new AssertionError("KERNIX app-created roots not restricted to 0700");
            if(!Files.getPosixFilePermissions(app).equals(groupWrite))
                throw new AssertionError("Android-managed getFilesDir modified");
            for(String name:G2EGuestGlibcAssets.PATHS){
                byte[] signed=Files.readAllBytes(source.resolve(name));
                byte[] present=Files.readAllBytes(root.resolve(name));
                if(!java.util.Arrays.equals(signed,present))
                    throw new AssertionError("Signed original x86 guest bytes changed");
            }
            Path bin=root.resolve("bin/kernix-g2e-dynamic-guest");
            if(!bin.toFile().setWritable(true,true))
                throw new IOException("Test cannot mutate disposable installed ELF");
            byte[] original=Files.readAllBytes(bin);
            byte[] changed=original.clone();
            changed[128]^=0x20;
            Files.write(bin,changed);
            reject(()->G2EGuestGlibcAssets.stage(app.toFile(),provider),
                   "pre-existing tampered guest overwritten");
            reject(()->G2EGuestGlibcAssets.attestAppPrivate(app.toFile()),
                   "installed binary changed");

            Path other=temp.resolve("new-files");
            Files.createDirectories(other);
            G2EGuestGlibcAssets.InputProvider bad = name -> {
                byte[] data=Files.readAllBytes(source.resolve(name));
                if(name.equals(G2EGuestGlibcAssets.PATHS[1]))data[150]^=1;
                return new ByteArrayInputStream(data);
            };
            reject(()->G2EGuestGlibcAssets.stage(other.toFile(),bad),
                   "modified signed APK asset bytes");
            if(Files.exists(other.resolve("kernix/runtime-v1/guest-rootfs/g2e-glibc-v1")))
                throw new AssertionError("Partial guest installed on invalid source");
            reject(()->G2EGuestGlibcAssets.stage(other.toFile(),
                name->null),"missing asset stream");
            if(Files.exists(other.resolve("kernix/runtime-v1/guest-rootfs/g2e-glibc-v1")))
                throw new AssertionError("Partial guest installed on missing stream");

            Path redirected=temp.resolve("linked-files");
            Files.createDirectory(redirected);
            Files.createSymbolicLink(redirected.resolve("kernix"),
                                     app.resolve("kernix"));
            reject(()->G2EGuestGlibcAssets.stage(redirected.toFile(),provider),
                   "app-private ancestor symlink");
            G2EGuestGlibcAssets.InputProvider valid = provider;
            Path empty=temp.resolve("empty-files");
            Files.createDirectory(empty);
            if(!G2EGuestGlibcAssets.STAGED.equals(
                    G2EGuestGlibcAssets.stage(empty.toFile(),valid)))
                throw new AssertionError("Valid signed source blocked after hostile cases");
            System.out.println(
                "KERNIX_G2E_JAVA_SIGNED_GLIBC_ASSET_PRIVATE_SHA256_STAGING_TAMPER_REJECT_PASS_NO_FEX");
        } finally {
            deleteTree(temp);
        }
    }
}
