package org.kernix.host;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.stream.Stream;

/** CI-only source staging proof; NEVER launches x86, FEX, Wine or games. */
public final class G2DGuestAssetsTest {
    private static void reject(Action test,String label)throws Exception {
        try { test.run(); }
        catch(IOException expected) { return; }
        throw new AssertionError("Unsafe MIT 16KiB input accepted: "+label);
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
        if(args.length!=1)throw new AssertionError("Expected MIT 16KiB guest root");
        final Path source=Path.of(args[0]);
        final G2DGuestAssets.InputProvider provider =
            name -> Files.newInputStream(source.resolve(name));
        Path temp=Files.createTempDirectory("kernix-g2d-mit-import-java-");
        try {
            Path app=temp.resolve("files");
            Files.createDirectories(app);
            if(!G2DGuestAssets.STAGED.equals(
                 G2DGuestAssets.stage(app.toFile(),provider)))
                throw new AssertionError("First hash-proven asset staging not acknowledged");
            if(!G2DGuestAssets.ALREADY.equals(
                 G2DGuestAssets.stage(app.toFile(),provider)))
                throw new AssertionError("Already installed guest not independently verified");
            if(!G2DGuestAssets.attestAppPrivate(app.toFile())
                    .contains("ALL_THREE_SHA256_VERIFIED"))
                throw new AssertionError("MIT private tree not verified");
            Path root=app.resolve("kernix/runtime-v1/guest-rootfs/g2d-import-v1");
            try(Stream<Path> list=Files.walk(root)) {
                if(list.filter(Files::isRegularFile).count()!=3)
                    throw new AssertionError("Expected only 3 MIT ELF files");
            }
            Path bin=root.resolve("bin/kernix-g2d-import-app");
            if(!bin.toFile().setWritable(true,true))
                throw new IOException("Test cannot mutate disposable installed ELF");
            byte[] original=Files.readAllBytes(bin);
            byte[] changed=original.clone();
            changed[128]^=0x20;
            Files.write(bin,changed);
            reject(()->G2DGuestAssets.stage(app.toFile(),provider),
                   "pre-existing tampered guest overwritten");
            reject(()->G2DGuestAssets.attestAppPrivate(app.toFile()),
                   "installed binary changed");

            Path other=temp.resolve("new-files");
            Files.createDirectories(other);
            G2DGuestAssets.InputProvider bad = name -> {
                byte[] data=Files.readAllBytes(source.resolve(name));
                if(name.equals(G2DGuestAssets.PATHS[1]))data[150]^=1;
                return new ByteArrayInputStream(data);
            };
            reject(()->G2DGuestAssets.stage(other.toFile(),bad),
                   "modified signed APK asset bytes");
            if(Files.exists(other.resolve("kernix/runtime-v1/guest-rootfs/g2d-import-v1")))
                throw new AssertionError("Partial guest installed on invalid source");
            reject(()->G2DGuestAssets.stage(other.toFile(),
                name->null),"missing asset stream");
            if(Files.exists(other.resolve("kernix/runtime-v1/guest-rootfs/g2d-import-v1")))
                throw new AssertionError("Partial guest installed on missing stream");

            Path redirected=temp.resolve("linked-files");
            Files.createDirectory(redirected);
            Files.createSymbolicLink(redirected.resolve("kernix"),
                                     app.resolve("kernix"));
            reject(()->G2DGuestAssets.stage(redirected.toFile(),provider),
                   "app-private ancestor symlink");
            G2DGuestAssets.InputProvider valid = provider;
            Path empty=temp.resolve("empty-files");
            Files.createDirectory(empty);
            if(!G2DGuestAssets.STAGED.equals(
                    G2DGuestAssets.stage(empty.toFile(),valid)))
                throw new AssertionError("Valid signed source blocked after hostile cases");
            System.out.println(
                "KERNIX_G2D_MIT_IMPORT_JAVA_SIGNED_ASSET_PRIVATE_SHA256_STAGING_TAMPER_REJECT_PASS_NO_FEX");
        } finally {
            deleteTree(temp);
        }
    }
}
