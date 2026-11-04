package org.kernix.host;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.stream.Stream;

/** CI-only real app-private file handoff, NEVER x86/FEX runtime execution. */
public final class G2CPrivateFixtureStagerTest {
    private static void rejected(File source, File app, String message) throws Exception {
        try {
            G2CPrivateFixtureStager.stageVerifiedOnly(source,app);
        } catch(IOException expected) {
            return;
        }
        throw new AssertionError("Unsafe G2-C guest handoff accepted: "+message);
    }

    private static void deleteTree(Path folder) throws Exception {
        if (!Files.exists(folder)) return;
        try (Stream<Path> files=Files.walk(folder)) {
            for (Path p : (Iterable<Path>) files.sorted(
                   (a,b)->Integer.compare(b.getNameCount(),a.getNameCount()))::iterator)
                Files.deleteIfExists(p);
        }
    }

    public static void main(String[] args) throws Exception {
        if(args.length!=1) throw new AssertionError("Expected vetted fixture directory");
        File source=Path.of(args[0]).toAbsolutePath().toFile();
        Path temp=Files.createTempDirectory("kernix-g2c-stager-");
        try {
            Path app=temp.resolve("files");
            Files.createDirectory(app);
            String first=G2CPrivateFixtureStager.stageVerifiedOnly(source,app.toFile());
            if (!G2CPrivateFixtureStager.STAGED_PASS.equals(first))
                throw new AssertionError("Expected first private handoff");
            String second=G2CPrivateFixtureStager.stageVerifiedOnly(source,app.toFile());
            if (!G2CPrivateFixtureStager.ALREADY_PASS.equals(second))
                throw new AssertionError("Expected idempotent verified private handoff");
            G2CFixedGuestFixture.attestAppPrivate(app.toFile());
            Path finalRoot=app.resolve("kernix/runtime-v1/guest-rootfs/g2c-fixed-v1");
            Path main=finalRoot.resolve("bin/kernix-dynamic-app");
            if (Files.getPosixFilePermissions(main).contains(PosixFilePermission.OWNER_WRITE))
                throw new AssertionError("Guest binary left writable");
            try (Stream<Path> dir=Files.list(finalRoot.getParent())) {
                if (dir.filter(p->p.getFileName().toString()
                                .startsWith(".kernix-g2c-private-stage-")).count()!=0)
                    throw new AssertionError("Temporary install contents left behind");
            }
            Path original=main;
            if (!original.toFile().setWritable(true,true))
                throw new IOException("Cannot modify disposable test copy");
            byte[] bytes=Files.readAllBytes(main);
            bytes[100]^=1;
            Files.write(main,bytes);
            rejected(source,app.toFile(),"tampered installed ELF must not be overwritten");

            Path blocked=temp.resolve("blocked-app");
            Files.createDirectory(blocked);
            Files.createSymbolicLink(blocked.resolve("kernix"),app.resolve("kernix"));
            rejected(source,blocked.toFile(),"app folder with a redirected child symlink");

            Path badSource=temp.resolve("source/g2c-fixed-v1");
            Files.createDirectories(badSource.getParent());
            try(Stream<Path> srcFiles=Files.walk(source.toPath())) {
                for(Path file:(Iterable<Path>)srcFiles::iterator) {
                    Path to=badSource.resolve(source.toPath().relativize(file));
                    if(Files.isDirectory(file)) Files.createDirectories(to);
                    else Files.copy(file,to);
                }
            }
            Path libc=badSource.resolve("lib/x86_64-linux-gnu/libc.so.6");
            if (!libc.toFile().setWritable(true,true))
                throw new IOException("Cannot tamper disposable source");
            byte[] libcBytes=Files.readAllBytes(libc);
            libcBytes[101]^=0x20;
            Files.write(libc,libcBytes);
            Path rejectedApp=temp.resolve("rejected-app");
            Files.createDirectory(rejectedApp);
            rejected(badSource.toFile(),rejectedApp.toFile(),"tampered source ELF");
            if (Files.exists(rejectedApp.resolve("kernix")))
                throw new AssertionError("Tampered source unexpectedly created rootfs");
            System.out.println(
                "KERNIX_G2C_ATTESTED_APP_PRIVATE_SIX_FILE_STAGING_AND_NO_SYMLINK_PASS_NO_FEX_DEVICE");
        } finally {
            deleteTree(temp);
        }
    }
}
