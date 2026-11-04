package org.kernix.host;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.stream.Stream;

/** JVM contract test for data-only fixed Android G2-C input validation. */
public final class G2CFixedGuestFixtureTest {
    private static void expectFailure(Path root) throws Exception {
        boolean rejected = false;
        try {
            G2CFixedGuestFixture.attest(root.toFile());
        } catch (IOException expected) {
            rejected = true;
        }
        if (!rejected) throw new AssertionError("Unsafe G2-C guest input accepted");
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 1) throw new AssertionError("Expected staged source root");
        Path source = Path.of(args[0]).toAbsolutePath().normalize();
        Path temporary = Files.createTempDirectory("kernix-g2c-jvm-");
        Path root = temporary.resolve("g2c-fixed-v1");
        Files.createDirectory(root);
        try {
            try (Stream<Path> stream = Files.walk(source)) {
                for (Path file : (Iterable<Path>) stream::iterator) {
                    Path rel = source.relativize(file);
                    Path to = root.resolve(rel);
                    if (Files.isDirectory(file)) {
                        Files.createDirectories(to);
                    } else {
                        Files.copy(file, to, StandardCopyOption.REPLACE_EXISTING);
                    }
                }
            }
            String pass = G2CFixedGuestFixture.attest(root.toFile());
            if (!pass.equals(
                    "KERNIX_G2C_ANDROID_FIXED_FIXTURE_BYTES_VERIFIED_NOT_DEVICE_EXECUTED"))
                throw new AssertionError("Unscoped Android proof");

            Path elf = root.resolve("bin/kernix-dynamic-app");
            byte[] original = Files.readAllBytes(elf);
            byte[] tampered = original.clone();
            tampered[100] ^= 0x01;
            Files.write(elf, tampered);
            expectFailure(root);
            Files.write(elf, original);

            Path extra = root.resolve("unexpected-guest");
            Files.writeString(extra, "untrusted");
            expectFailure(root);
            Files.delete(extra);

            Path linked = root.resolve("unexpected-link");
            Files.createSymbolicLink(linked, elf);
            expectFailure(root);
            Files.delete(linked);
            Files.delete(root.resolve("lib64/ld-linux-x86-64.so.2"));
            expectFailure(root);
            System.out.println("KERNIX_G2C_ANDROID_JVM_FIXED_GUEST_HARD_REJECTION_PASS_NOT_DEVICE");
        } finally {
            try (Stream<Path> stream = Files.walk(temporary)) {
                stream.sorted((a,b)->b.getNameCount()-a.getNameCount()).forEach(p->{
                    try { Files.deleteIfExists(p); }
                    catch (IOException err) { throw new RuntimeException(err); }
                });
            }
        }
    }
}
