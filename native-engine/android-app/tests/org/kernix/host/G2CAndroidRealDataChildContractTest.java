package org.kernix.host;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.stream.Stream;

/**
 * Executes one real Linux host child process in CI, never an Android guest,
 * x86 code, FEX, dynamic loader or game. Tests Android Java ProcessBuilder
 * supervision against actual exit/stdout/stderr/failures, not FakeProcess.
 */
public final class G2CAndroidRealDataChildContractTest {
    private static void expect(String actual, String expected) {
        if (!expected.equals(actual))
            throw new AssertionError("Expected " + expected + " but got " + actual);
    }

    private static Process spawn(Path nativeHostChild, Path appPrivate,
                                 String argument) throws IOException {
        ProcessBuilder pb = new ProcessBuilder(nativeHostChild.toString(),
                                              argument, appPrivate.toString());
        pb.environment().clear();
        return pb.start();
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 2)
            throw new AssertionError("Expected Linux CI native binary and staged x86 fixture");
        Path binary = Path.of(args[0]).toRealPath();
        Path source = Path.of(args[1]).toRealPath();
        if (!Files.isRegularFile(binary) || !Files.isExecutable(binary))
            throw new AssertionError("Actual CI child executable not found");
        Path temp = Files.createTempDirectory("kernix-g2c-real-child-");
        try {
            Path files = temp.resolve("app-private-files");
            Path fixture = files.resolve("kernix/runtime-v1/guest-rootfs/g2c-fixed-v1");
            Files.createDirectories(fixture);
            try (Stream<Path> walk = Files.walk(source)) {
                for (Path file : (Iterable<Path>) walk::iterator) {
                    Path destination = fixture.resolve(source.relativize(file));
                    if (Files.isDirectory(file)) {
                        Files.createDirectories(destination);
                    } else {
                        Files.copy(file, destination, StandardCopyOption.COPY_ATTRIBUTES);
                    }
                }
            }

            // Real kernel child + two real pipes, supervised by same Java class
            // used for the future Android process. Distinct data-only marker.
            expect(G2CAndroidChildSupervisor.superviseDataOnly(
                    spawn(binary, files, "--fixed-data-only-preflight")),
                   "KERNIX_G2C_ANDROID_CHILD_DATA_ONLY_WATCHDOG_PASS_NOT_FEX");

            // Same Linux C++ child also tests safe host page mapping:
            // 4K or 16K, PROT_NONE to PROT_READ only, never PROT_EXEC.
            // The Linux CI ABI marker is NOT accepted as device success.
            String page = G2CAndroidChildSupervisor.supervisePageOnly(
                    spawn(binary, files, "--android-host-page-preflight"));
            if (!page.startsWith("KERNIX_G2C_ANDROID_PAGE_CHILD_8S_PASS_NO_FEX\n") ||
                !page.contains("ABI=linux-host-ci\n") ||
                !page.contains("GUEST_EXECUTED=0\n") ||
                !page.contains("FEX_EXECUTED=0\n"))
                throw new AssertionError("Real native host page preflight failed: " + page);

            // Its real data-only output MUST be rejected as FEX success.
            expect(G2CAndroidChildSupervisor.supervise(
                    spawn(binary, files, "--fixed-data-only-preflight")),
                   "KERNIX_G2C_ANDROID_CHILD_REJECTED_EXIT_OR_MARKER");

            // No arbitrary CLI flags; even a correctly staged rootfs fails.
            expect(G2CAndroidChildSupervisor.superviseDataOnly(
                    spawn(binary, files, "--unexpected-command")),
                   "KERNIX_G2C_ANDROID_CHILD_REJECTED_EXIT_OR_MARKER");

            Path elf = fixture.resolve("bin/kernix-dynamic-app");
            byte[] original = Files.readAllBytes(elf);
            if (!elf.toFile().setWritable(true, true))
                throw new IOException("Cannot mutate disposable child fixture");
            byte[] changed = original.clone();
            changed[100] ^= 1;
            Files.write(elf, changed);
            if (!elf.toFile().setReadOnly())
                throw new IOException("Cannot seal disposable negative case");
            expect(G2CAndroidChildSupervisor.superviseDataOnly(
                    spawn(binary, files, "--fixed-data-only-preflight")),
                   "KERNIX_G2C_ANDROID_CHILD_REJECTED_EXIT_OR_MARKER");

            // Negative tests are REAL kernel children, not fake-process
            // simulations: one floods output, the other hangs indefinitely.
            expect(G2CAndroidChildSupervisor.superviseDataOnly(
                    spawn(binary, files, "--ci-overflow-stdout")),
                   "KERNIX_G2C_ANDROID_CHILD_OUTPUT_OR_PIPE_REJECTED");

            Process hung = spawn(binary, files, "--ci-hang-until-killed");
            expect(G2CAndroidChildSupervisor.superviseDataOnly(hung),
                   "KERNIX_G2C_ANDROID_CHILD_TIMEOUT_8S_NO_GUEST_PASS");
            if (hung.isAlive())
                throw new AssertionError("Actual timed-out native process survived");

            // Keep existing production gate CLOSED, even after data-only
            // child succeeds and a fake native executable is present.
            expect(G2CAndroidChildSupervisor.run(files.toFile(), binary.getParent().toFile()),
                   G2CAndroidChildSupervisor.GATE_CLOSED);
            System.out.println(
                "KERNIX_G2C_REAL_SEPARATE_PROCESS_DATA_ONLY_WATCHDOG_CONTRACT_PASS_NOT_ANDROID_FEX");
        } finally {
            try (Stream<Path> walk = Files.walk(temp)) {
                walk.sorted((a,b) -> b.getNameCount() - a.getNameCount())
                    .forEach(p -> {
                        try { Files.deleteIfExists(p); }
                        catch (IOException e) { throw new RuntimeException(e); }
                    });
            }
        }
    }
}
