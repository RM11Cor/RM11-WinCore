package org.kernix.host;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

/** No Android process is spawned: deterministic child-supervisor contract. */
public final class G2CAndroidChildSupervisorTest {
    private static final class FakeProcess extends Process {
        final int code;
        final boolean hang;
        final InputStream out, err;
        boolean killed;
        FakeProcess(int code, boolean hang, String stdout, String stderr) {
            this.code = code;
            this.hang = hang;
            this.out = new ByteArrayInputStream(stdout.getBytes(StandardCharsets.UTF_8));
            this.err = new ByteArrayInputStream(stderr.getBytes(StandardCharsets.UTF_8));
        }
        @Override public OutputStream getOutputStream() { return new ByteArrayOutputStream(); }
        @Override public InputStream getInputStream() { return out; }
        @Override public InputStream getErrorStream() { return err; }
        @Override public int waitFor() { return code; }
        @Override public boolean waitFor(long timeout, TimeUnit unit) { return !hang; }
        @Override public int exitValue() { return code; }
        @Override public void destroy() { killed = true; }
        @Override public Process destroyForcibly() { killed = true; return this; }
        @Override public boolean isAlive() { return hang && !killed; }
    }

    private static void expect(String actual, String expected) {
        if (!expected.equals(actual))
            throw new AssertionError("Expected " + expected + ", got: " + actual);
    }

    private static void mustReject(Path root) throws Exception {
        try {
            G2CFixedGuestFixture.attestAppPrivate(root.toFile());
            throw new AssertionError("Escaped private fixture accepted");
        } catch (IOException expected) {
            // expected
        }
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 1) throw new AssertionError("Expected verified G2-C fixture");
        if (G2CAndroidChildSupervisor.approved())
            throw new AssertionError("Unqualified G2-C runner accidentally enabled");
        if (!G2CAndroidChildSupervisor.CANDIDATE_FLAG.equals(
            "--kernix-g2c-execute-fixed-snapshot-direct-entry-v1"))
            throw new AssertionError("Java and native G2-C candidate command disagree");
        expect(G2CAndroidChildSupervisor.run(null, null),
               G2CAndroidChildSupervisor.GATE_CLOSED);
        if (!G2CAndroidChildSupervisor.verified(0, false,
                G2CAndroidChildSupervisor.PASS_STDOUT, "")) {
            throw new AssertionError("Exact test marker semantics changed");
        }
        if (G2CAndroidChildSupervisor.verified(0, false,
                G2CAndroidChildSupervisor.PASS_STDOUT + "junk\n", "") ||
            G2CAndroidChildSupervisor.verified(1, false,
                G2CAndroidChildSupervisor.PASS_STDOUT, "") ||
            G2CAndroidChildSupervisor.verified(0, true,
                G2CAndroidChildSupervisor.PASS_STDOUT, "") ||
            G2CAndroidChildSupervisor.verified(0, false,
                G2CAndroidChildSupervisor.PASS_STDOUT,
                "KERNIX_G2C_UNEXPECTED_GUEST_SYSCALL_REJECTED")) {
            throw new AssertionError("Ambiguous child evidence accepted");
        }

        FakeProcess ok = new FakeProcess(0, false,
                G2CAndroidChildSupervisor.PASS_STDOUT, "");
        expect(G2CAndroidChildSupervisor.supervise(ok),
               "KERNIX_G2C_ANDROID_CHILD_EXACT_MARKER_PASS");
        if (!ok.killed) throw new AssertionError("Child not reaped after pass");

        FakeProcess wrong = new FakeProcess(0, false,
                G2CAndroidChildSupervisor.PASS_STDOUT + "extra", "");
        expect(G2CAndroidChildSupervisor.supervise(wrong),
               "KERNIX_G2C_ANDROID_CHILD_REJECTED_EXIT_OR_MARKER");

        FakeProcess failed = new FakeProcess(6, false,
                G2CAndroidChildSupervisor.PASS_STDOUT, "");
        expect(G2CAndroidChildSupervisor.supervise(failed),
               "KERNIX_G2C_ANDROID_CHILD_REJECTED_EXIT_OR_MARKER");

        FakeProcess hung = new FakeProcess(0, true,
                G2CAndroidChildSupervisor.PASS_STDOUT, "");
        expect(G2CAndroidChildSupervisor.supervise(hung),
               "KERNIX_G2C_ANDROID_CHILD_TIMEOUT_8S_NO_GUEST_PASS");
        if (!hung.killed) throw new AssertionError("Timed-out child survived");

        FakeProcess overflow = new FakeProcess(0, false, "x".repeat(2500), "");
        expect(G2CAndroidChildSupervisor.supervise(overflow),
               "KERNIX_G2C_ANDROID_CHILD_OUTPUT_OR_PIPE_REJECTED");

        String pageRecord = "KERNIX_G2C_ANDROID_PAGE_PREFLIGHT_V1\n" +
                "ABI=aarch64\nHOST_PAGE_BYTES=16384\n" +
                "PROT_NONE_RESERVATION=1\nPROT_READ_TRANSITION=1\n" +
                "GUEST_EXECUTED=0\nFEX_EXECUTED=0\nWINE_EXECUTED=0\n";
        String pagePass = G2CAndroidChildSupervisor.supervisePageOnly(
                new FakeProcess(0,false,pageRecord,""));
        if (!pagePass.contains("KERNIX_G2C_ANDROID_PAGE_CHILD_8S_PASS_NO_FEX") ||
            !pagePass.contains("HOST_PAGE_BYTES=16384\n"))
            throw new AssertionError("Valid 16 KiB Bionic-only page witness rejected");
        expect(G2CAndroidChildSupervisor.supervise(
                new FakeProcess(0,false,pageRecord,"")),
               "KERNIX_G2C_ANDROID_CHILD_REJECTED_EXIT_OR_MARKER");
        expect(G2CAndroidChildSupervisor.supervisePageOnly(
                new FakeProcess(0,false,pageRecord.replace(
                    "HOST_PAGE_BYTES=16384","HOST_PAGE_BYTES=65536"),"")),
               "KERNIX_G2C_ANDROID_CHILD_REJECTED_EXIT_OR_MARKER");
        expect(G2CAndroidChildSupervisor.supervisePageOnly(
                new FakeProcess(0,false,pageRecord,"unexpected stderr")),
               "KERNIX_G2C_ANDROID_CHILD_REJECTED_EXIT_OR_MARKER");
        expect(G2CAndroidChildSupervisor.supervisePageOnly(
                new FakeProcess(3,false,pageRecord,"")),
               "KERNIX_G2C_ANDROID_CHILD_REJECTED_EXIT_OR_MARKER");
        if (G2CAndroidPageProbe.BINARY.equals(G2CAndroidChildSupervisor.RUNNER))
            throw new AssertionError("Data-only and FEX runner identities conflated");

        Path temp = Files.createTempDirectory("kernix-g2c-private-");
        try {
            Path appRoot = temp.resolve("app-private-files");
            Path fixture = appRoot.resolve(
                    "kernix/runtime-v1/guest-rootfs/g2c-fixed-v1");
            Files.createDirectories(fixture);
            Path source = Path.of(args[0]);
            try (Stream<Path> stream = Files.walk(source)) {
                for (Path file : (Iterable<Path>) stream::iterator) {
                    Path target = fixture.resolve(source.relativize(file));
                    if (Files.isDirectory(file)) {
                        Files.createDirectories(target);
                    } else {
                        Files.copy(file, target, StandardCopyOption.REPLACE_EXISTING);
                    }
                }
            }
            expect(G2CFixedGuestFixture.attestAppPrivate(appRoot.toFile()),
                  "KERNIX_G2C_ANDROID_FIXED_FIXTURE_BYTES_VERIFIED_NOT_DEVICE_EXECUTED");
            mustReject(fixture);
            Path link = appRoot.resolve("kernix/runtime-v1/guest-rootfs/other");
            Files.createSymbolicLink(link, fixture);
            mustReject(link);
            if (!Files.isRegularFile(fixture.resolve("bin/kernix-dynamic-app")))
                throw new AssertionError("Test bundle missing");
            expect(G2CAndroidChildSupervisor.run(appRoot.toFile(), temp.toFile()),
                   G2CAndroidChildSupervisor.GATE_CLOSED);
        } finally {
            try (Stream<Path> stream = Files.walk(temp)) {
                stream.sorted((a,b)->b.getNameCount()-a.getNameCount()).forEach(p -> {
                    try { Files.deleteIfExists(p); }
                    catch (IOException e) { throw new RuntimeException(e); }
                });
            }
        }
        System.out.println("KERNIX_G2C_ANDROID_ISOLATED_CHILD_SUPERVISOR_JVM_PASS_NOT_DEVICE_RUN");
    }
}
