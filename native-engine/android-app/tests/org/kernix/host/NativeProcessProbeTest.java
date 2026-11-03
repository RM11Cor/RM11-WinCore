package org.kernix.host;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.EnumSet;

public final class NativeProcessProbeTest {
    static void check(boolean condition, String reason) {
        if (!condition) throw new AssertionError(reason);
    }
    public static void main(String[] args) throws Exception {
        check(NativeProcessProbe.verified(0, NativeProcessProbe.EXPECTED + "\n"),
              "correct verified proof rejected");
        check(!NativeProcessProbe.verified(1, NativeProcessProbe.EXPECTED + "\n"),
              "nonzero exit accepted");
        check(!NativeProcessProbe.verified(0, NativeProcessProbe.EXPECTED),
              "missing LF accepted");
        check(!NativeProcessProbe.verified(0, NativeProcessProbe.EXPECTED + "\nextra"),
              "extra stdout accepted");
        Path dir = Files.createTempDirectory("kernix-native-lib-proof-");
        try {
            boolean rejected = false;
            try { NativeProcessProbe.resolve(dir.toFile()); }
            catch (IOException expected) { rejected = true; }
            check(rejected, "missing APK native executable accepted");
            Path proof = Files.writeString(dir.resolve(NativeProcessProbe.FILE_NAME), "fixture");
            Files.setPosixFilePermissions(proof, EnumSet.of(PosixFilePermission.OWNER_READ,
                           PosixFilePermission.OWNER_EXECUTE));
            check(NativeProcessProbe.resolve(dir.toFile()).getName()
                  .equals(NativeProcessProbe.FILE_NAME), "fixed filename not resolved");
            Files.delete(proof);
            Path other = Files.writeString(dir.resolve("elsewhere"), "not executed");
            Files.createSymbolicLink(proof, other);
            rejected = false;
            try { NativeProcessProbe.resolve(dir.toFile()); }
            catch (IOException expected) { rejected = true; }
            check(rejected, "symlink to another file accepted");
            check(NativeProcessProbe.run(dir.toFile()).startsWith("ANDROID_NATIVE_PROCESS_FAIL"),
                  "unverified symlink executed");
        } finally {
            // Test fixture only; never touch Android device paths.
        }
        System.out.println("KERNIX_ANDROID_FIXED_APK_BIONIC_PROCESS_BOUNDARY_PASS");
    }
}
