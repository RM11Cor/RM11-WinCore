package org.kernix.host;

import java.nio.file.Files;
import java.nio.file.Path;
import java.io.IOException;

public final class FexCoreLoadProbeTest {
    static void check(boolean condition) {
        if (!condition) throw new AssertionError("FEXCore Android loader policy regression");
    }
    public static void main(String[] args) throws Exception {
        check(FexCoreLoadProbe.verified(0, FexCoreLoadProbe.MARKER));
        check(!FexCoreLoadProbe.verified(1, FexCoreLoadProbe.MARKER));
        check(!FexCoreLoadProbe.verified(0, FexCoreLoadProbe.MARKER + "extra"));
        check(!FexCoreLoadProbe.verified(0, FexCoreLoadProbe.MARKER.trim()));
        Path root=Files.createTempDirectory("kernix-fexcore-load-proof-");
        boolean rejected=false;
        try { FexCoreLoadProbe.resolve(root.toFile(), "other.so"); }
        catch(IOException e) { rejected=true; }
        check(rejected);
        rejected=false;
        try { FexCoreLoadProbe.resolve(root.toFile(), "libFEXCore.so"); }
        catch(IOException e) { rejected=true; }
        check(rejected);
        Path destination=Files.writeString(root.resolve("target"), "does not execute");
        Files.createSymbolicLink(root.resolve("libFEXCore.so"),destination);
        rejected=false;
        try { FexCoreLoadProbe.resolve(root.toFile(), "libFEXCore.so"); }
        catch(IOException e) { rejected=true; }
        check(rejected);
        check(FexCoreLoadProbe.run(root.toFile()).startsWith("FEXCORE_ANDROID_LOAD_FAIL"));
        System.out.println("KERNIX_FIXED_SIGNED_APK_FEXCORE_LOADER_POLICY_PASS");
    }
}
