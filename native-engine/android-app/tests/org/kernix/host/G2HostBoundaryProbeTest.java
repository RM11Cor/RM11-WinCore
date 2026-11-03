package org.kernix.host;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.EnumSet;

public final class G2HostBoundaryProbeTest {
    private static void require(boolean v, String reason) {
        if (!v) throw new AssertionError(reason);
    }
    private static final String PASS =
        "KERNIX_G2_BIONIC_HOST_BOUNDARY_V1\nABI=aarch64\n" +
        "PAGE_BYTES=16384\nSECCOMP_MODE=2\nNO_NEW_PRIVS=1\n" +
        "FEX_CORE_LOAD=1\nFEX_CONFIG_SYMBOL=1\nWINE_PE_EXECUTED=0\n";
    public static void main(String[] args) throws Exception {
        require(G2HostBoundaryProbe.verified(0, PASS), "valid exact proof rejected");
        require(G2HostBoundaryProbe.verified(0, PASS.replace("16384", "4096")),
                "4KiB Android page rejected");
        require(G2HostBoundaryProbe.verified(0,
                PASS.replace("SECCOMP_MODE=2", "SECCOMP_MODE=unknown")),
                "unreadable sandbox value rejected");
        require(!G2HostBoundaryProbe.verified(1, PASS), "nonzero process accepted");
        require(!G2HostBoundaryProbe.verified(0, PASS + "PE_EXECUTED=1\n"),
                "forged PE claim accepted");
        require(!G2HostBoundaryProbe.verified(0, PASS.replace("WINE_PE_EXECUTED=0",
                "WINE_PE_EXECUTED=1")), "unverified Windows execution accepted");
        require(!G2HostBoundaryProbe.verified(0,
                PASS.replace("FEX_CONFIG_SYMBOL=1", "FEX_CONFIG_SYMBOL=0")),
                "missing FEX exported symbol accepted");
        require(!G2HostBoundaryProbe.verified(0,
                PASS.replace("PAGE_BYTES=16384", "PAGE_BYTES=0")),
                "invalid page size accepted");
        require(!G2HostBoundaryProbe.verified(0, PASS.substring(0, PASS.length()-1)),
                "truncated stdout accepted");
        Path dir = Files.createTempDirectory("kernix-g2-host-boundary-");
        require(G2HostBoundaryProbe.run(dir.toFile()).startsWith(
                "KERNIX_G2_HOST_BOUNDARY_FAIL"), "missing signed native file accepted");
        Path run = Files.writeString(dir.resolve(G2HostBoundaryProbe.BINARY), "fixture");
        Path core = Files.writeString(dir.resolve(G2HostBoundaryProbe.CORE), "fixture");
        Files.setPosixFilePermissions(run, EnumSet.of(
            PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_EXECUTE));
        require(G2HostBoundaryProbe.resolve(dir.toFile(), G2HostBoundaryProbe.BINARY)
                .getName().equals(G2HostBoundaryProbe.BINARY), "valid runner rejected");
        require(G2HostBoundaryProbe.resolve(dir.toFile(), G2HostBoundaryProbe.CORE)
                .equals(core.toFile().getCanonicalFile()), "valid library rejected");
        Files.delete(run);
        Files.createSymbolicLink(run, core);
        boolean denied = false;
        try { G2HostBoundaryProbe.resolve(dir.toFile(), G2HostBoundaryProbe.BINARY); }
        catch (IOException expected) { denied = true; }
        require(denied, "symlink redirection accepted");
        denied = false;
        try { G2HostBoundaryProbe.resolve(dir.toFile(), "../other"); }
        catch (IOException expected) { denied = true; }
        require(denied, "arbitrary binary name accepted");
        System.out.println("KERNIX_G2_ANDROID_HOST_BOUNDARY_JAVA_CONTRACT_PASS_NOT_DEVICE_EXECUTION");
    }
}
