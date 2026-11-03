package org.kernix.host;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

public final class FixedX86WriteProbeTest {
    static void check(boolean value) {
        if (!value) throw new AssertionError("Fixed guest memory pointer/write syscall proof regression");
    }

    public static void main(String[] args) throws Exception {
        check(FixedX86WriteProbe.verified(0, FixedX86WriteProbe.SUCCESS));
        check(!FixedX86WriteProbe.verified(1, FixedX86WriteProbe.SUCCESS));
        check(!FixedX86WriteProbe.verified(0, FixedX86WriteProbe.SUCCESS+"extra"));
        check(!FixedX86WriteProbe.verified(0, FixedX86WriteProbe.SUCCESS.trim()));
        Path root=Files.createTempDirectory("kernix-fixed-x86-memory-write-probe-");
        boolean rejected=false;
        try { FixedX86WriteProbe.resolve(root.toFile(),"arbitrary.exe"); }
        catch(IOException expected) { rejected=true; }
        check(rejected);
        Path target=Files.writeString(root.resolve("outside"),"no execution");
        Files.createSymbolicLink(root.resolve(FixedX86WriteProbe.BINARY),target);
        rejected=false;
        try { FixedX86WriteProbe.resolve(root.toFile(),FixedX86WriteProbe.BINARY); }
        catch(IOException expected) { rejected=true; }
        check(rejected);
        check(FixedX86WriteProbe.run(root.toFile()).startsWith("KERNIX_X86_MEMORY_WRITE_BRIDGE_EXEC_FAIL"));
        System.out.println("KERNIX_FIXED_X86_GUEST_WRITE_GETPID_MEMORY_BRIDGE_BOUNDARY_PASS");
    }
}
