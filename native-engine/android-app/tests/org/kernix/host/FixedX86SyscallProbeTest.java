package org.kernix.host;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

public final class FixedX86SyscallProbeTest {
    static void check(boolean value) {
        if (!value) throw new AssertionError("Fixed x86 guest proof regression");
    }

    public static void main(String[] args) throws Exception {
        check(FixedX86SyscallProbe.verified(0, FixedX86SyscallProbe.SUCCESS));
        check(!FixedX86SyscallProbe.verified(1, FixedX86SyscallProbe.SUCCESS));
        check(!FixedX86SyscallProbe.verified(0, FixedX86SyscallProbe.SUCCESS+"extra"));
        check(!FixedX86SyscallProbe.verified(0, FixedX86SyscallProbe.SUCCESS.trim()));
        Path root=Files.createTempDirectory("kernix-fixed-x86-syscall-probe-");
        boolean rejected=false;
        try { FixedX86SyscallProbe.resolve(root.toFile(),"arbitrary.exe"); }
        catch(IOException expected) { rejected=true; }
        check(rejected);
        Path target=Files.writeString(root.resolve("outside"),"no execution");
        Files.createSymbolicLink(root.resolve(FixedX86SyscallProbe.BINARY),target);
        rejected=false;
        try { FixedX86SyscallProbe.resolve(root.toFile(),FixedX86SyscallProbe.BINARY); }
        catch(IOException expected) { rejected=true; }
        check(rejected);
        check(FixedX86SyscallProbe.run(root.toFile()).startsWith("KERNIX_X86_SYSCALL_BRIDGE_EXEC_FAIL"));
        System.out.println("KERNIX_FIXED_X86_GETPID_SYSCALL_BRIDGE_PROOF_BOUNDARY_PASS");
    }
}
