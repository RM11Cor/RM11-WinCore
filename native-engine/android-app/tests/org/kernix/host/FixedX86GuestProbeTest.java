package org.kernix.host;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

public final class FixedX86GuestProbeTest {
    static void check(boolean value) {
        if (!value) throw new AssertionError("Fixed x86 guest proof regression");
    }

    public static void main(String[] args) throws Exception {
        check(FixedX86GuestProbe.verified(0, FixedX86GuestProbe.SUCCESS));
        check(!FixedX86GuestProbe.verified(1, FixedX86GuestProbe.SUCCESS));
        check(!FixedX86GuestProbe.verified(0, FixedX86GuestProbe.SUCCESS+"extra"));
        check(!FixedX86GuestProbe.verified(0, FixedX86GuestProbe.SUCCESS.trim()));
        Path root=Files.createTempDirectory("kernix-fixed-x86-probe-");
        boolean rejected=false;
        try { FixedX86GuestProbe.resolve(root.toFile(),"arbitrary.exe"); }
        catch(IOException expected) { rejected=true; }
        check(rejected);
        Path target=Files.writeString(root.resolve("outside"),"no execution");
        Files.createSymbolicLink(root.resolve(FixedX86GuestProbe.BINARY),target);
        rejected=false;
        try { FixedX86GuestProbe.resolve(root.toFile(),FixedX86GuestProbe.BINARY); }
        catch(IOException expected) { rejected=true; }
        check(rejected);
        check(FixedX86GuestProbe.run(root.toFile()).startsWith("KERNIX_X86_GUEST_EXEC_FAIL"));
        System.out.println("KERNIX_FIXED_X86_GUEST_EXECUTION_PROOF_BOUNDARY_PASS");
    }
}
