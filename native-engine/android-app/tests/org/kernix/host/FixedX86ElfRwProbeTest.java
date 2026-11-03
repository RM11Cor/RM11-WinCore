package org.kernix.host;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

public final class FixedX86ElfRwProbeTest {
    static void check(boolean value) {
        if (!value) throw new AssertionError("Fixed guest memory pointer/write syscall proof regression");
    }

    public static void main(String[] args) throws Exception {
        check(FixedX86ElfRwProbe.verified(0, FixedX86ElfRwProbe.SUCCESS));
        check(!FixedX86ElfRwProbe.verified(1, FixedX86ElfRwProbe.SUCCESS));
        check(!FixedX86ElfRwProbe.verified(0, FixedX86ElfRwProbe.SUCCESS+"extra"));
        check(!FixedX86ElfRwProbe.verified(0, FixedX86ElfRwProbe.SUCCESS.trim()));
        Path root=Files.createTempDirectory("kernix-fixed-x86-elf64-probe-");
        boolean rejected=false;
        try { FixedX86ElfRwProbe.resolve(root.toFile(),"arbitrary.exe"); }
        catch(IOException expected) { rejected=true; }
        check(rejected);
        Path target=Files.writeString(root.resolve("outside"),"no execution");
        Files.createSymbolicLink(root.resolve(FixedX86ElfRwProbe.BINARY),target);
        rejected=false;
        try { FixedX86ElfRwProbe.resolve(root.toFile(),FixedX86ElfRwProbe.BINARY); }
        catch(IOException expected) { rejected=true; }
        check(rejected);
        check(FixedX86ElfRwProbe.run(root.toFile()).startsWith("KERNIX_X86_ELF64_RW_EXEC_FAIL"));
        System.out.println("KERNIX_X86_ELF64_RW_GUEST_MEMORY_AND_NATIVE_FEX_PROOF_BOUNDARY_PASS");
    }
}
