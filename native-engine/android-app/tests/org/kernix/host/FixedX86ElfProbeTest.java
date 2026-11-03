package org.kernix.host;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

public final class FixedX86ElfProbeTest {
    static void check(boolean value) {
        if (!value) throw new AssertionError("Fixed guest memory pointer/write syscall proof regression");
    }

    public static void main(String[] args) throws Exception {
        check(FixedX86ElfProbe.verified(0, FixedX86ElfProbe.SUCCESS));
        check(!FixedX86ElfProbe.verified(1, FixedX86ElfProbe.SUCCESS));
        check(!FixedX86ElfProbe.verified(0, FixedX86ElfProbe.SUCCESS+"extra"));
        check(!FixedX86ElfProbe.verified(0, FixedX86ElfProbe.SUCCESS.trim()));
        Path root=Files.createTempDirectory("kernix-fixed-x86-elf64-probe-");
        boolean rejected=false;
        try { FixedX86ElfProbe.resolve(root.toFile(),"arbitrary.exe"); }
        catch(IOException expected) { rejected=true; }
        check(rejected);
        Path target=Files.writeString(root.resolve("outside"),"no execution");
        Files.createSymbolicLink(root.resolve(FixedX86ElfProbe.BINARY),target);
        rejected=false;
        try { FixedX86ElfProbe.resolve(root.toFile(),FixedX86ElfProbe.BINARY); }
        catch(IOException expected) { rejected=true; }
        check(rejected);
        check(FixedX86ElfProbe.run(root.toFile()).startsWith("KERNIX_X86_ELF64_EXEC_FAIL"));
        System.out.println("KERNIX_FIXED_GENUINE_X86_ELF64_NATIVE_FEX_PROOF_BOUNDARY_PASS");
    }
}
