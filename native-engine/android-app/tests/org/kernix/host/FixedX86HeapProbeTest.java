package org.kernix.host;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

public final class FixedX86HeapProbeTest {
    static void check(boolean value) {
        if (!value) throw new AssertionError("Fixed guest memory pointer/write syscall proof regression");
    }

    public static void main(String[] args) throws Exception {
        check(FixedX86HeapProbe.verified(0, FixedX86HeapProbe.SUCCESS));
        check(!FixedX86HeapProbe.verified(1, FixedX86HeapProbe.SUCCESS));
        check(!FixedX86HeapProbe.verified(0, FixedX86HeapProbe.SUCCESS+"extra"));
        check(!FixedX86HeapProbe.verified(0, FixedX86HeapProbe.SUCCESS.trim()));
        Path root=Files.createTempDirectory("kernix-fixed-x86-elf64-probe-");
        boolean rejected=false;
        try { FixedX86HeapProbe.resolve(root.toFile(),"arbitrary.exe"); }
        catch(IOException expected) { rejected=true; }
        check(rejected);
        Path target=Files.writeString(root.resolve("outside"),"no execution");
        Files.createSymbolicLink(root.resolve(FixedX86HeapProbe.BINARY),target);
        rejected=false;
        try { FixedX86HeapProbe.resolve(root.toFile(),FixedX86HeapProbe.BINARY); }
        catch(IOException expected) { rejected=true; }
        check(rejected);
        check(FixedX86HeapProbe.run(root.toFile()).startsWith("KERNIX_X86_ELF64_HEAP_EXEC_FAIL"));
        System.out.println("KERNIX_X86_ELF64_HEAP_MEMORY_FOUR_SYSCALL_BOUNDARY_PASS");
    }
}
