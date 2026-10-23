package com.rm11.autocore.runtime;

import org.junit.Test;
import static org.junit.Assert.*;
import java.nio.file.Files;
import java.nio.file.Path;

public final class WineUnixLibProbeTest {
    @Test public void rejectsMissingOrWrongArchitectures() throws Exception {
        Path root=Files.createTempDirectory("rm11-unixlib-");
        assertEquals("MISSING",WineUnixLibProbe.checkElfArm64(root.resolve("missing.so")));
        byte[] file=new byte[1500];
        Files.write(root.resolve("bad.so"),file);
        assertEquals("NOT_64_BIT_ELF",WineUnixLibProbe.checkElfArm64(root.resolve("bad.so")));
        file[0]=0x7f; file[1]='E';file[2]='L';file[3]='F';file[4]=2;file[5]=1;
        file[18]=(byte)0x3e; file[19]=0; // AMD64: must reject
        Files.write(root.resolve("wrong.so"),file);
        assertTrue(WineUnixLibProbe.checkElfArm64(root.resolve("wrong.so")).startsWith("WRONG_CPU_ARCH"));
        file[18]=(byte)0xb7; file[19]=0;
        Files.write(root.resolve("arm64.so"),file);
        assertTrue(WineUnixLibProbe.checkElfArm64(root.resolve("arm64.so")).startsWith("PRESENT_ARM64_ELF"));
    }
}
