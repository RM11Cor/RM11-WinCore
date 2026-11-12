package com.fh5.port;

import org.junit.Test;
import static org.junit.Assert.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

public final class PeDllHeaderValidatorTest {
    static PeDllHeaderValidator.Result validate(byte[] bytes) throws Exception {
        Path f=Files.createTempFile("fh5-dll-pe",".dll");
        try {
            Files.write(f,bytes);
            try(SeekableByteChannel ch=Files.newByteChannel(f,StandardOpenOption.READ)) {
                return PeDllHeaderValidator.inspect(ch);
            }
        } finally {Files.deleteIfExists(f);}
    }
    static byte[] dll() {
        byte[] b=PeImportProbeTest.sample();
        ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN)
            .putShort(0x80+22,(short)0x2022);
        return b;
    }
    @Test public void checksRealX64DllHeaderBitsNotJustFilename() throws Exception {
        PeDllHeaderValidator.Result r=validate(dll());
        assertEquals("PE64_AMD64_DLL_HEADER_VERIFIED",r.status);
        assertTrue(r.amd64);assertTrue(r.pe32Plus);assertTrue(r.dllFlag);
    }
    @Test public void nonDllExecutableIsNotMislabeledAsDll() throws Exception {
        byte[] b=PeImportProbeTest.sample();
        assertEquals("NOT_AMD64_PE32PLUS_DLL_HEADER",validate(b).status);
    }
    @Test public void executableOfOtherArchitectureRejected() throws Exception {
        byte[] b=dll();
        ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN)
            .putShort(0x80+4,(short)0xaa64);
        assertEquals("NOT_AMD64_PE32PLUS_DLL_HEADER",validate(b).status);
    }
    @Test public void invalidPEAndTinyFileRejected() throws Exception {
        byte[] b=dll();b[0]=0;
        assertEquals("NOT_WINDOWS_MZ",validate(b).status);
        assertEquals("DLL_FILE_SIZE_INVALID",validate(new byte[40]).status);
    }
}
