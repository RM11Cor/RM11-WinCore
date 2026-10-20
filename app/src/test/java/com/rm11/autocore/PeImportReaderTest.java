package com.rm11.autocore;

import org.junit.Test;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.charset.StandardCharsets;
import static org.junit.Assert.*;

/** Synthetic, harmless test PE header; no real game EXE is shipped in the project. */
public class PeImportReaderTest {
    static byte[] syntheticPe(String dll) {
        ByteBuffer b = ByteBuffer.allocate(2048).order(ByteOrder.LITTLE_ENDIAN);
        b.put(0, (byte) 'M'); b.put(1, (byte) 'Z');
        b.putInt(0x3c, 0x80);
        b.put(0x80, (byte)'P'); b.put(0x81, (byte)'E');
        b.putShort(0x84, (short)0x8664); // x86-64
        b.putShort(0x86, (short)1); // one section
        b.putShort(0x94, (short)240); // PE32+ optional header
        int optional = 0x80 + 24;
        b.putShort(optional, (short)0x20b);
        b.putInt(optional + 112 + 8, 0x1100); // import directory RVA
        int section = optional + 240;
        b.putInt(section + 12, 0x1000); // VA
        b.putInt(section + 16, 0x300); // raw size
        b.putInt(section + 20, 0x200); // raw offset
        b.putInt(0x300 + 12, 0x1140); // import descriptor name RVA
        byte[] data = (dll + "\0").getBytes(StandardCharsets.US_ASCII);
        for (int i = 0; i < data.length; i++) b.put(0x340 + i, data[i]);
        return b.array();
    }
    @Test public void readsArchitectureAndDllWithoutRunningProgram() throws Exception {
        Path file = Files.createTempFile("rm11-pe-test", ".exe");
        try {
            Files.write(file, syntheticPe("d3d12.dll"));
            try (FileChannel channel = FileChannel.open(file, StandardOpenOption.READ)) {
                PeImportReader.Info info = PeImportReader.read(channel);
                assertEquals("x86-64", info.architecture);
                assertEquals(1, info.importedDlls.size());
                assertEquals("d3d12.dll", info.importedDlls.get(0));
            }
        } finally { Files.deleteIfExists(file); }
    }
    @Test public void invalidExecutablesReturnUnknownSafely() throws Exception {
        Path file = Files.createTempFile("rm11-invalid-test", ".bin");
        try {
            Files.write(file, new byte[] {0,1,2,3,4});
            try (FileChannel channel = FileChannel.open(file, StandardOpenOption.READ)) {
                assertEquals("غير محدد", PeImportReader.read(channel).architecture);
                assertTrue(PeImportReader.read(channel).importedDlls.isEmpty());
            }
        } finally { Files.deleteIfExists(file); }
    }
}
