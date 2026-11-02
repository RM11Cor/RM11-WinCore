package org.kernix.host;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/** Pure Java regression test; does not need a device or Android runtime. */
public final class GameInspectorTest {
    private static byte[] sample(int arch) {
        byte[] data = new byte[512];
        ByteBuffer b = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);
        b.put(0, (byte)'M'); b.put(1, (byte)'Z');
        b.putInt(60, 128);
        b.put(128, (byte)'P'); b.put(129, (byte)'E');
        b.putShort(132, (short)arch); // IMAGE_FILE_MACHINE
        b.putShort(134, (short)1); // number of sections
        b.putShort(148, (short)240); // optional header size
        b.putShort(152, (short)(arch == 0x014c ? 0x10b : 0x20b));
        b.putShort(152+68, (short)2); // Windows GUI subsystem
        return data;
    }

    private static void expect(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
    private static void invalid(byte[] data) throws Exception {
        try {
            GameInspector.inspect(new ByteArrayInputStream(data));
            throw new AssertionError("Malformed file passed PE validation");
        } catch (IOException expected) {
            // Reject by design.
        }
    }

    public static void main(String[] args) throws Exception {
        String x64=GameInspector.inspect(new ByteArrayInputStream(sample(0x8664)));
        expect(x64.contains("x86-64"), "x86_64 architecture missing");
        expect(x64.contains("DirectX version: NOT YET DETERMINED"), "invented DX version");
        expect(x64.contains("Game executed: NO"), "incorrect execution label");
        String x86=GameInspector.inspect(new ByteArrayInputStream(sample(0x014c)));
        expect(x86.contains("x86 32-bit"), "x86 architecture missing");
        invalid(new byte[512]);
        byte[] malformed=sample(0x8664);malformed[128]=0;
        invalid(malformed);
        byte[] truncated=sample(0x8664);
        invalid(java.util.Arrays.copyOf(truncated, 140));
        System.out.println("KERNIX_ANDROID_PE_INSPECTOR_TEST_PASS");
    }
}
