package com.fh5.port;

import org.junit.Test;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import static org.junit.Assert.*;

public final class X64ProofTest {
    @Test public void syntheticPeContainsRealMachineAndEntry() {
        byte[] b=X64Proof.syntheticPe42();
        ByteBuffer x=ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN);
        assertEquals(1024,b.length);
        assertEquals('M',b[0]); assertEquals('Z',b[1]);
        assertEquals(0x80,x.getInt(0x3c));
        assertEquals(0x8664,Short.toUnsignedInt(x.getShort(0x84)));
        assertEquals(0x20b,Short.toUnsignedInt(x.getShort(0x98)));
        assertEquals(0x1000,x.getInt(0x98+16));
        assertEquals(0x60000020,x.getInt(0x98+0xf0+36));
    }
    @Test public void x86SequenceUsesBalancedGameLikeStackAndReturns42() {
        byte[] b=X64Proof.syntheticPe42();
        int i=0x200;
        assertEquals((byte)0x48,b[i]);
        assertEquals((byte)0x83,b[i+1]);
        assertEquals((byte)0xEC,b[i+2]);
        assertEquals(40,b[i+3]);
        assertEquals((byte)0xb8,b[i+4]);
        assertEquals(2,b[i+5]);
        assertEquals((byte)0x05,b[i+9]);
        assertEquals(40,b[i+10]);
        assertEquals((byte)0x48,b[i+14]);
        assertEquals((byte)0x83,b[i+15]);
        assertEquals((byte)0xC4,b[i+16]);
        assertEquals(40,b[i+17]);
        assertEquals((byte)0xc3,b[i+18]);
    }
    @Test public void syntheticFixtureHasNoGameData() {
        byte[] b=X64Proof.syntheticPe42();
        String value=new String(b,java.nio.charset.StandardCharsets.ISO_8859_1);
        assertFalse(value.contains("ForzaHorizon5"));
        assertFalse(value.contains("steam_api64"));
        assertFalse(value.contains("d3d12.dll"));
    }
}
