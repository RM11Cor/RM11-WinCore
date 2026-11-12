package com.fh5.port;

import org.junit.Test;
import static org.junit.Assert.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

public final class PeImportSymbolProbeTest {
    static byte[] fixture() {
        byte[] raw=PeImportProbeTest.sample();
        ByteBuffer b=ByteBuffer.wrap(raw).order(ByteOrder.LITTLE_ENDIAN);
        // Descriptor #1 ILT, descriptor #2 ILT.
        b.putInt(4096+0x200,0x1400);
        b.putInt(4096+0x214,0x1420);
        // First DLL: named "CreateFileW", then ordinal #37, then terminator.
        b.putLong(4096+0x400,0x1500L);
        b.putLong(4096+0x408,0x8000000000000025L);
        // Second DLL: one named "D3D12CreateDevice", then terminator.
        b.putLong(4096+0x420,0x1520L);
        byte[] a="CreateFileW\0".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        byte[] d="D3D12CreateDevice\0".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        System.arraycopy(a,0,raw,4096+0x502,a.length);
        System.arraycopy(d,0,raw,4096+0x522,d.length);
        return raw;
    }
    static PeImportSymbolProbe.Report inspect(byte[] raw) throws Exception {
        Path tmp=Files.createTempFile("fh5-symbol-test",".exe");
        try {
            Files.write(tmp,raw);
            try(SeekableByteChannel ch=Files.newByteChannel(tmp,StandardOpenOption.READ)) {
                return PeImportSymbolProbe.inspectDirect(ch);
            }
        } finally {Files.deleteIfExists(tmp);}
    }
    @Test public void discoversNamedAndOrdinalFunctionsInSyntheticExe() throws Exception {
        PeImportSymbolProbe.Report r=inspect(fixture());
        assertTrue(r.complete);
        assertEquals("IMPORT_SYMBOLS_DECODED",r.status);
        assertEquals(2,r.dllsChecked);
        assertEquals(2,r.totalNamedImports);
        assertEquals(1,r.totalOrdinalImports);
        assertEquals("kernel32.dll",r.dlls.get(0).dll);
        assertEquals("CreateFileW",r.dlls.get(0).exampleFunctions.get(0));
        assertEquals(1,r.dlls.get(0).ordinalImports);
        assertEquals("D3D12CreateDevice",r.dlls.get(1).exampleFunctions.get(0));
        assertFalse(r.gameExecuted);
    }
    @Test public void noImportDirectoryDoesNotCreateInventedSymbols() throws Exception {
        byte[] pe=fixture();
        ByteBuffer.wrap(pe).order(ByteOrder.LITTLE_ENDIAN).putInt(0x98+120,0);
        PeImportSymbolProbe.Report r=inspect(pe);
        assertEquals(0,r.dllsChecked);
        assertTrue(r.complete);
        assertEquals("NO_STATIC_IMPORT_DIRECTORY",r.status);
    }
    @Test public void maliciousFunctionRvaFailsClosed() throws Exception {
        byte[] pe=fixture();
        ByteBuffer.wrap(pe).order(ByteOrder.LITTLE_ENDIAN).putLong(4096+0x400,0x3000000000L);
        try {inspect(pe);fail("bad thunk");}
        catch(java.io.IOException e){assertEquals("pe_symbol_unbound_thunk_invalid",e.getMessage());}
    }
    @Test public void nonTerminatedDllThunkDoesNotClaimComplete() throws Exception {
        byte[] pe=fixture();
        // Use a thunk RVA in the last eight bytes of the backed section.
        ByteBuffer.wrap(pe).order(ByteOrder.LITTLE_ENDIAN).putInt(4096+0x200,0x1ff8);
        // first thunk = ordinal, second read would cross the section.
        ByteBuffer.wrap(pe).order(ByteOrder.LITTLE_ENDIAN)
          .putLong(4096+0xff8,0x8000000000000001L);
        try {inspect(pe);fail("unbacked thunk");}
        catch(java.io.IOException e) {
            assertTrue(e.getMessage().startsWith("pe_import_"));
        }
    }
    @Test public void boundedSampleAndThunkLimitsAreFixed() {
        assertEquals(6,PeImportSymbolProbe.MAX_SAMPLE_NAMES);
        assertTrue(PeImportSymbolProbe.MAX_TOTAL_THUNKS<=8192);
        assertTrue(PeImportSymbolProbe.MAX_THUNKS_PER_DLL<=512);
    }
}
