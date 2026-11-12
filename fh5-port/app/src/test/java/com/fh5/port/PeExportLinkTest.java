package com.fh5.port;

import org.junit.Test;
import static org.junit.Assert.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

public final class PeExportLinkTest {
    static byte[] dll() {
        byte[] b=PeImportProbeTest.sample();
        ByteBuffer out=ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN);
        out.putShort(0x80+22,(short)0x2022); // x64 DLL
        out.putInt(0x98+112,0x1100); // export directory RVA
        out.putInt(0x98+116,0x100); // directory size
        final int d=4096+0x100;
        out.putInt(d+16,37);         // Ordinal base
        out.putInt(d+20,2);          // NumberOfFunctions
        out.putInt(d+24,1);          // NumberOfNames
        out.putInt(d+28,0x1200);     // EAT
        out.putInt(d+32,0x1300);     // name pointer table
        out.putInt(d+36,0x1400);     // name ordinal index table
        out.putInt(4096+0x200,0x1600);
        out.putInt(4096+0x204,0x1610);
        out.putInt(4096+0x300,0x1500);
        out.putShort(4096+0x400,(short)1);
        byte[] name="CreateFileW\0".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        System.arraycopy(name,0,b,4096+0x500,name.length);
        return b;
    }
    private static PeExportIndex.Result parseDll(byte[] bytes) throws Exception {
        Path f=Files.createTempFile("fh5-export-test", ".dll");
        try{
            Files.write(f,bytes);
            try(SeekableByteChannel ch=Files.newByteChannel(f,StandardOpenOption.READ)){
                return PeExportIndex.inspect(ch);
            }
        }finally{Files.deleteIfExists(f);}
    }
    private static PeLocalImportLinkProbe.Report compare(
            PeExportIndex.Result exports,String name) throws Exception {
        Path f=Files.createTempFile("fh5-import-matching", ".exe");
        try{
            Files.write(f,PeImportSymbolProbeTest.fixture());
            try(SeekableByteChannel exe=Files.newByteChannel(f,StandardOpenOption.READ)){
                Map<String,PeExportIndex.Result> indexes=new HashMap<>();
                if(exports!=null)indexes.put(name,exports);
                return PeLocalImportLinkProbe.inspect(exe,indexes,
                    new HashSet<>(Collections.singleton(name)));
            }
        }finally{Files.deleteIfExists(f);}
    }
    @Test public void properlyMatchesNamedAndOrdinalImportsAgainstRealPeExportTable()
            throws Exception {
        PeExportIndex.Result dll=parseDll(dll());
        assertTrue(dll.complete);
        assertEquals("EXPORT_INDEX_DECODED",dll.status);
        assertEquals(37,dll.ordinalBase);
        assertEquals("DIRECT_EXPORT_PRESENT",dll.lookupName("CreateFileW"));
        assertEquals("DIRECT_EXPORT_PRESENT",dll.lookupOrdinal(37));
        assertEquals("ORDINAL_EXPORT_NOT_FOUND",dll.lookupOrdinal(2));
        PeLocalImportLinkProbe.Report p=compare(dll,"kernel32.dll");
        assertTrue(p.complete);
        assertEquals(1,p.dllsAssessed);
        assertEquals(2,p.importsCompared);
        assertEquals(2,p.directMatches);
        assertEquals(0,p.notFound);
        assertFalse(p.executed);assertFalse(p.iatModified);
    }
    @Test public void recordsMissingNamedExportInsteadOfClaimingBinding()
            throws Exception {
        PeLocalImportLinkProbe.Report p=compare(parseDll(dll()),"d3d12.dll");
        assertTrue(p.complete);
        assertEquals(1,p.notFound);
        assertEquals(0,p.directMatches);
        assertEquals("D3D12CreateDevice",p.dlls.get(0).missingExamples.get(0));
    }
    @Test public void identifiesExportForwardersButDoesNotResolveThem()
            throws Exception {
        byte[] bytes=dll();
        ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
            .putInt(4096+0x204,0x1190);
        PeExportIndex.Result e=parseDll(bytes);
        assertEquals(1,e.forwardedFunctions);
        assertEquals("FORWARDED_EXPORT",e.lookupName("CreateFileW"));
        PeLocalImportLinkProbe.Report p=compare(e,"kernel32.dll");
        assertTrue(p.complete);
        assertEquals(1,p.forwardedMatches);
        assertEquals(1,p.directMatches);
        assertEquals(0,p.notFound);
    }
    @Test public void absentExportIndexIsMarkedPartialNotMissing()
            throws Exception {
        PeLocalImportLinkProbe.Report p=compare(null,"kernel32.dll");
        assertFalse(p.complete);
        assertEquals(2,p.importsCompared);
        assertEquals(0,p.directMatches);
        assertEquals(0,p.notFound);
        assertEquals("EXPORT_INDEX_UNAVAILABLE",p.dlls.get(0).exportScanStatus);
    }
    @Test public void invalidHeaderNeverClaimedToBeExports() throws Exception {
        byte[] b=dll();b[0]=0;
        assertEquals("NOT_AMD64_PE64_DLL",parseDll(b).status);
    }
    @Test public void insaneExportCountsFailClosed() throws Exception {
        byte[] b=dll();
        ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN)
            .putInt(4096+0x100+20,90000);
        PeExportIndex.Result r=parseDll(b);
        assertFalse(r.complete);
        assertEquals("EXPORT_INDEX_BUDGET_REACHED",r.status);
    }
    @Test public void exactOrdinalBaseMatters() throws Exception {
        byte[] b=dll();
        ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN)
            .putInt(4096+0x100+16,38);
        PeExportIndex.Result r=parseDll(b);
        assertEquals("ORDINAL_EXPORT_NOT_FOUND",r.lookupOrdinal(37));
        PeLocalImportLinkProbe.Report p=compare(r,"kernel32.dll");
        assertTrue(p.complete);
        assertEquals(1,p.notFound);
    }
}
