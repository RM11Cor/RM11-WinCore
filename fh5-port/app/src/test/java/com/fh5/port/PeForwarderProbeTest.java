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

public final class PeForwarderProbeTest {
    private static byte[] fixture(String forwarding) {
        byte[] b=PeExportLinkTest.dll();
        // "CreateFileW" maps to EAT function index 1; pointer is within
        // the original export directory 0x1100..0x1200.
        ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN)
            .putInt(4096+0x204,0x1190);
        byte[] string=(forwarding+"\0").getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        System.arraycopy(string,0,b,4096+0x190,string.length);
        return b;
    }
    private static PeForwarderProbe.Result parse(byte[] raw) throws Exception {
        Path f=Files.createTempFile("fh5-forwarder-test",".dll");
        try {
            Files.write(f,raw);
            try(SeekableByteChannel ch=Files.newByteChannel(f,StandardOpenOption.READ)) {
                PeExportIndex.Result index=PeExportIndex.inspect(ch);
                assertTrue(index.complete);
                return PeForwarderProbe.inspect(ch,index,
                    Collections.singleton("CreateFileW"));
            }
        } finally {Files.deleteIfExists(f);}
    }
    @Test public void decodesForwardedSymbolTargetWithoutExecutingDll() throws Exception {
        PeForwarderProbe.Result r=parse(fixture("agshelper.agsInitialize"));
        assertTrue(r.complete);
        assertEquals(1,r.requested);
        assertEquals(1,r.decoded);
        assertEquals(0,r.malformed);
        assertEquals("CreateFileW",r.targets.get(0).requestedImport);
        assertEquals("agshelper",r.targets.get(0).targetModule);
        assertEquals("agsInitialize",r.targets.get(0).targetFunction);
        assertFalse(r.targets.get(0).ordinal);
        assertFalse(r.gameExecuted);
        assertFalse(r.iatModified);
    }
    @Test public void decodesOrdinalTarget() throws Exception {
        PeForwarderProbe.Result r=parse(fixture("related.dll.#77"));
        assertTrue(r.complete);
        assertEquals("related.dll",r.targets.get(0).targetModule);
        assertEquals("#77",r.targets.get(0).targetFunction);
        assertTrue(r.targets.get(0).ordinal);
    }
    @Test public void malformedTargetReportsPartialWithoutPretendingItResolved() throws Exception {
        PeForwarderProbe.Result r=parse(fixture("incompleteSymbol"));
        assertFalse(r.complete);
        assertEquals("FORWARDER_SYNTAX_INVALID",r.targets.get(0).status);
        assertEquals(0,r.decoded);
    }
    @Test public void unTerminatedForwarderStoppedAtExportDirectoryBoundary() throws Exception {
        byte[] b=fixture("agshelper.x");
        ByteBuffer bb=ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN);
        bb.putInt(4096+0x204,0x11f8);
        java.util.Arrays.fill(b,4096+0x1f8,4096+0x210,(byte)'A');
        PeForwarderProbe.Result r=parse(b);
        assertFalse(r.complete);
        assertEquals("pe_forwarder_not_terminated_in_directory",
            r.targets.get(0).status);
    }
    @Test public void unsafeForwarderPathIsNotTrusted() throws Exception {
        PeForwarderProbe.Result r=parse(fixture("..\\system32\\bad.dll.Call"));
        assertFalse(r.complete);
        assertEquals("pe_forwarder_char_invalid",r.targets.get(0).status);
    }
    @Test public void budgetDoesNotAllowUnboundedRequestedForwarders() throws Exception {
        byte[] b=fixture("agshelper.Call");
        Path p=Files.createTempFile("fh5-forwarder-limits",".dll");
        try {
            Files.write(p,b);
            try(SeekableByteChannel ch=Files.newByteChannel(p,StandardOpenOption.READ)) {
                PeExportIndex.Result idx=PeExportIndex.inspect(ch);
                java.util.Set<String> requests=new java.util.LinkedHashSet<>();
                for(int i=0;i<17;i++)requests.add("F"+i);
                try {PeForwarderProbe.inspect(ch,idx,requests);
                    fail("must reject over cap");
                } catch(java.io.IOException ex) {
                    assertEquals("pe_forwarder_requested_budget",ex.getMessage());
                }
            }
        } finally {Files.deleteIfExists(p);}
    }
}
