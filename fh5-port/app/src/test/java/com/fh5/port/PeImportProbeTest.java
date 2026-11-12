package com.fh5.port;

import org.junit.Test;
import static org.junit.Assert.*;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;

public final class PeImportProbeTest {
    /** Independently synthesized PE32+ x64 file: no proprietary game bytes. */
    static byte[] sample() {
        byte[] raw=new byte[8192];
        ByteBuffer b=ByteBuffer.wrap(raw).order(ByteOrder.LITTLE_ENDIAN);
        raw[0]='M';raw[1]='Z';b.putInt(0x3c,0x80);
        raw[0x80]='P';raw[0x81]='E';
        b.putShort(0x84,(short)0x8664);
        b.putShort(0x86,(short)1);
        b.putShort(0x94,(short)0xf0);
        int opt=0x98;
        b.putShort(opt,(short)0x20b);
        b.putInt(opt+16,0x1000);
        b.putInt(opt+56,0x4000);
        b.putInt(opt+60,0x400);
        b.putShort(opt+68,(short)2);
        b.putInt(opt+108,16);
        b.putInt(opt+120,0x1200);
        b.putInt(opt+124,60);
        int section=opt+0xf0;
        raw[section]='.';raw[section+1]='r';raw[section+2]='d';
        b.putInt(section+8,4096);
        b.putInt(section+12,0x1000);
        b.putInt(section+16,4096);
        b.putInt(section+20,4096);
        b.putInt(section+36,0x40000040);
        // Descriptor 1, descriptor 2, then 20-byte NUL terminator.
        b.putInt(4096+0x200+12,0x1300);
        b.putInt(4096+0x214+12,0x1320);
        byte[] nameA="KERNEL32.dll\0".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        byte[] nameB="d3d12.dll\0".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        System.arraycopy(nameA,0,raw,4096+0x300,nameA.length);
        System.arraycopy(nameB,0,raw,4096+0x320,nameB.length);
        return raw;
    }
    private static PeImportProbe.Result parse(byte[] bytes) throws Exception {
        Path p=Files.createTempFile("fh5-pe-import-", ".exe");
        try {
            Files.write(p,bytes);
            try(SeekableByteChannel ch=Files.newByteChannel(p,StandardOpenOption.READ)) {
                return PeImportProbe.inspectDirect(ch);
            }
        } finally {Files.deleteIfExists(p);}
    }
    private static void rejected(byte[] bytes,String error) throws Exception {
        try {parse(bytes);fail("expected "+error);}
        catch(IOException e){assertEquals(error,e.getMessage());}
    }
    @Test public void discoversTwoStaticDependenciesWithoutRunningAnything() throws Exception {
        PeImportProbe.Result r=parse(sample());
        assertEquals("STATIC_IMPORT_NAMES_DECODED",r.status);
        assertEquals(2,r.descriptorCount);
        assertEquals(2,r.uniqueNameCount);
        assertEquals(Arrays.asList("kernel32.dll","d3d12.dll"),r.dllNames);
        assertTrue(r.importsPresent);
        assertTrue(r.complete);
        assertTrue(r.noOriginalGameExecution);
        assertEquals(0x1200,r.directoryRva);
    }
    @Test public void absentImportTableIsNotAGameLoaderFailure() throws Exception {
        byte[] pe=sample();
        ByteBuffer.wrap(pe).order(ByteOrder.LITTLE_ENDIAN).putInt(0x98+120,0);
        PeImportProbe.Result r=parse(pe);
        assertEquals("NO_STATIC_IMPORT_DIRECTORY",r.status);
        assertTrue(r.complete);
        assertFalse(r.importsPresent);
    }
    @Test public void malformedImportNameRvaRejectedBeforeRead() throws Exception {
        byte[] pe=sample();
        ByteBuffer.wrap(pe).order(ByteOrder.LITTLE_ENDIAN).putInt(4096+0x200+12,0x3f00);
        rejected(pe,"pe_import_name_unmapped");
    }
    @Test public void nameCannotContainStoragePathOrInvalidCharacters() throws Exception {
        byte[] pe=sample();
        pe[4096+0x300+3]=(byte)'/';
        rejected(pe,"pe_import_name_invalid_char");
    }
    @Test public void outOfImageDirectoryIsNotLoaded() throws Exception {
        byte[] pe=sample();
        ByteBuffer.wrap(pe).order(ByteOrder.LITTLE_ENDIAN).putInt(0x98+120,0x3fff);
        rejected(pe,"pe_import_directory_outside_image");
    }
    @Test public void incompleteDescriptorTableIsExplicitlyMarked() throws Exception {
        byte[] pe=sample();
        ByteBuffer.wrap(pe).order(ByteOrder.LITTLE_ENDIAN).putInt(0x98+124,40);
        PeImportProbe.Result r=parse(pe);
        assertEquals("IMPORT_TERMINATOR_NOT_WITHIN_DIRECTORY_SIZE",r.status);
        assertFalse(r.complete);
        assertEquals(2,r.descriptorCount);
    }
    @Test public void importCountCannotAllocateUnboundedMemory() {
        assertTrue(PeImportProbe.MAX_DLL_DESCRIPTORS<=128);
        assertTrue(PeImportProbe.MAX_DLL_NAME_BYTES<=128);
    }
}
