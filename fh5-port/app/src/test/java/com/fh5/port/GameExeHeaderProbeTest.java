package com.fh5.port;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.junit.Assert.*;

public final class GameExeHeaderProbeTest {
    @Rule public TemporaryFolder dir=new TemporaryFolder();
    private byte[] syntheticExe(int machine) {
        byte[] b=new byte[4096];
        ByteBuffer m=ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN);
        b[0]='M';b[1]='Z';m.putInt(0x3c,0x80);
        b[0x80]='P';b[0x81]='E';
        m.putShort(0x84,(short)machine);
        m.putShort(0x86,(short)11);
        m.putShort(0x94,(short)0xf0);
        m.putShort(0x98,(short)0x20b);
        m.putInt(0x98+16,0x1000);
        m.putInt(0x98+56,0x1000000);
        m.putShort(0x98+68,(short)2);
        m.putInt(0x98+108,16);
        m.putInt(0x98+120,0x2f000);
        m.putInt(0x98+124,160);
        return b;
    }
    private byte[] buildZip(boolean stored, String[] names, byte[][] payloads) throws Exception {
        ByteArrayOutputStream out=new ByteArrayOutputStream();
        try(ZipOutputStream zip=new ZipOutputStream(out)) {
            for(int i=0;i<names.length;i++) {
                ZipEntry e=new ZipEntry(names[i]);
                if(stored) {
                    e.setMethod(ZipEntry.STORED);
                    e.setSize(payloads[i].length);
                    e.setCompressedSize(payloads[i].length);
                    CRC32 crc=new CRC32();crc.update(payloads[i]);
                    e.setCrc(crc.getValue());
                }
                zip.putNextEntry(e);
                zip.write(payloads[i]);
                zip.closeEntry();
            }
        }
        return out.toByteArray();
    }
    private GameExeHeaderProbe.Result scan(byte[] data) throws Exception {
        Path path=dir.newFile("archive"+System.nanoTime()+".zip").toPath();
        Files.write(path,data);
        try(SeekableByteChannel ch=Files.newByteChannel(path,StandardOpenOption.READ)) {
            return GameExeHeaderProbe.inspect(ch);
        }
    }
    private void fails(byte[] archive,String expected) throws Exception {
        try { scan(archive);fail("Expected: "+expected);}
        catch(IOException e) {assertTrue(e.getMessage(),e.getMessage().contains(expected));}
    }
    @Test public void readActualHeaderFromDeflatedMember() throws Exception {
        byte[] z=buildZip(false,new String[]{"root/ForzaHorizon5.exe"},new byte[][]{syntheticExe(0x8664)});
        GameExeHeaderProbe.Result r=scan(z);
        assertEquals("P2_2_REAL_EXE_PE_HEADER_READ_ONLY",r.stage);
        assertTrue(r.pe32plus);assertTrue(r.amd64);assertTrue(r.importsPresent);
        assertEquals(0x8664,r.machine);assertEquals(11,r.sections);
        assertEquals(0x1000,r.entryPointRva);assertEquals(0x1000000,r.imageSize);
        assertEquals(0x2f000,r.importDirectoryRva);
        assertEquals(4096,r.unpackedExeBytes);assertEquals(8,r.compressionMethod);
    }
    @Test public void readsStoredExecutableWithoutExtraction() throws Exception {
        byte[] z=buildZip(true,new String[]{"game/ForzaHorizon5.exe"},new byte[][]{syntheticExe(0x8664)});
        GameExeHeaderProbe.Result r=scan(z);
        assertEquals(0,r.compressionMethod);
        assertEquals(4096,r.compressedExeBytes);
    }
    @Test public void rejectsWrongMachine() throws Exception {
        byte[] z=buildZip(false,new String[]{"ForzaHorizon5.exe"},new byte[][]{syntheticExe(0x14c)});
        fails(z,"pe_not_amd64");
    }
    @Test public void rejectsNoExe() throws Exception {
        byte[] z=buildZip(false,new String[]{"readme.txt"},new byte[][]{{65,66,67}});
        fails(z,"zip_forza_exe_not_found");
    }
    @Test public void rejectsExeWithBrokenDos() throws Exception {
        byte[] exe=syntheticExe(0x8664);exe[0]=0;
        byte[] z=buildZip(false,new String[]{"ForzaHorizon5.exe"},new byte[][]{exe});
        fails(z,"pe_dos_magic_invalid");
    }
    @Test public void rejectsAmbiguousDuplicateExe() throws Exception {
        byte[] exe=syntheticExe(0x8664);
        byte[] z=buildZip(false,new String[]{"a/ForzaHorizon5.exe","b/ForzaHorizon5.exe"},new byte[][]{exe,exe});
        fails(z,"zip_multiple_forza_exes");
    }
    @Test public void rejectsCorruptedLocalHeader() throws Exception {
        byte[] z=buildZip(false,new String[]{"ForzaHorizon5.exe"},new byte[][]{syntheticExe(0x8664)});
        z[0]=0;
        fails(z,"zip_local_signature_invalid");
    }
    @Test public void supportsZip64DirectoryLocator() throws Exception {
        byte[] z=buildZip(false,new String[]{"ForzaHorizon5.exe"},new byte[][]{syntheticExe(0x8664)});
        int end=-1;
        for(int i=z.length-22;i>=0;i--) {
            if(ByteBuffer.wrap(z,i,4).order(ByteOrder.LITTLE_ENDIAN).getInt()==0x06054b50) {
                end=i;break;
            }
        }
        assertTrue(end>0);
        byte[] original=Arrays.copyOfRange(z,end,end+22);
        ByteBuffer e=ByteBuffer.wrap(original).order(ByteOrder.LITTLE_ENDIAN);
        long cdSize=Integer.toUnsignedLong(e.getInt(12)),cdOffset=Integer.toUnsignedLong(e.getInt(16));
        ByteArrayOutputStream buf=new ByteArrayOutputStream();
        buf.write(z,0,end);
        ByteBuffer rec=ByteBuffer.allocate(56).order(ByteOrder.LITTLE_ENDIAN);
        rec.putInt(0x06064b50).putLong(44).putShort((short)45).putShort((short)45)
            .putInt(0).putInt(0).putLong(1).putLong(1).putLong(cdSize).putLong(cdOffset);
        buf.write(rec.array());
        ByteBuffer locator=ByteBuffer.allocate(20).order(ByteOrder.LITTLE_ENDIAN);
        locator.putInt(0x07064b50).putInt(0).putLong(end).putInt(1);
        buf.write(locator.array());
        e.putShort(8,(short)0xffff);
        e.putShort(10,(short)0xffff);
        e.putInt(12,0xffffffff);e.putInt(16,0xffffffff);
        buf.write(original);
        GameExeHeaderProbe.Result r=scan(buf.toByteArray());
        assertEquals(0x8664,r.machine);
        assertTrue(r.importsPresent);
    }
}
