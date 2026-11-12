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
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.junit.Assert.*;

public final class Zip64IndexTest {
    @Rule public TemporaryFolder tmp=new TemporaryFolder();

    private static byte[] zip(String... entries) throws IOException {
        ByteArrayOutputStream b=new ByteArrayOutputStream();
        try(ZipOutputStream z=new ZipOutputStream(b)) {
            for(String entry: entries) {
                z.putNextEntry(new ZipEntry(entry));
                if(!entry.endsWith("/"))z.write(new byte[]{0x51,0x52,0x53});
                z.closeEntry();
            }
        }
        return b.toByteArray();
    }
    private Zip64Index.Result check(byte[] content) throws Exception {
        Path file=tmp.newFile("test-"+System.nanoTime()+".zip").toPath();
        Files.write(file,content);
        try(SeekableByteChannel ch=Files.newByteChannel(file,StandardOpenOption.READ)) {
            return Zip64Index.inspect(ch);
        }
    }
    private static int getU32(byte[] b,int off) {
        return ByteBuffer.wrap(b,off,4).order(ByteOrder.LITTLE_ENDIAN).getInt();
    }
    private static int eocd(byte[] source) {
        for(int i=source.length-22;i>=0;i--)
            if(getU32(source,i)==0x06054b50)return i;
        return -1;
    }
    @Test public void recognizesGameAndNestedZips() throws Exception {
        Zip64Index.Result r=check(zip("ForzaHorizon5.exe","media/cars.zip","media/data.pak","media/a.modelbin"));
        assertEquals(4,r.entries);
        assertEquals(1,r.exeMatches);
        assertEquals(1,r.nestedZipNames);
        assertEquals(1,r.modelBinNames);
        assertEquals(3,r.dataEntries);
        assertTrue(r.entireCentralDirectoryIndexed);
        assertFalse(r.payloadCrcVerified);
        assertFalse(r.gamePlayable);
    }
    @Test public void doesNotClaimGameFromGenericZip() throws Exception {
        Zip64Index.Result r=check(zip("readme.txt","media/"));
        assertEquals(0,r.exeMatches);
        assertEquals(1,r.files);
        assertEquals(1,r.directories);
        assertFalse(r.gameCompleteVerified);
    }
    @Test public void rejectsBrokenEocd() throws Exception {
        try {check(new byte[128]);fail("should reject");}
        catch(IOException expected) {assertTrue(expected.getMessage().contains("zip_eocd"));}
    }
    @Test public void supportsZipComment() throws Exception {
        byte[] b=zip("ForzaHorizon5.exe");
        int at=eocd(b);
        ByteArrayOutputStream out=new ByteArrayOutputStream();
        out.write(b,0,at+20);
        out.write(3);out.write(0);
        out.write(new byte[]{'A','B','C'});
        assertEquals(1,check(out.toByteArray()).exeMatches);
    }
    @Test public void detectsUnsupportedMultiDisk() throws Exception {
        byte[] b=zip("ForzaHorizon5.exe");
        b[eocd(b)+4]=1;
        try {check(b);fail("should reject");}
        catch(IOException expected) {assertTrue(expected.getMessage().contains("multidisk"));}
    }
    @Test public void enforcesCentralDirectoryBounds() throws Exception {
        byte[] b=zip("ForzaHorizon5.exe");
        int at=eocd(b);
        ByteBuffer.wrap(b,at+16,4).order(ByteOrder.LITTLE_ENDIAN).putInt(0x7fffffff);
        try {check(b);fail("should reject");}
        catch(IOException expected) {assertTrue(expected.getMessage().contains("bounds"));}
    }
    @Test public void readsZip64EndLocatorWithoutFullFileScan() throws Exception {
        byte[] normal=zip("ForzaHorizon5.exe","media/data.pak");
        int end=eocd(normal);
        int size=getU32(normal,end+12);
        int offset=getU32(normal,end+16);
        ByteArrayOutputStream buffer=new ByteArrayOutputStream();
        buffer.write(normal,0,end);
        ByteBuffer rec=ByteBuffer.allocate(56).order(ByteOrder.LITTLE_ENDIAN);
        rec.putInt(0x06064b50).putLong(44).putShort((short)45).putShort((short)45)
            .putInt(0).putInt(0).putLong(2).putLong(2).putLong(size).putLong(offset);
        buffer.write(rec.array());
        ByteBuffer locator=ByteBuffer.allocate(20).order(ByteOrder.LITTLE_ENDIAN);
        locator.putInt(0x07064b50).putInt(0).putLong(end).putInt(1);
        buffer.write(locator.array());
        byte[] e=Arrays.copyOfRange(normal,end,end+22);
        ByteBuffer eocd=ByteBuffer.wrap(e).order(ByteOrder.LITTLE_ENDIAN);
        eocd.putShort(8,(short)0xffff);
        eocd.putShort(10,(short)0xffff);
        eocd.putInt(12,0xffffffff);
        eocd.putInt(16,0xffffffff);
        buffer.write(e);
        Zip64Index.Result r=check(buffer.toByteArray());
        assertTrue(r.zip64);
        assertEquals(2,r.entries);
        assertEquals(1,r.exeMatches);
        assertFalse(r.payloadCrcVerified);
    }
    @Test public void doesNotExportPrivateFilenames() throws Exception {
        Zip64Index.Result r=check(zip("Private/UserName/ForzaHorizon5.exe","Private/Secret/data.dat"));
        assertEquals(1,r.exeMatches);
        assertEquals(2,r.files);
        assertFalse(r.gameExecutableExecuted);
        assertEquals(0,r.unknownUnpackedLengths);
    }
}
