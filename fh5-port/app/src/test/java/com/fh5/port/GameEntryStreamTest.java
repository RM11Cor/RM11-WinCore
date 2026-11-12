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
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import static org.junit.Assert.*;

/** Real bounded ZIP decompression and RVA->raw file offset tests. */
public final class GameEntryStreamTest {
    @Rule public TemporaryFolder tmp=new TemporaryFolder();

    private static byte[] syntheticPe(int rawOffset,boolean executable) {
        byte[] pe=new byte[rawOffset+4096];
        ByteBuffer b=ByteBuffer.wrap(pe).order(ByteOrder.LITTLE_ENDIAN);
        pe[0]='M';pe[1]='Z';b.putInt(0x3c,0x80);
        pe[0x80]='P';pe[0x81]='E';
        b.putShort(0x84,(short)0x8664);
        b.putShort(0x86,(short)1);
        b.putShort(0x94,(short)0xf0);
        b.putShort(0x98,(short)0x20b);
        b.putInt(0x98+16,0x1000);
        b.putInt(0x98+56,0x500000);
        b.putShort(0x98+68,(short)2);
        b.putInt(0x98+108,16);
        b.putInt(0x98+120,0x4000);
        b.putInt(0x98+124,32);
        int section=0x98+0xf0;
        byte[] name={'.','t','e','x','t',0,0,0};
        System.arraycopy(name,0,pe,section,name.length);
        b.putInt(section+8,0x1000);     // in-memory virtual size
        b.putInt(section+12,0x1000);    // entrypoint RVA
        b.putInt(section+16,4096);      // raw section size
        b.putInt(section+20,rawOffset); // file offset
        b.putInt(section+36,executable?0x60000020:0x40000040);
        byte[] instructions={(byte)0x48,(byte)0x83,(byte)0xec,0x28,
                             (byte)0x48,(byte)0x89,0x5c,0x24,0x20,
                             (byte)0xc3};
        System.arraycopy(instructions,0,pe,rawOffset,instructions.length);
        return pe;
    }
    private static byte[] zip(byte[] exe,boolean store) throws Exception {
        ByteArrayOutputStream out=new ByteArrayOutputStream();
        try(ZipOutputStream z=new ZipOutputStream(out)) {
            ZipEntry e=new ZipEntry("subfolder/ForzaHorizon5.exe");
            if(store) {
                e.setMethod(ZipEntry.STORED);
                e.setSize(exe.length);e.setCompressedSize(exe.length);
                CRC32 crc=new CRC32();crc.update(exe);e.setCrc(crc.getValue());
            }
            z.putNextEntry(e);
            z.write(exe);
            z.closeEntry();
        }
        return out.toByteArray();
    }
    private GameExeHeaderProbe.EntryResult run(byte[] zip) throws Exception {
        Path f=tmp.newFile("zip"+System.nanoTime()+".zip").toPath();
        Files.write(f,zip);
        try(SeekableByteChannel c=Files.newByteChannel(f,StandardOpenOption.READ)) {
            return GameExeHeaderProbe.inspectEntry(c);
        }
    }
    private void fails(byte[] zip,String expected) throws Exception {
        try {run(zip);fail("Expected failure "+expected);}
        catch(IOException ex){assertTrue(ex.getMessage(),ex.getMessage().contains(expected));}
    }
    @Test public void storedMemberMapsTrueEntrypoint() throws Exception {
        byte[] pe=syntheticPe(4096,true);
        GameExeHeaderProbe.EntryResult r=run(zip(pe,true));
        assertEquals(0,r.sectionIndex);
        assertEquals(4096,r.entryFileOffset);
        assertEquals(128,r.sampleLength);
        assertEquals("stack-sub-imm8",r.leadingOpcodeFamily);
        assertEquals(0x48,r.entrySample[0]&255);
        assertEquals(0x83,r.entrySample[1]&255);
        assertEquals(4096+128,r.bytesInflated);
        assertEquals(128,r.compressedBytesRead);
        assertTrue(r.pe.amd64);
    }
    @Test public void deflateMemberStreamsEntryFromMiddle() throws Exception {
        int offset=1024*1024+4096;
        GameExeHeaderProbe.EntryResult r=run(zip(syntheticPe(offset,true),false));
        assertEquals(offset,r.entryFileOffset);
        assertEquals(128,r.sampleLength);
        assertTrue(r.bytesInflated>=offset+128);
        assertTrue(r.compressedBytesRead>0);
        assertEquals("stack-sub-imm8",r.leadingOpcodeFamily);
    }
    @Test public void rejectsEntryInNonExecutableSection() throws Exception {
        fails(zip(syntheticPe(4096,false),false),"pe_entry_section_not_executable");
    }
    @Test public void rejectsCorruptRvaMapping() throws Exception {
        byte[] exe=syntheticPe(4096,true);
        ByteBuffer.wrap(exe).order(ByteOrder.LITTLE_ENDIAN)
            .putInt(0x98+16,0x5000);
        fails(zip(exe,false),"pe_entry_rva_unmapped");
    }
    @Test public void rejectsFileOffsetOutsideExePayload() throws Exception {
        byte[] exe=syntheticPe(4096,true);
        int section=0x98+0xf0;
        ByteBuffer.wrap(exe).order(ByteOrder.LITTLE_ENDIAN)
            .putInt(section+20,0x500000);
        fails(zip(exe,false),"pe_entry_not_backed_by_file");
    }
    @Test public void readsJumpInstructionFamily() throws Exception {
        byte[] exe=syntheticPe(4096,true);
        exe[4096]=(byte)0xE9;
        assertEquals("relative-jump",run(zip(exe,true)).leadingOpcodeFamily);
    }
    @Test public void rejectsUnsupportedZipCompressionMetadata() throws Exception {
        byte[] raw=zip(syntheticPe(4096,true),false);
        // ZIP local method at +8 and central method 10 bytes after central header.
        // Change both to 99, guaranteeing explicit rejection without decompression.
        int central=-1;
        for(int i=0;i<raw.length-46;i++)
            if((raw[i]&255)==0x50 && (raw[i+1]&255)==0x4b &&
                (raw[i+2]&255)==1 && (raw[i+3]&255)==2){central=i;break;}
        assertTrue(central>=0);
        raw[8]=99;raw[9]=0;
        raw[central+10]=99;raw[central+11]=0;
        fails(raw,"zip_exe_compression_unsupported");
    }

    private GameExeHeaderProbe.EntryResult probeAt(byte[] zip,long rva) throws Exception {
        Path f=tmp.newFile("target"+System.nanoTime()+".zip").toPath();
        Files.write(f,zip);
        try(SeekableByteChannel c=Files.newByteChannel(f,StandardOpenOption.READ)) {
            return GameExeHeaderProbe.inspectAtRva(c,rva);
        }
    }
    @Test public void directCallTargetRvaCanBeReadWithoutExtractingExe() throws Exception {
        // Synthetic test: RVA 0x1004 is inside executable .text.
        GameExeHeaderProbe.EntryResult target=
            probeAt(zip(syntheticPe(4096,true),false),0x1004);
        assertEquals(0,target.sectionIndex);
        assertEquals(4100,target.entryFileOffset);
        assertEquals(128,target.sampleLength);
        assertEquals("rex-mov-modrm",target.leadingOpcodeFamily);
    }
    @Test public void targetOutsideExeVirtualImageIsRejected() throws Exception {
        byte[] data=zip(syntheticPe(4096,true),false);
        try {probeAt(data,0x500000);fail("must reject outside PE virtual image");}
        catch(IOException ex){assertTrue(ex.getMessage().contains("pe_target_rva_outside_image"));}
    }
    @Test public void targetInUnmappedSectionIsRejected() throws Exception {
        byte[] data=zip(syntheticPe(4096,true),false);
        try {probeAt(data,0x3000);fail("must reject unmapped target");}
        catch(IOException ex){assertTrue(ex.getMessage().contains("pe_entry_rva_unmapped"));}
    }
    @Test public void targetFromNonExecutableSectionIsRejected() throws Exception {
        byte[] data=zip(syntheticPe(4096,false),false);
        try {probeAt(data,0x1008);fail("must reject data target");}
        catch(IOException ex){assertTrue(ex.getMessage().contains("pe_entry_section_not_executable"));}
    }
    @Test public void targetCanStream512BytesReadOnly() throws Exception {
        byte[] data=zip(syntheticPe(4096,true),false);
        Path file=tmp.newFile("deep"+System.nanoTime()+".zip").toPath();
        Files.write(file,data);
        try(SeekableByteChannel channel=Files.newByteChannel(file,StandardOpenOption.READ)) {
            GameExeHeaderProbe.EntryResult result=
                GameExeHeaderProbe.inspectAtRva(channel,0x1004,512);
            assertEquals(512,result.sampleLength);
            assertEquals(4100,result.entryFileOffset);
            assertTrue(result.bytesInflated>=4100+512);
            assertEquals(0x48,result.entrySample[0]&255);
        }
    }
    @Test public void rejectUnboundedTargetSampleBeforeFileRead() throws Exception {
        byte[] data=zip(syntheticPe(4096,true),true);
        Path file=tmp.newFile("bounds"+System.nanoTime()+".zip").toPath();
        Files.write(file,data);
        try(SeekableByteChannel channel=Files.newByteChannel(file,StandardOpenOption.READ)) {
            try {GameExeHeaderProbe.inspectAtRva(channel,0x1000,513);fail("budget");}
            catch(IOException ex) {
                assertEquals("pe_target_sample_budget_invalid",ex.getMessage());
            }
        }
    }
}
