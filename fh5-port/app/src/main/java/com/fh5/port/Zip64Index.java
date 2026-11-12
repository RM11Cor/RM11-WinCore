package com.fh5.port;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

/**
 * Read-only ZIP/ZIP64 central-directory index over a SEEKABLE SAF document.
 *
 * Does not decompress, copy, or hash any member data. Only bounded metadata
 * is read. The returned result has no game paths, entry names, hashes or bytes.
 * Android document providers that cannot seek must fail explicitly.
 */
public final class Zip64Index {
    private Zip64Index() {}
    private static final int EOCD = 0x06054b50;
    private static final int ZIP64_END = 0x06064b50;
    private static final int ZIP64_LOCATOR = 0x07064b50;
    private static final int CENTRAL = 0x02014b50;
    private static final long U32_MAX = 0xffffffffL;
    private static final int MAX_MEMBERS = 100000;
    private static final long MAX_DIRECTORY = 128L * 1024 * 1024;
    private static final int MAX_TAIL = 65557;
    private static final int MAX_NAME_BYTES = 8192;
    private static final long MAX_FILE_LENGTH = Long.MAX_VALUE / 4;

    public static final class Result {
        public final boolean zip64;
        public final long archiveBytes;
        public final long directoryBytes;
        public final long entries;
        public final long files;
        public final long directories;
        public final long exeMatches;
        public final long nestedZipNames;
        public final long dataEntries;
        public final long modelBinNames;
        public final long carBinNames;
        public final long shaderBinNames;
        public final long materialBinNames;
        public final long unknownUnpackedLengths;
        public final long summedKnownUnpackedBytes;
        public final boolean entireCentralDirectoryIndexed;
        public final boolean payloadCrcVerified = false;
        public final boolean gameCompleteVerified = false;
        public final boolean gameExecutableExecuted = false;
        public final boolean gamePlayable = false;

        private Result(boolean z, long size, long dirBytes, long entries, long files,
                       long dirs, long exe, long nested, long data, long models,
                       long cars, long shaders, long materials, long unknown,
                       long unpacked) {
            this.zip64=z; this.archiveBytes=size; this.directoryBytes=dirBytes;
            this.entries=entries; this.files=files; this.directories=dirs;
            this.exeMatches=exe; this.nestedZipNames=nested; this.dataEntries=data;
            this.modelBinNames=models; this.carBinNames=cars;
            this.shaderBinNames=shaders; this.materialBinNames=materials;
            this.unknownUnpackedLengths=unknown; this.summedKnownUnpackedBytes=unpacked;
            this.entireCentralDirectoryIndexed=true;
        }
    }

    private static long u16(byte[] b, int p) {
        return ((long)b[p]&255L)|(((long)b[p+1]&255L)<<8);
    }
    private static long u32(byte[] b, int p) {
        return u16(b,p)|(u16(b,p+2)<<16);
    }
    private static long u64(byte[] b, int p) throws IOException {
        long low=u32(b,p),high=u32(b,p+4);
        if (high>0x7fffffffL) throw new IOException("zip64_number_overflow");
        return low | (high<<32);
    }
    private static byte[] at(SeekableByteChannel ch, long pos, int n) throws IOException {
        long size=ch.size();
        if (pos<0 || n<0 || pos>size || (long)n>size-pos)
            throw new IOException("zip_index_read_outside_file");
        byte[] data=new byte[n];
        ByteBuffer bb=ByteBuffer.wrap(data);
        ch.position(pos);
        while(bb.hasRemaining()) {
            int r=ch.read(bb);
            if(r<=0) throw new IOException("zip_index_truncated_or_non_seekable");
        }
        return data;
    }
    private static int endRecord(byte[] tail) {
        for(int i=tail.length-22;i>=0;i--) {
            if(u32(tail,i)==EOCD &&
               i+22+u16(tail,i+20)==tail.length) return i;
        }
        return -1;
    }
    private static boolean dataSuffix(String s) {
        return s.endsWith(".bin") || s.endsWith(".dat") || s.endsWith(".pak")
                || s.endsWith(".arc") || s.endsWith(".bundle")
                || s.endsWith(".modelbin") || s.endsWith(".carbin")
                || s.endsWith(".shaderbin") || s.endsWith(".materialbin")
                || s.endsWith(".zip");
    }
    private static long parseZip64Unpacked(byte[] extra, long value) throws IOException {
        if (value!=U32_MAX) return value;
        int at=0;
        while(at+4<=extra.length) {
            int code=(int)u16(extra,at);
            int len=(int)u16(extra,at+2);
            at+=4;
            if(len>extra.length-at) throw new IOException("zip_extra_truncated");
            if(code==0x0001) {
                if(len<8) throw new IOException("zip64_unpacked_missing");
                return u64(extra,at);
            }
            at+=len;
        }
        throw new IOException("zip64_unpacked_not_found");
    }

    public static Result inspect(SeekableByteChannel channel) throws IOException {
        final long length=channel.size();
        if(length<22 || length>MAX_FILE_LENGTH) throw new IOException("zip_file_length_invalid");
        int tailSize=(int)Math.min(length,MAX_TAIL);
        byte[] tail=at(channel,length-tailSize,tailSize);
        int eocd=endRecord(tail);
        if(eocd<0) throw new IOException("zip_eocd_not_found");
        long eocdAt=length-tailSize+eocd;
        if(u16(tail,eocd+4)!=0 || u16(tail,eocd+6)!=0)
            throw new IOException("zip_multidisk_not_supported");
        long nEntries=u16(tail,eocd+10),dirSize=u32(tail,eocd+12),
             dirOffset=u32(tail,eocd+16);
        boolean is64=false;
        if(nEntries==65535 || dirSize==U32_MAX || dirOffset==U32_MAX) {
            is64=true;
            if(eocdAt<20) throw new IOException("zip64_locator_missing");
            byte[] locator=at(channel,eocdAt-20,20);
            if(u32(locator,0)!=ZIP64_LOCATOR || u32(locator,4)!=0 ||
                    u32(locator,16)!=1) throw new IOException("zip64_locator_invalid");
            long recordAt=u64(locator,8);
            if(recordAt>=eocdAt-20 || recordAt>length-56)
                throw new IOException("zip64_record_outside_file");
            byte[] rec=at(channel,recordAt,56);
            if(u32(rec,0)!=ZIP64_END || u64(rec,4)<44 ||
                    u32(rec,16)!=0 || u32(rec,20)!=0)
                throw new IOException("zip64_record_invalid");
            nEntries=u64(rec,32);
            dirSize=u64(rec,40);
            dirOffset=u64(rec,48);
        }
        if(nEntries>MAX_MEMBERS || dirSize>MAX_DIRECTORY ||
           dirOffset>length || dirSize>length-dirOffset ||
           (nEntries>0 && dirSize<nEntries*46L) ||
           dirOffset+dirSize>eocdAt)
            throw new IOException("zip_central_directory_bounds_or_budget");
        long ptr=dirOffset,dirEnd=ptr+dirSize;
        long files=0,dirs=0,exe=0,nested=0,data=0,models=0,cars=0,shaders=0,
            materials=0,unknown=0,totalUnpacked=0;
        for(long i=0;i<nEntries;i++) {
            if(ptr>dirEnd-46) throw new IOException("zip_entry_outside_central_directory");
            byte[] hdr=at(channel,ptr,46);
            if(u32(hdr,0)!=CENTRAL) throw new IOException("zip_central_signature_invalid");
            int flag=(int)u16(hdr,8);
            if((flag&1)!=0) throw new IOException("zip_encrypted_index_not_supported");
            long unpacked=u32(hdr,24);
            int nameLength=(int)u16(hdr,28),extraLength=(int)u16(hdr,30),
                commentLength=(int)u16(hdr,32);
            if(nameLength>MAX_NAME_BYTES || nameLength==0)
                throw new IOException("zip_name_length_budget");
            long sizeOfRecord=46L+nameLength+extraLength+commentLength;
            if(sizeOfRecord>dirEnd-ptr)
                throw new IOException("zip_central_entry_truncated");
            byte[] nameBytes=at(channel,ptr+46,nameLength);
            String rawName=new String(nameBytes,
                (flag&0x0800)!=0 ? StandardCharsets.UTF_8 : java.nio.charset.Charset.forName("IBM437"));
            String name=rawName.replace('\\','/').toLowerCase(Locale.ROOT);
            if(name.endsWith("/")) {
                dirs++;
            } else {
                files++;
                String leaf=name.substring(name.lastIndexOf('/')+1);
                if(leaf.equals("forzahorizon5.exe")) exe++;
                if(name.endsWith(".zip")) nested++;
                if(dataSuffix(name)) data++;
                if(name.endsWith(".modelbin")) models++;
                if(name.endsWith(".carbin")) cars++;
                if(name.endsWith(".shaderbin")) shaders++;
                if(name.endsWith(".materialbin")) materials++;
                if(unpacked==U32_MAX) {
                    byte[] extra=at(channel,ptr+46+nameLength,extraLength);
                    try { unpacked=parseZip64Unpacked(extra,unpacked); }
                    catch(IOException problem) { unknown++;unpacked=0; }
                }
                if(unpacked>Long.MAX_VALUE-totalUnpacked)
                    throw new IOException("zip_unpacked_total_overflow");
                totalUnpacked+=unpacked;
            }
            ptr+=sizeOfRecord;
        }
        // Reject truncated directory, but tolerate optional digital signature records.
        if(ptr>dirEnd) throw new IOException("zip_central_overrun");
        return new Result(is64,length,dirSize,nEntries,files,dirs,exe,nested,
                data,models,cars,shaders,materials,unknown,totalUnpacked);
    }
}
