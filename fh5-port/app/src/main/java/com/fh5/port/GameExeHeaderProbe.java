package com.fh5.port;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

/**
 * P2.2: inspect the ORIGINAL ForzaHorizon5.exe PE64 header from a giant ZIP64
 * via the Android storage provider, read-only and without extracting a game file.
 * Does NOT execute game bytes, perform CRC of the complete EXE, or bypass licenses.
 */
public final class GameExeHeaderProbe {
    private GameExeHeaderProbe() {}
    private static final int EOCD=0x06054b50, ZIP64_LOC=0x07064b50,
            ZIP64_END=0x06064b50, CENTRAL=0x02014b50, LOCAL=0x04034b50;
    private static final long U32=0xffffffffL;
    private static final int MAX_EOCD_TAIL=65557, MAX_ENTRIES=100000;
    private static final long MAX_DIRECTORY=128L*1024*1024;
    private static final int MAX_PREFIX=256*1024;
    private static final int MAX_COMPRESSED_INPUT=1024*1024;
    public static final class Result {
        public final String stage;
        public final long archiveBytes,compressedExeBytes,unpackedExeBytes;
        public final int compressionMethod,machine,sections,subsystem;
        public final long entryPointRva,imageSize,importDirectoryRva,importDirectorySize;
        public final boolean amd64,pe32plus,importsPresent;
        public final int headerBytesRead;
        private Result(long arc,long compressed,long unpacked,int method,int machine,
                       int sections,int subsystem,long entry,long image,long importRva,
                       long importSize,int read) {
            stage="P2_2_REAL_EXE_PE_HEADER_READ_ONLY";
            archiveBytes=arc;compressedExeBytes=compressed;unpackedExeBytes=unpacked;
            compressionMethod=method;this.machine=machine;this.sections=sections;
            this.subsystem=subsystem;entryPointRva=entry;imageSize=image;
            importDirectoryRva=importRva;importDirectorySize=importSize;
            headerBytesRead=read;amd64=machine==0x8664;
            pe32plus=true;importsPresent=importRva!=0 && importSize!=0;
        }
    }
    private static int u16(byte[] b,int p) {
        return (b[p]&255)|((b[p+1]&255)<<8);
    }
    private static long u32(byte[] b,int p) {
        return (long)u16(b,p)|((long)u16(b,p+2)<<16);
    }
    private static long u64(byte[] b,int p) throws IOException {
        long low=u32(b,p),hi=u32(b,p+4);
        if(hi>Integer.MAX_VALUE)throw new IOException("zip64_integer_overflow");
        return low|(hi<<32);
    }
    private static byte[] read(SeekableByteChannel ch,long position,int count) throws IOException {
        long size=ch.size();
        if(count<0 || position<0 || position>size || count>size-position)
            throw new IOException("zip_metadata_bounds");
        byte[] out=new byte[count];
        ByteBuffer b=ByteBuffer.wrap(out);
        ch.position(position);
        while(b.hasRemaining()) {
            int n=ch.read(b);
            if(n<=0)throw new IOException("zip_metadata_read_failed");
        }
        return out;
    }
    private static int findEocd(byte[] b) {
        for(int p=b.length-22;p>=0;p--) {
            if(u32(b,p)==EOCD && p+22+u16(b,p+20)==b.length)return p;
        }
        return -1;
    }
    private static final class Directory {
        long count,start,length;
    }
    private static Directory directory(SeekableByteChannel ch) throws IOException {
        long size=ch.size();
        if(size<22)throw new IOException("zip_eocd_missing");
        int tailSize=(int)Math.min(size,MAX_EOCD_TAIL);
        byte[] tail=read(ch,size-tailSize,tailSize);
        int e=findEocd(tail);
        if(e<0)throw new IOException("zip_eocd_missing");
        if(u16(tail,e+4)!=0 || u16(tail,e+6)!=0)
            throw new IOException("zip_multivolume_not_supported");
        Directory d=new Directory();
        d.count=u16(tail,e+10);d.length=u32(tail,e+12);d.start=u32(tail,e+16);
        long physicalEocd=size-tailSize+e;
        if(d.count==65535 || d.length==U32 || d.start==U32) {
            if(physicalEocd<20)throw new IOException("zip64_locator_missing");
            byte[] locator=read(ch,physicalEocd-20,20);
            if(u32(locator,0)!=ZIP64_LOC || u32(locator,4)!=0 ||
                    u32(locator,16)!=1)throw new IOException("zip64_locator_invalid");
            long zip64Location=u64(locator,8);
            if(zip64Location>size-56 || zip64Location<0 ||
                    zip64Location>=physicalEocd-20)
                throw new IOException("zip64_record_bounds");
            byte[] zip64=read(ch,zip64Location,56);
            if(u32(zip64,0)!=ZIP64_END || u64(zip64,4)<44 ||
                    u32(zip64,16)!=0 || u32(zip64,20)!=0)
                throw new IOException("zip64_record_invalid");
            d.count=u64(zip64,32);
            d.length=u64(zip64,40);
            d.start=u64(zip64,48);
        }
        if(d.count>MAX_ENTRIES || d.length>MAX_DIRECTORY ||
           d.length>d.count*66000L+1024L || d.start>size ||
           d.length>size-d.start || d.start+d.length>physicalEocd ||
           d.length<d.count*46L)
            throw new IOException("zip_directory_budget_or_bounds");
        return d;
    }
    private static long[] resolveZip64Values(byte[] extra,
        long unpacked,long compressed,long localOffset) throws IOException {
        boolean a=unpacked==U32,b=compressed==U32,c=localOffset==U32;
        if(!a&&!b&&!c)return new long[]{unpacked,compressed,localOffset};
        int i=0;
        while(i+4<=extra.length) {
            int type=u16(extra,i),len=u16(extra,i+2);
            i+=4;
            if(len>extra.length-i)throw new IOException("zip64_extra_bounds");
            if(type==1) {
                int ptr=i,end=i+len;
                if(a) {if(ptr+8>end)throw new IOException("zip64_unpacked_missing");
                       unpacked=u64(extra,ptr);ptr+=8;}
                if(b) {if(ptr+8>end)throw new IOException("zip64_compressed_missing");
                       compressed=u64(extra,ptr);ptr+=8;}
                if(c) {if(ptr+8>end)throw new IOException("zip64_local_offset_missing");
                       localOffset=u64(extra,ptr);}
                return new long[]{unpacked,compressed,localOffset};
            }
            i+=len;
        }
        throw new IOException("zip64_extra_missing");
    }
    private static final class Member {
        long compressed,unpacked,localOffset;
        int flags,method;
    }
    private static Member findExe(SeekableByteChannel ch,Directory d) throws IOException {
        long ptr=d.start,end=d.start+d.length;
        Member found=null;
        for(long n=0;n<d.count;n++) {
            if(ptr>end-46)throw new IOException("zip_directory_truncated");
            byte[] h=read(ch,ptr,46);
            if(u32(h,0)!=CENTRAL)throw new IOException("zip_central_header_invalid");
            int flags=u16(h,8),method=u16(h,10);
            if((flags&1)!=0)throw new IOException("zip_encrypted_archive_not_supported");
            int nlen=u16(h,28),xlen=u16(h,30),clen=u16(h,32);
            long record=46L+nlen+xlen+clen;
            if(nlen==0 || nlen>8192 || record>end-ptr)
                throw new IOException("zip_member_metadata_bounds");
            byte[] nameBytes=read(ch,ptr+46,nlen);
            String name=new String(nameBytes,
                (flags&0x0800)!=0?StandardCharsets.UTF_8:
                java.nio.charset.Charset.forName("IBM437"));
            name=name.replace('\\','/').toLowerCase(Locale.ROOT);
            String leaf=name.substring(name.lastIndexOf('/')+1);
            if(leaf.equals("forzahorizon5.exe")) {
                if(found!=null)throw new IOException("zip_multiple_forza_exes");
                byte[] extra=read(ch,ptr+46+nlen,xlen);
                long[] values=resolveZip64Values(extra,u32(h,24),u32(h,20),u32(h,42));
                Member m=new Member();
                m.unpacked=values[0];m.compressed=values[1];
                m.localOffset=values[2];m.flags=flags;m.method=method;
                found=m;
            }
            ptr+=record;
        }
        if(found==null)throw new IOException("zip_forza_exe_not_found");
        return found;
    }
    private static byte[] decompressHeader(SeekableByteChannel ch,
            long dataAt,Member m) throws IOException {
        if(m.unpacked<256 || m.compressed<1)
            throw new IOException("zip_exe_size_too_small");
        if(m.compressed>ch.size()-dataAt)
            throw new IOException("zip_exe_payload_outside_archive");
        int wanted=(int)Math.min(m.unpacked,MAX_PREFIX);
        if(m.method==0) {
            if(m.compressed!=m.unpacked)
                throw new IOException("zip_stored_size_mismatch");
            return read(ch,dataAt,wanted);
        }
        if(m.method!=8)throw new IOException("zip_exe_compression_unsupported");
        byte[] result=new byte[wanted];
        byte[] input=new byte[8192];
        Inflater inflater=new Inflater(true);
        long compressedRead=0;
        int filled=0;
        try {
            while(filled<wanted) {
                if(inflater.needsInput()) {
                    long left=Math.min(m.compressed,MAX_COMPRESSED_INPUT)-compressedRead;
                    if(left<=0)break;
                    int n=(int)Math.min(input.length,left);
                    byte[] chunk=read(ch,dataAt+compressedRead,n);
                    inflater.setInput(chunk);
                    compressedRead+=n;
                }
                int n=inflater.inflate(result,filled,wanted-filled);
                filled+=n;
                if(inflater.finished())break;
                if(n==0&&!inflater.needsInput()) {
                    if(inflater.needsDictionary())
                        throw new IOException("zip_deflate_dictionary_unsupported");
                    throw new IOException("zip_deflate_stalled");
                }
            }
        } catch(DataFormatException ex) {
            throw new IOException("zip_exe_deflate_corrupt",ex);
        } finally {inflater.end();}
        if(filled<256)throw new IOException("zip_exe_header_unavailable");
        if(filled==wanted)return result;
        byte[] cut=new byte[filled];
        System.arraycopy(result,0,cut,0,filled);
        return cut;
    }
    private static Result readPe(byte[] b,long archiveBytes,Member m) throws IOException {
        if(b.length<256 || b[0]!='M' || b[1]!='Z')
            throw new IOException("pe_dos_magic_invalid");
        long nt=u32(b,0x3c);
        if(nt> b.length-24 || nt+24>=b.length)
            throw new IOException("pe_nt_header_not_in_prefix");
        int p=(int)nt;
        if(b[p]!='P' || b[p+1]!='E' || b[p+2]!=0 || b[p+3]!=0)
            throw new IOException("pe_signature_invalid");
        int machine=u16(b,p+4);
        int sections=u16(b,p+6);
        int optSize=u16(b,p+20);
        int opt=p+24;
        if(sections==0 || sections>96 || optSize<136 ||
           optSize>b.length-opt)
            throw new IOException("pe_optional_header_bounds");
        if(u16(b,opt)!=0x20b)
            throw new IOException("pe_not_pe32plus");
        if(machine!=0x8664)
            throw new IOException("pe_not_amd64");
        long entry=u32(b,opt+16);
        long imageSize=u32(b,opt+56);
        int subsystem=u16(b,opt+68);
        long rva=u32(b,opt+120),impSize=u32(b,opt+124);
        long directoryCount=u32(b,opt+108);
        if(directoryCount<2) {rva=0;impSize=0;}
        if(entry==0 || imageSize==0)
            throw new IOException("pe_entry_or_image_size_invalid");
        return new Result(archiveBytes,m.compressed,m.unpacked,m.method,machine,
                sections,subsystem,entry,imageSize,rva,impSize,b.length);
    }
    public static Result inspect(SeekableByteChannel ch) throws IOException {
        Directory d=directory(ch);
        Member m=findExe(ch,d);
        if(m.localOffset>ch.size()-30)
            throw new IOException("zip_local_header_bounds");
        byte[] local=read(ch,m.localOffset,30);
        if(u32(local,0)!=LOCAL)
            throw new IOException("zip_local_signature_invalid");
        if((u16(local,6)&1)!=0 || u16(local,8)!=m.method)
            throw new IOException("zip_local_compression_mismatch");
        long dataAt=m.localOffset+30L+u16(local,26)+u16(local,28);
        if(dataAt>ch.size() || m.compressed>ch.size()-dataAt)
            throw new IOException("zip_local_payload_bounds");
        byte[] pePrefix=decompressHeader(ch,dataAt,m);
        return readPe(pePrefix,ch.size(),m);
    }

    /**
     * P2.3 read-only mapping of the *actual* game entrypoint bytes.
     * This never executes, stores, uploads, or JIT-maps bytes from the game.
     * Streams at most 256 MiB of uncompressed EXE output with ~128 KiB scratch.
     */
    public static final class EntryResult {
        public final Result pe;
        public final int sectionIndex, sampleLength;
        public final long entryFileOffset, bytesInflated, compressedBytesRead;
        public final String leadingOpcodeFamily;
        // Volatile diagnostic sample stays only inside the APK process and is
        // fed to a NON-EXECUTING translator probe. Never exported to reports.
        public final byte[] entrySample;
        private EntryResult(Result pe,int sectionIndex,long fileOffset,
                            long inflated,long compressedRead,byte[] sample) {
            this.pe=pe;
            this.sectionIndex=sectionIndex;
            this.entryFileOffset=fileOffset;
            this.bytesInflated=inflated;
            this.compressedBytesRead=compressedRead;
            this.entrySample=sample;
            this.sampleLength=sample.length;
            this.leadingOpcodeFamily=classifyLeadingOpcode(sample);
        }
    }
    private static String classifyLeadingOpcode(byte[] op) {
        if(op.length<1)return "missing";
        int a=op[0]&255;
        if(a==0xE9 || a==0xEB)return "relative-jump";
        if(a==0xE8)return "relative-call";
        if(a==0xC3 || a==0xC2)return "return";
        if(a==0xCC)return "int3-breakpoint";
        if(a==0x90)return "nop";
        if(a>=0x50 && a<=0x5f)return "push-or-pop";
        if(a==0x48 && op.length>=3) {
            int b=op[1]&255,c=op[2]&255;
            if(b==0x83 && c==0xEC)return "stack-sub-imm8";
            if(b==0x81 && c==0xEC)return "stack-sub-imm32";
            if(b==0x89 || b==0x8B)return "rex-mov-modrm";
            if(b==0x8D)return "rex-lea-modrm";
            return "rex-prefixed-other";
        }
        if(a>=0x40 && a<=0x4F)return "rex-prefix";
        if(a==0x0f)return "two-byte-opcode";
        if(a==0xf3 || a==0xf2)return "rep-prefix";
        if(a==0xff)return "group5-indirect";
        if(a==0xe0 || a==0xe1 || a==0xe2)return "loop";
        return "other-or-unclassified";
    }
    private static final int SAMPLE_LENGTH=128;
    private static final long MAX_INFLATE_OUT=256L*1024*1024;
    private static final int IN_BUFFER=65536;
    private static final int OUT_BUFFER=65536;

    private static final class Range {
        final byte[] bytes;
        final long outProcessed, compressedRead;
        Range(byte[] bytes,long out,long in){this.bytes=bytes;outProcessed=out;compressedRead=in;}
    }
    private static Range readUncompressedRange(SeekableByteChannel ch,long dataAt,
                  Member m,long first,int count) throws IOException {
        if(first<0 || count<=0 || count>1024 ||
           first>m.unpacked || count>m.unpacked-first)
            throw new IOException("pe_entry_range_out_of_exe");
        if(first+count>MAX_INFLATE_OUT)
            throw new IOException("pe_entry_exceeds_stream_budget");
        if(dataAt<0 || dataAt>ch.size() || m.compressed>ch.size()-dataAt)
            throw new IOException("zip_exe_payload_outside_archive");
        if(m.method==0) {
            if(m.compressed!=m.unpacked)throw new IOException("zip_stored_size_mismatch");
            return new Range(read(ch,dataAt+first,count),first+count,count);
        }
        if(m.method!=8)throw new IOException("zip_exe_compression_unsupported");
        Inflater inflater=new Inflater(true);
        byte[] inBuf=new byte[IN_BUFFER],outBuf=new byte[OUT_BUFFER],found=new byte[count];
        long readCompressed=0,processed=0;
        int copied=0;
        try {
            while(copied<count) {
                if(inflater.needsInput()) {
                    long remaining=m.compressed-readCompressed;
                    if(remaining<=0)throw new IOException("zip_entry_deflate_truncated");
                    int n=(int)Math.min(inBuf.length,remaining);
                    // One bounded Android SAF random read, no staging file created.
                    byte[] bytes=read(ch,dataAt+readCompressed,n);
                    System.arraycopy(bytes,0,inBuf,0,n);
                    inflater.setInput(inBuf,0,n);
                    readCompressed+=n;
                }
                int n=inflater.inflate(outBuf);
                if(n>0) {
                    long next=processed+n;
                    if(next>MAX_INFLATE_OUT || next>m.unpacked)
                        throw new IOException("zip_stream_output_budget");
                    long start=Math.max(processed,first);
                    long end=Math.min(next,first+count);
                    if(end>start) {
                        int from=(int)(start-processed),take=(int)(end-start);
                        System.arraycopy(outBuf,from,found,(int)(start-first),take);
                        copied+=take;
                    }
                    processed=next;
                } else if(inflater.finished())
                    throw new IOException("zip_exe_ended_before_entry");
                else if(inflater.needsDictionary())
                    throw new IOException("zip_deflate_dictionary_unsupported");
                else if(!inflater.needsInput())
                    throw new IOException("zip_deflate_stalled");
            }
        } catch(DataFormatException ex) {
            throw new IOException("zip_entry_deflate_corrupt",ex);
        } finally {inflater.end();}
        return new Range(found,processed,readCompressed);
    }
    private static long[] mapEntrypointToFile(byte[] prefix,long entry,long fileLength)
            throws IOException {
        long pe=u32(prefix,0x3c);
        if(pe>prefix.length-24)throw new IOException("pe_section_table_unavailable");
        int nt=(int)pe;
        int count=u16(prefix,nt+6),optSize=u16(prefix,nt+20);
        long sectionAt=pe+24L+optSize;
        if(count<1 || count>96 || sectionAt<0 || sectionAt+40L*count>prefix.length)
            throw new IOException("pe_section_table_bounds");
        for(int i=0;i<count;i++) {
            int p=(int)sectionAt+i*40;
            long virtualSize=u32(prefix,p+8);
            long virtualAddress=u32(prefix,p+12);
            long rawSize=u32(prefix,p+16);
            long rawOffset=u32(prefix,p+20);
            long characteristics=u32(prefix,p+36);
            long memorySize=Math.max(virtualSize,rawSize);
            if(entry>=virtualAddress && entry-virtualAddress<memorySize) {
                long delta=entry-virtualAddress;
                if((characteristics&0x20000000L)==0)
                    throw new IOException("pe_entry_section_not_executable");
                if(delta>=rawSize || rawOffset>fileLength ||
                   delta>fileLength-rawOffset ||
                   SAMPLE_LENGTH>fileLength-rawOffset-delta)
                    throw new IOException("pe_entry_not_backed_by_file");
                return new long[]{i,rawOffset+delta};
            }
        }
        throw new IOException("pe_entry_rva_unmapped");
    }
    public static EntryResult inspectEntry(SeekableByteChannel ch) throws IOException {
        return inspectAtRva(ch,-1);
    }

    /**
     * P2.6: resolve one confirmed direct call target RVA to its executable PE
     * section and stream 128 target bytes from the original ZIP64 member.
     * The sentinel -1 selects the original entrypoint; other negative values
     * are refused. No target is executed or saved to shared storage.
     */
    public static EntryResult inspectAtRva(SeekableByteChannel ch,long targetRva)
            throws IOException {
        if(targetRva < -1)throw new IOException("pe_target_rva_invalid");
        Directory d=directory(ch);
        Member m=findExe(ch,d);
        if(m.localOffset<0 || m.localOffset>ch.size()-30)
            throw new IOException("zip_local_header_bounds");
        byte[] local=read(ch,m.localOffset,30);
        if(u32(local,0)!=LOCAL || (u16(local,6)&1)!=0 ||
           u16(local,8)!=m.method)
            throw new IOException("zip_local_header_invalid");
        long dataAt=m.localOffset+30L+u16(local,26)+u16(local,28);
        if(dataAt>ch.size() || m.compressed>ch.size()-dataAt)
            throw new IOException("zip_local_payload_bounds");
        byte[] pePrefix=decompressHeader(ch,dataAt,m);
        Result pe=readPe(pePrefix,ch.size(),m);
        long lookupRva=(targetRva==-1)?pe.entryPointRva:targetRva;
        if(lookupRva<=0 || lookupRva>=pe.imageSize)
            throw new IOException("pe_target_rva_outside_image");
        long[] mapped=mapEntrypointToFile(pePrefix,lookupRva,m.unpacked);
        Range range=readUncompressedRange(ch,dataAt,m,mapped[1],SAMPLE_LENGTH);
        return new EntryResult(pe,(int)mapped[0],mapped[1],
                range.outProcessed,range.compressedRead,range.bytes);
    }
}
