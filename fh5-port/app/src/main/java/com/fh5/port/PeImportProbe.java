package com.fh5.port;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;

/**
 * P3.4: Bounded PE32+ Import Directory parser for an extracted Windows EXE.
 *
 * This is metadata only: no DLL loads, Windows API calls, machine-code
 * execution, import address binding, Steam activation, or code export.
 * The parser only reads an existing SAF-granted seekable channel.
 */
public final class PeImportProbe {
    private PeImportProbe() { }
    public static final int MAX_DLL_DESCRIPTORS=128;
    public static final int MAX_DLL_NAME_BYTES=128;
    public static final int MAX_PE_HEADER_BYTES=256*1024;
    private static final long MAX_EXE_BYTES=1024L*1024*1024;
    private static final int MAX_SECTIONS=96;
    private static final int DESCRIPTOR_SIZE=20;

    public static final class Result {
        public final String stage="P3_4_PE64_STATIC_IMPORT_DIRECTORY_READ_ONLY";
        public final String status;
        public final long directoryRva, directoryBytes, sourceFileBytes;
        public final int descriptorCount, uniqueNameCount;
        public final boolean importsPresent, complete, noOriginalGameExecution;
        public final List<String> dllNames;
        private Result(String status,long rva,long size,long total,
                       List<String> names,int descriptors,boolean complete) {
            this.status=status;directoryRva=rva;directoryBytes=size;
            sourceFileBytes=total;descriptorCount=descriptors;
            dllNames=Collections.unmodifiableList(new ArrayList<>(names));
            uniqueNameCount=dllNames.size();
            importsPresent=rva!=0 && size!=0;
            this.complete=complete;
            noOriginalGameExecution=true;
        }
    }
    private static int u16(byte[] b,int i) {
        return (b[i]&255)|((b[i+1]&255)<<8);
    }
    static long u32(byte[] b,int i) {
        return (long)u16(b,i)|((long)u16(b,i+2)<<16);
    }
    static byte[] read(SeekableByteChannel ch,long off,int len)
            throws IOException {
        if(off<0||len<0||off>ch.size()||len>ch.size()-off)
            throw new IOException("pe_import_file_bounds");
        byte[] out=new byte[len];
        ByteBuffer b=ByteBuffer.wrap(out);
        ch.position(off);
        while(b.hasRemaining()) {
            if(ch.read(b)<=0)throw new IOException("pe_import_read_failed");
        }
        return out;
    }

    /** PE32+ RVA -> raw-file offset: no relocations, no section execution. */
    static final class Mapper {
        final long fileSize,headersSize;
        final byte[] prefix;
        final int count,sectionTable;
        Mapper(byte[] prefix,long fileSize) throws IOException {
            this.prefix=prefix;this.fileSize=fileSize;
            if(prefix.length<256 || prefix[0]!='M'||prefix[1]!='Z')
                throw new IOException("pe_import_mz_invalid");
            long nt=u32(prefix,0x3c);
            if(nt>prefix.length-24)throw new IOException("pe_import_nt_bounds");
            int p=(int)nt;
            if(prefix[p]!='P'||prefix[p+1]!='E'||
               prefix[p+2]!=0||prefix[p+3]!=0)
                throw new IOException("pe_import_signature_invalid");
            count=u16(prefix,p+6);
            if(count<1||count>MAX_SECTIONS)throw new IOException("pe_import_sections_invalid");
            int optLen=u16(prefix,p+20),opt=p+24;
            if(optLen<136||optLen>prefix.length-opt||
               u16(prefix,opt)!=0x20b || u16(prefix,p+4)!=0x8664)
                throw new IOException("pe_import_optional_header_invalid");
            headersSize=u32(prefix,opt+60);
            long table=(long)opt+optLen;
            if(table>prefix.length || 40L*count>prefix.length-table)
                throw new IOException("pe_import_section_table_bounds");
            sectionTable=(int)table;
        }
        long map(long rva,int wanted) throws IOException {
            if(wanted<1||wanted>MAX_DLL_NAME_BYTES+1)
                throw new IOException("pe_import_sample_budget");
            if(rva<headersSize && rva<=prefix.length &&
               wanted<=headersSize-rva && wanted<=fileSize-rva)
                return rva;
            for(int i=0;i<count;i++) {
                int p=sectionTable+40*i;
                long vsize=u32(prefix,p+8),base=u32(prefix,p+12);
                long rawLen=u32(prefix,p+16),raw=u32(prefix,p+20);
                long mappedSize=Math.max(vsize,rawLen);
                if(rva>=base && rva-base<mappedSize) {
                    long delta=rva-base;
                    if(raw>fileSize || delta>rawLen || wanted>rawLen-delta ||
                       delta>fileSize-raw || wanted>fileSize-raw-delta)
                        throw new IOException("pe_import_unbacked_rva");
                    return raw+delta;
                }
            }
            throw new IOException("pe_import_rva_unmapped");
        }
        int backedNameBytes(long rva) throws IOException {
            if(rva<headersSize && rva<prefix.length)
                return (int)Math.min(MAX_DLL_NAME_BYTES+1,
                    Math.min(headersSize-rva,fileSize-rva));
            for(int i=0;i<count;i++) {
                int p=sectionTable+40*i;
                long vsize=u32(prefix,p+8),base=u32(prefix,p+12);
                long rawLen=u32(prefix,p+16),raw=u32(prefix,p+20);
                if(rva>=base && rva-base<Math.max(vsize,rawLen)) {
                    long delta=rva-base;
                    if(raw>fileSize||delta>=rawLen||delta>=fileSize-raw)
                        throw new IOException("pe_import_name_unbacked");
                    return (int)Math.min(MAX_DLL_NAME_BYTES+1,
                            Math.min(rawLen-delta,fileSize-raw-delta));
                }
            }
            throw new IOException("pe_import_name_unmapped");
        }
    }
    private static String readDllName(SeekableByteChannel ch,Mapper m,long rva)
            throws IOException {
        int length=m.backedNameBytes(rva);
        if(length<2)throw new IOException("pe_import_name_unbacked");
        byte[] raw=read(ch,m.map(rva,1),length);
        int end=0;
        while(end<raw.length && raw[end]!=0) {
            int c=raw[end]&255;
            if(!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||
                 (c>='0'&&c<='9')||c=='.'||c=='_'||c=='-'))
                throw new IOException("pe_import_name_invalid_char");
            end++;
        }
        if(end==0||end==raw.length||end>MAX_DLL_NAME_BYTES)
            throw new IOException("pe_import_name_not_terminated");
        String name=new String(raw,0,end,StandardCharsets.US_ASCII);
        // Static PE images can refer to a path; do not allow leaking any path.
        if(name.indexOf('/')>=0||name.indexOf('\\')>=0)
            throw new IOException("pe_import_name_path_disallowed");
        return name.toLowerCase(Locale.ROOT);
    }

    public static Result inspectDirect(SeekableByteChannel ch) throws IOException {
        long size=ch.size();
        if(size<256||size>MAX_EXE_BYTES)
            throw new IOException("pe_import_exe_size_invalid");
        GameExeHeaderProbe.Result pe=GameExeHeaderProbe.inspectDirectHeader(ch);
        if(!pe.importsPresent)
            return new Result("NO_STATIC_IMPORT_DIRECTORY",0,0,size,
                    Collections.emptyList(),0,true);
        byte[] prefix=read(ch,0,(int)Math.min(size,MAX_PE_HEADER_BYTES));
        Mapper mapper=new Mapper(prefix,size);
        LinkedHashSet<String> names=new LinkedHashSet<>();
        int count=0;
        // The PE Directory Size may include descriptors beyond a short list.
        // Read each fixed-size descriptor only if fully inside its directory.
        long maxByDir=pe.importDirectorySize/DESCRIPTOR_SIZE;
        int max=(int)Math.min(MAX_DLL_DESCRIPTORS,maxByDir);
        boolean terminated=false;
        for(int i=0;i<max;i++) {
            long dRva=pe.importDirectoryRva+i*(long)DESCRIPTOR_SIZE;
            if(dRva>=pe.imageSize ||
               DESCRIPTOR_SIZE>pe.imageSize-dRva)
                throw new IOException("pe_import_directory_outside_image");
            byte[] record=read(ch,mapper.map(dRva,DESCRIPTOR_SIZE),DESCRIPTOR_SIZE);
            boolean zero=true;
            for(byte x:record)if(x!=0){zero=false;break;}
            if(zero){terminated=true;break;}
            long nameRva=u32(record,12);
            if(nameRva==0||nameRva>=pe.imageSize)
                throw new IOException("pe_import_invalid_name_rva");
            names.add(readDllName(ch,mapper,nameRva));
            count++;
        }
        String status=terminated?"STATIC_IMPORT_NAMES_DECODED":
            max==MAX_DLL_DESCRIPTORS?"IMPORT_DESCRIPTOR_COUNT_BUDGET_REACHED":
            "IMPORT_TERMINATOR_NOT_WITHIN_DIRECTORY_SIZE";
        return new Result(status,pe.importDirectoryRva,
            pe.importDirectorySize,size,new ArrayList<>(names),count,terminated);
    }
}
