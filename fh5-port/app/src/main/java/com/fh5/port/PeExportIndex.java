package com.fh5.port;

import java.io.IOException;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Read-only export table index for a Windows PE32+ AMD64 DLL.
 * Nothing is loaded, relocated, called, bound, or written to disk.
 */
public final class PeExportIndex {
    private PeExportIndex() {}
    public static final int MAX_EXPORT_FUNCTIONS=8192;
    public static final int MAX_EXPORT_NAMES=4096;
    public static final int MAX_EXPORT_NAME_SCAN_BYTES=1024;
    private static final int STRING_CHUNK=96;

    public static final class Result {
        public final String status;
        public final boolean complete;
        public final long ordinalBase;
        public final int exportedFunctions,exportedNames,forwardedFunctions;
        public final Map<String,Integer> namedOrdinalIndexes;
        public final Set<Integer> validOrdinalIndexes,forwardedOrdinalIndexes;
        private Result(String status,boolean complete,long ordinalBase,
                       int functions,int names,int forwarded,
                       Map<String,Integer> named,Set<Integer> ords,Set<Integer> forwardedOrds) {
            this.status=status;this.complete=complete;
            this.ordinalBase=ordinalBase;
            exportedFunctions=functions;exportedNames=names;
            forwardedFunctions=forwarded;
            namedOrdinalIndexes=Collections.unmodifiableMap(new HashMap<>(named));
            validOrdinalIndexes=Collections.unmodifiableSet(new HashSet<>(ords));
            forwardedOrdinalIndexes=Collections.unmodifiableSet(new HashSet<>(forwardedOrds));
        }
        public String lookupName(String name) {
            if(!complete)return "EXPORT_INDEX_INCOMPLETE";
            Integer ord=namedOrdinalIndexes.get(name);
            if(ord==null)return "NAMED_EXPORT_NOT_FOUND";
            return forwardedOrdinalIndexes.contains(ord)?"FORWARDED_EXPORT":"DIRECT_EXPORT_PRESENT";
        }
        public String lookupOrdinal(int ordinal) {
            if(!complete)return "EXPORT_INDEX_INCOMPLETE";
            long index=((long)ordinal)-ordinalBase;
            if(index<0||index>=exportedFunctions||!validOrdinalIndexes.contains((int)index))
                return "ORDINAL_EXPORT_NOT_FOUND";
            return forwardedOrdinalIndexes.contains((int)index)?"FORWARDED_EXPORT":"DIRECT_EXPORT_PRESENT";
        }
    }
    private static long u32(byte[] b,int at){return PeImportProbe.u32(b,at);}
    private static int u16(byte[] b,int at){
        return (b[at]&255)|((b[at+1]&255)<<8);
    }
    private static String readString(SeekableByteChannel ch,PeImportProbe.Mapper m,
                                     long rva,long imageSize) throws IOException {
        if(rva<=0||rva>=imageSize)throw new IOException("pe_exports_name_rva_invalid");
        StringBuilder sb=new StringBuilder();
        int count=0;
        while(count<MAX_EXPORT_NAME_SCAN_BYTES) {
            long pos=rva+count;
            if(pos>=imageSize)throw new IOException("pe_exports_name_image_bounds");
            int n=Math.min(Math.min(m.backedNameBytes(pos),STRING_CHUNK),
                MAX_EXPORT_NAME_SCAN_BYTES-count);
            if(n<1)throw new IOException("pe_exports_name_file_bounds");
            byte[] data=PeImportProbe.read(ch,m.map(pos,n),n);
            for(byte bb:data) {
                int c=bb&255;
                if(c==0) {
                    if(sb.length()<1)throw new IOException("pe_exports_name_empty");
                    return sb.toString();
                }
                if(c<33||c>126||c=='/'||c=='\\'||c=='"'||c=='<'
                    ||c=='>'||c=='{'||c=='}')
                    throw new IOException("pe_exports_name_char_invalid");
                sb.append((char)c);
                count++;
            }
        }
        throw new IOException("pe_exports_name_budget_exceeded");
    }
    public static Result inspect(SeekableByteChannel ch) throws IOException {
        PeDllHeaderValidator.Result dll=PeDllHeaderValidator.inspect(ch);
        if(!"PE64_AMD64_DLL_HEADER_VERIFIED".equals(dll.status))
            return new Result("NOT_AMD64_PE64_DLL",false,0,0,0,0,
                Collections.emptyMap(),Collections.emptySet(),Collections.emptySet());
        long size=ch.size();
        byte[] prefix=PeImportProbe.read(ch,0,
            (int)Math.min(size,PeImportProbe.MAX_PE_HEADER_BYTES));
        PeImportProbe.Mapper map=new PeImportProbe.Mapper(prefix,size);
        int nt=(int)u32(prefix,0x3c);
        int opt=nt+24;
        if(u32(prefix,opt+108)<1) {
            return new Result("NO_EXPORT_DIRECTORY",true,0,0,0,0,
                Collections.emptyMap(),Collections.emptySet(),Collections.emptySet());
        }
        long imageSize=u32(prefix,opt+56);
        long exportRva=u32(prefix,opt+112),exportBytes=u32(prefix,opt+116);
        if(exportRva==0||exportBytes==0)
            return new Result("NO_EXPORT_DIRECTORY",true,0,0,0,0,
                Collections.emptyMap(),Collections.emptySet(),Collections.emptySet());
        if(exportRva>=imageSize||exportBytes>imageSize-exportRva || exportBytes<40)
            throw new IOException("pe_exports_directory_image_bounds");
        byte[] dir=PeImportProbe.read(ch,map.map(exportRva,40),40);
        long base=u32(dir,16);
        long nFunctions=u32(dir,20),nNames=u32(dir,24);
        long functionRva=u32(dir,28),nameRva=u32(dir,32),ordinalRva=u32(dir,36);
        if(nFunctions>MAX_EXPORT_FUNCTIONS||nNames>MAX_EXPORT_NAMES)
            return new Result("EXPORT_INDEX_BUDGET_REACHED",false,base,
                (int)Math.min(nFunctions,MAX_EXPORT_FUNCTIONS),
                (int)Math.min(nNames,MAX_EXPORT_NAMES),0,
                Collections.emptyMap(),Collections.emptySet(),Collections.emptySet());
        if(nNames>nFunctions)throw new IOException("pe_exports_name_count_invalid");
        int functions=(int)nFunctions,names=(int)nNames;
        if(functions==0 && names==0)
            return new Result("EXPORT_TABLE_EMPTY",true,base,0,0,0,
                Collections.emptyMap(),Collections.emptySet(),Collections.emptySet());
        if(functionRva==0 || (names>0 && (nameRva==0||ordinalRva==0)))
            throw new IOException("pe_exports_table_missing");
        Set<Integer> available=new HashSet<>(),forwarded=new HashSet<>();
        long forwardedEnd=exportRva+exportBytes;
        for(int i=0;i<functions;i++) {
            long rva=functionRva+i*4L;
            if(rva>=imageSize||imageSize-rva<4)
                throw new IOException("pe_exports_functions_table_image_bounds");
            long fn=u32(PeImportProbe.read(ch,map.map(rva,4),4),0);
            if(fn==0)continue;
            if(fn>=imageSize)throw new IOException("pe_exports_function_rva_invalid");
            available.add(i);
            if(fn>=exportRva&&fn<forwardedEnd)forwarded.add(i);
        }
        Map<String,Integer> byName=new HashMap<>();
        for(int i=0;i<names;i++) {
            long item=nameRva+i*4L,ord=ordinalRva+i*2L;
            if(item>=imageSize||imageSize-item<4||ord>=imageSize||imageSize-ord<2)
                throw new IOException("pe_exports_names_table_image_bounds");
            long symbolRva=u32(PeImportProbe.read(ch,map.map(item,4),4),0);
            int idx=u16(PeImportProbe.read(ch,map.map(ord,2),2),0);
            if(idx>=functions)throw new IOException("pe_exports_ordinal_table_invalid");
            String symbol=readString(ch,map,symbolRva,imageSize);
            if(byName.containsKey(symbol) && !byName.get(symbol).equals(idx))
                throw new IOException("pe_exports_duplicate_name_ambiguous");
            byName.put(symbol,idx);
        }
        return new Result("EXPORT_INDEX_DECODED",true,base,functions,
            names,forwarded.size(),byName,available,forwarded);
    }
}
