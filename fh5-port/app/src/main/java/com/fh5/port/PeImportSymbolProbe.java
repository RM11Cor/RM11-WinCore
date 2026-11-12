package com.fh5.port;

import java.io.IOException;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * P3.6: nonexecuting PE32+ import lookup-table (ILT) inspection.
 * Actual DLL import function/ordinal counts, not just DLL filenames.
 *
 * Limits: 128 descriptors, 512 thunks per DLL, 8192 total, at most
 * six sanitized sample function names per DLL; no user paths, game bytes,
 * IAT binding, memory mapping or process execution.
 */
public final class PeImportSymbolProbe {
    private PeImportSymbolProbe() {}
    public static final int MAX_THUNKS_PER_DLL=512;
    public static final int MAX_TOTAL_THUNKS=8192;
    public static final int MAX_SAMPLE_NAMES=6;
    private static final int MAX_SYMBOL_BYTES=96;
    private static final long ORDINAL_FLAG=Long.MIN_VALUE;

    public static final class Dll {
        public final String dll;
        public final int namedImports, ordinalImports;
        public final boolean thunkTableComplete;
        public final List<String> exampleFunctions;
        private Dll(String dll,int named,int ordinal,boolean complete,
                    List<String> examples) {
            this.dll=dll;
            namedImports=named;ordinalImports=ordinal;
            thunkTableComplete=complete;
            exampleFunctions=Collections.unmodifiableList(new ArrayList<>(examples));
        }
    }
    public static final class Report {
        public final String status;
        public final int totalNamedImports,totalOrdinalImports;
        public final int dllsChecked;
        public final boolean complete,gameExecuted=false;
        public final List<Dll> dlls;
        private Report(String status,List<Dll> dlls,int named,int ord,boolean complete) {
            this.status=status;
            this.dlls=Collections.unmodifiableList(new ArrayList<>(dlls));
            dllsChecked=dlls.size();
            totalNamedImports=named;totalOrdinalImports=ord;this.complete=complete;
        }
    }
    private static long u64(byte[] b) {
        long result=0;
        for(int i=0;i<8;i++)result|=(b[i]&255L)<<(8*i);
        return result;
    }
    private static String functionName(SeekableByteChannel ch,
                    PeImportProbe.Mapper map,long rva,long imageSize) throws IOException {
        if(rva<=0||rva>=imageSize||imageSize-rva<3)
            throw new IOException("pe_symbol_function_rva_invalid");
        // IMAGE_IMPORT_BY_NAME: 2-byte hint followed by null-terminated name.
        PeImportProbe.read(ch,map.map(rva,2),2);
        int bounded=map.backedNameBytes(rva+2);
        if(bounded<2)throw new IOException("pe_symbol_function_name_unbacked");
        bounded=Math.min(bounded,MAX_SYMBOL_BYTES+1);
        byte[] src=PeImportProbe.read(ch,map.map(rva+2,1),bounded);
        int end=0;
        while(end<src.length&&src[end]!=0) {
            int c=src[end]&255;
            // PE decorated names may include ? $ @ . and underscores.
            // No newlines, control characters, separators or paths.
            if(c<33||c>126||c=='/'||c=='\\'||c=='"'||c=='<'
                ||c=='>'||c=='{'||c=='}')
                throw new IOException("pe_symbol_function_name_invalid");
            end++;
        }
        if(end<1||end>=src.length||end>MAX_SYMBOL_BYTES)
            throw new IOException("pe_symbol_function_name_unterminated");
        return new String(src,0,end,StandardCharsets.US_ASCII);
    }
    public static Report inspectDirect(SeekableByteChannel ch) throws IOException {
        PeImportProbe.Result imports=PeImportProbe.inspectDirect(ch);
        if(!imports.importsPresent)
            return new Report("NO_STATIC_IMPORT_DIRECTORY",
                Collections.emptyList(),0,0,true);
        if(!imports.complete)
            return new Report("IMPORT_DESCRIPTOR_LIST_INCOMPLETE",
                Collections.emptyList(),0,0,false);
        GameExeHeaderProbe.Result pe=GameExeHeaderProbe.inspectDirectHeader(ch);
        long size=ch.size();
        byte[] prefix=PeImportProbe.read(ch,0,
            (int)Math.min(size,PeImportProbe.MAX_PE_HEADER_BYTES));
        PeImportProbe.Mapper map=new PeImportProbe.Mapper(prefix,size);
        long maxByDir=pe.importDirectorySize/20;
        int descriptorLimit=(int)Math.min(PeImportProbe.MAX_DLL_DESCRIPTORS,maxByDir);
        List<Dll> details=new ArrayList<>();
        int totalNamed=0,totalOrdinal=0,total=0;
        boolean allComplete=true, descriptorTerminated=false;
        for(int i=0;i<descriptorLimit;i++) {
            long descriptorRva=pe.importDirectoryRva+i*20L;
            if(descriptorRva>=pe.imageSize || pe.imageSize-descriptorRva<20)
                throw new IOException("pe_symbol_descriptor_outside_image");
            byte[] desc=PeImportProbe.read(ch,map.map(descriptorRva,20),20);
            boolean zero=true;
            for(byte x:desc)if(x!=0){zero=false;break;}
            if(zero){descriptorTerminated=true;break;}
            if(i>=imports.dllNames.size())
                throw new IOException("pe_symbol_descriptor_count_mismatch");
            // OriginalFirstThunk (ILT) is preferred; fallback to FirstThunk.
            // Reading never writes or binds an IAT.
            long thunkRva=PeImportProbe.u32(desc,0);
            if(thunkRva==0)thunkRva=PeImportProbe.u32(desc,16);
            int named=0,ordinal=0;
            boolean tableComplete=false;
            List<String> examples=new ArrayList<>();
            if(thunkRva>0 && thunkRva<pe.imageSize) {
                for(int j=0;j<MAX_THUNKS_PER_DLL && total<MAX_TOTAL_THUNKS;j++) {
                    long itemRva=thunkRva+8L*j;
                    if(itemRva>=pe.imageSize || pe.imageSize-itemRva<8)
                        throw new IOException("pe_symbol_thunk_outside_image");
                    long value=u64(PeImportProbe.read(ch,map.map(itemRva,8),8));
                    if(value==0){tableComplete=true;break;}
                    total++;
                    if((value&ORDINAL_FLAG)!=0) {
                        // Ordinal flag is the only permitted high bit. PE docs
                        // reserve other bits; do not interpret bogus pointers.
                        if((value&~(ORDINAL_FLAG|0xffffL))!=0)
                            throw new IOException("pe_symbol_ordinal_bits_invalid");
                        ordinal++;totalOrdinal++;
                    } else {
                        if((value>>>32)!=0)
                            throw new IOException("pe_symbol_unbound_thunk_invalid");
                        String name=functionName(ch,map,value,pe.imageSize);
                        if(examples.size()<MAX_SAMPLE_NAMES)examples.add(name);
                        named++;totalNamed++;
                    }
                }
            }
            if(!tableComplete)allComplete=false;
            details.add(new Dll(imports.dllNames.get(i),
                named,ordinal,tableComplete,examples));
        }
        boolean complete=allComplete&&descriptorTerminated
            &&details.size()==imports.descriptorCount;
        return new Report(complete?"IMPORT_SYMBOLS_DECODED":
            "IMPORT_SYMBOLS_INCOMPLETE_OR_BUDGET_REACHED",
            details,totalNamed,totalOrdinal,complete);
    }
}
