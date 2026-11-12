package com.fh5.port;

import java.io.IOException;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * P3.8: Offline import-vs-export compatibility comparison.
 * All results are read-only observations, NOT in-process Windows IAT binding.
 * DLL import name/ordinal matches cannot prove ABI/function compatibility.
 */
public final class PeLocalImportLinkProbe {
    private PeLocalImportLinkProbe() {}
    public static final int MAX_TOTAL_IMPORTS=8192;
    public static final int MAX_PER_DLL=512;
    public static final int MAX_FULL_NAME_BYTES=1024;
    public static final int MAX_MISSING_SAMPLES=8;
    private static final long ORDINAL_FLAG=Long.MIN_VALUE;

    public static final class Entry {
        public final String dll,exportScanStatus;
        public final int namedRequested,ordinalRequested,directMatch,forwardMatch,notFound;
        public final boolean thunkTableComplete;
        public final List<String> missingExamples,forwardedImportNames;
        Entry(String dll,String status,int named,int ordinal,int direct,int forwarded,
              int missing,boolean complete,List<String> examples,List<String> forwardedNames){
            this.dll=dll;exportScanStatus=status;
            namedRequested=named;ordinalRequested=ordinal;
            directMatch=direct;forwardMatch=forwarded;notFound=missing;
            thunkTableComplete=complete;
            missingExamples=Collections.unmodifiableList(new ArrayList<>(examples));
            forwardedImportNames=Collections.unmodifiableList(new ArrayList<>(forwardedNames));
        }
    }
    public static final class Report {
        public final String status;
        public final boolean complete,executed=false,iatModified=false;
        public final int dllsAssessed,importsCompared,directMatches,forwardedMatches,notFound;
        public final List<Entry> dlls;
        Report(List<Entry> entries,boolean allComplete){
            dlls=Collections.unmodifiableList(new ArrayList<>(entries));
            dllsAssessed=entries.size();complete=allComplete;
            int req=0,ok=0,fwd=0,missing=0;
            for(Entry e:entries){
                req+=e.namedRequested+e.ordinalRequested;
                ok+=e.directMatch;fwd+=e.forwardMatch;missing+=e.notFound;
            }
            importsCompared=req;directMatches=ok;forwardedMatches=fwd;notFound=missing;
            status=allComplete?"OFFLINE_LOCAL_IMPORT_EXPORT_COMPARISON_COMPLETE":
                "OFFLINE_LOCAL_IMPORT_EXPORT_COMPARISON_PARTIAL";
        }
    }
    private static long u64(byte[] b) {
        long r=0;
        for(int i=0;i<8;i++)r|=(b[i]&255L)<<(i*8);
        return r;
    }
    private static String readSymbol(SeekableByteChannel ch,PeImportProbe.Mapper m,
                                     long rva,long imageSize) throws IOException {
        if(rva<=0||rva>=imageSize||imageSize-rva<3)
            throw new IOException("pe_link_symbol_rva_invalid");
        PeImportProbe.read(ch,m.map(rva,2),2); // hint
        StringBuilder s=new StringBuilder();
        int count=0;
        while(count<MAX_FULL_NAME_BYTES){
            long pos=rva+2L+count;
            if(pos>=imageSize)throw new IOException("pe_link_symbol_rva_outside_image");
            int n=Math.min(Math.min(m.backedNameBytes(pos),96),
                MAX_FULL_NAME_BYTES-count);
            if(n<1)throw new IOException("pe_link_symbol_name_unbacked");
            byte[] b=PeImportProbe.read(ch,m.map(pos,n),n);
            for(byte raw:b){
                int c=raw&255;
                if(c==0){
                    if(count<1)throw new IOException("pe_link_symbol_name_empty");
                    return s.toString();
                }
                if(c<33||c>126||c=='/'||c=='\\'||c=='"'
                    ||c=='<'||c=='>'||c=='{'||c=='}')
                    throw new IOException("pe_link_symbol_name_invalid");
                s.append((char)c);count++;
            }
        }
        throw new IOException("pe_link_symbol_name_longer_than_budget");
    }
    private static String safeSample(String name){
        return name.length()>75?name.substring(0,75)+" [truncated]":name;
    }
    /**
     * @param exports indexes of DLLs already verified to be the original
     *                sibling files beside ForzaHorizon5.exe.
     * @param localNames exact lowercased imported file names discovered
     *                with user-granted Android SAF tree listing.
     */
    public static Report inspect(SeekableByteChannel exe,
              Map<String,PeExportIndex.Result> exports,
              Set<String> localNames) throws IOException {
        if(exe==null||exports==null||localNames==null)
            throw new IllegalArgumentException("pe_link_null_input");
        PeImportProbe.Result imports=PeImportProbe.inspectDirect(exe);
        if(!imports.complete)
            throw new IOException("pe_link_import_descriptors_incomplete");
        GameExeHeaderProbe.Result pe=GameExeHeaderProbe.inspectDirectHeader(exe);
        long size=exe.size();
        PeImportProbe.Mapper mapper=new PeImportProbe.Mapper(
            PeImportProbe.read(exe,0,
                (int)Math.min(size,PeImportProbe.MAX_PE_HEADER_BYTES)),size);
        List<Entry> entries=new ArrayList<>();
        int total=0;
        boolean allComplete=true;
        for(int index=0;index<imports.descriptorCount;index++){
            String dll=imports.dllNames.get(index).toLowerCase(Locale.ROOT);
            if(!localNames.contains(dll))continue;
            long descRva=pe.importDirectoryRva+index*20L;
            byte[] d=PeImportProbe.read(exe,mapper.map(descRva,20),20);
            long thunk=PeImportProbe.u32(d,0);
            if(thunk==0)thunk=PeImportProbe.u32(d,16);
            PeExportIndex.Result exportsOfDll=exports.get(dll);
            boolean expComplete=exportsOfDll!=null&&exportsOfDll.complete;
            String exportStatus=exportsOfDll==null?"EXPORT_INDEX_UNAVAILABLE":
                exportsOfDll.status;
            if(!expComplete)allComplete=false;
            int named=0,ordinal=0,direct=0,forwarded=0,missing=0;
            boolean terminated=false;
            List<String> missingNames=new ArrayList<>(),forwardedNames=new ArrayList<>();
            if(thunk!=0&&thunk<pe.imageSize) {
                for(int j=0;j<MAX_PER_DLL&&total<MAX_TOTAL_IMPORTS;j++){
                    long rva=thunk+j*8L;
                    if(rva>=pe.imageSize||pe.imageSize-rva<8)
                        throw new IOException("pe_link_thunk_image_bounds");
                    long val=u64(PeImportProbe.read(exe,mapper.map(rva,8),8));
                    if(val==0){terminated=true;break;}
                    total++;
                    String match,name;
                    if((val&ORDINAL_FLAG)!=0){
                        if((val&~(ORDINAL_FLAG|0xffffL))!=0)
                            throw new IOException("pe_link_bad_ordinal_bits");
                        ordinal++;
                        int ordinalValue=(int)(val&0xffff);
                        match=expComplete?exportsOfDll.lookupOrdinal(ordinalValue):
                            "EXPORT_INDEX_INCOMPLETE";
                        name="#"+ordinalValue;
                    } else {
                        if(val>>>32!=0)throw new IOException("pe_link_bad_thunk_rva");
                        named++;
                        name=readSymbol(exe,mapper,val,pe.imageSize);
                        match=expComplete?exportsOfDll.lookupName(name):
                            "EXPORT_INDEX_INCOMPLETE";
                    }
                    if("DIRECT_EXPORT_PRESENT".equals(match))direct++;
                    else if("FORWARDED_EXPORT".equals(match)){
                        forwarded++;
                        if(forwardedNames.size()<16)forwardedNames.add(name);
                    }
                    else if(expComplete){
                        missing++;
                        if(missingNames.size()<MAX_MISSING_SAMPLES)
                            missingNames.add(safeSample(name));
                    }
                }
            }
            if(!terminated)allComplete=false;
            entries.add(new Entry(dll,exportStatus,named,ordinal,
                direct,forwarded,missing,terminated,missingNames,forwardedNames));
        }
        return new Report(entries,allComplete);
    }
}
