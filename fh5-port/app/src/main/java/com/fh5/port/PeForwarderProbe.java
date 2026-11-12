package com.fh5.port;

import java.io.IOException;
import java.nio.channels.SeekableByteChannel;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * P3.9: Decodes forwarder strings from real local PE32+ AMD64 DLL export
 * address tables. Does not follow pointers, load any DLL, resolve API sets
 * or execute Windows/x64 code. The exported forwarder string is treated
 * solely as untrusted plain metadata.
 */
public final class PeForwarderProbe {
    private PeForwarderProbe() {}
    public static final int MAX_REQUESTED_FORWARDERS=16;
    public static final int MAX_FORWARDER_STRING_BYTES=512;
    private static final int READ_CHUNK=96;

    public static final class Target {
        public final String requestedImport,status,rawForwarder;
        public final String targetModule,targetFunction;
        public final boolean ordinal;
        Target(String request,String status,String raw,String module,
               String function,boolean ordinal) {
            this.requestedImport=request;this.status=status;rawForwarder=raw;
            targetModule=module;targetFunction=function;this.ordinal=ordinal;
        }
    }
    public static final class Result {
        public final String status;
        public final int requested,decoded,malformed;
        public final boolean complete,gameExecuted=false,iatModified=false;
        public final List<Target> targets;
        Result(List<Target> data,boolean complete) {
            targets=Collections.unmodifiableList(new ArrayList<>(data));
            requested=data.size();
            int good=0;
            for(Target t:data)if("FORWARDER_TARGET_DECODED".equals(t.status))good++;
            decoded=good;malformed=requested-good;this.complete=complete && good==requested;
            status=this.complete?"FORWARDER_TARGETS_DECODED":
                "FORWARDER_TARGETS_PARTIAL_OR_MALFORMED";
        }
    }
    private static long u32(byte[] b,int at) {return PeImportProbe.u32(b,at);}

    private static String readForwarder(SeekableByteChannel ch, PeImportProbe.Mapper m,
              long rva,long end,long imageSize) throws IOException {
        if(rva<=0||rva>=end||rva>=imageSize)
            throw new IOException("pe_forwarder_rva_outside_export_directory");
        StringBuilder text=new StringBuilder();
        int seen=0;
        while(seen<MAX_FORWARDER_STRING_BYTES) {
            long pos=rva+seen;
            if(pos>=end||pos>=imageSize)
                throw new IOException("pe_forwarder_not_terminated_in_directory");
            int length=Math.min(Math.min(m.backedNameBytes(pos),READ_CHUNK),
                (int)Math.min(end-pos,MAX_FORWARDER_STRING_BYTES-seen));
            if(length<=0)throw new IOException("pe_forwarder_string_file_bounds");
            byte[] chunk=PeImportProbe.read(ch,m.map(pos,length),length);
            for(byte b:chunk) {
                int c=b&255;
                if(c==0) {
                    if(text.length()==0)
                        throw new IOException("pe_forwarder_string_empty");
                    return text.toString();
                }
                if(c<33||c>126||c=='/'||c=='\\'||c=='"'||
                   c=='<'||c=='>'||c=='{'||c=='}')
                    throw new IOException("pe_forwarder_char_invalid");
                text.append((char)c);
                seen++;
            }
        }
        throw new IOException("pe_forwarder_string_over_budget");
    }
    private static Target parseTarget(String request,String raw) {
        int dot=raw.lastIndexOf('.');
        if(dot<=0||dot==raw.length()-1)
            return new Target(request,"FORWARDER_SYNTAX_INVALID",raw,"","",false);
        String module=raw.substring(0,dot);
        String symbol=raw.substring(dot+1);
        if(!module.matches("[A-Za-z0-9_.-]{1,120}"))
            return new Target(request,"FORWARDER_MODULE_INVALID",raw,"","",false);
        boolean isOrdinal=symbol.startsWith("#");
        if(isOrdinal) {
            if(!symbol.matches("#[0-9]{1,5}"))
                return new Target(request,"FORWARDER_ORDINAL_INVALID",raw,"","",true);
            try {
                int n=Integer.parseInt(symbol.substring(1));
                if(n>65535||n==0)
                    return new Target(request,"FORWARDER_ORDINAL_INVALID",raw,"","",true);
            } catch(NumberFormatException e) {
                return new Target(request,"FORWARDER_ORDINAL_INVALID",raw,"","",true);
            }
        } else if(!symbol.matches("[A-Za-z0-9_?$@.-]{1,250}")) {
            return new Target(request,"FORWARDER_SYMBOL_INVALID",raw,"","",false);
        }
        return new Target(request,"FORWARDER_TARGET_DECODED",raw,module,symbol,isOrdinal);
    }
    public static Result inspect(SeekableByteChannel dll,PeExportIndex.Result exports,
                                 Set<String> requestedNames) throws IOException {
        if(dll==null||exports==null||requestedNames==null)
            throw new IllegalArgumentException("pe_forwarder_null_input");
        if(requestedNames.size()>MAX_REQUESTED_FORWARDERS)
            throw new IOException("pe_forwarder_requested_budget");
        if(!exports.complete)
            throw new IOException("pe_forwarder_export_index_incomplete");
        if(!"PE64_AMD64_DLL_HEADER_VERIFIED".equals(PeDllHeaderValidator.inspect(dll).status))
            throw new IOException("pe_forwarder_not_amd64_dll");
        long fileLength=dll.size();
        byte[] prefix=PeImportProbe.read(dll,0,
            (int)Math.min(fileLength,PeImportProbe.MAX_PE_HEADER_BYTES));
        PeImportProbe.Mapper map=new PeImportProbe.Mapper(prefix,fileLength);
        int opt=(int)u32(prefix,0x3c)+24;
        long imageSize=u32(prefix,opt+56);
        long dirRva=u32(prefix,opt+112),dirBytes=u32(prefix,opt+116);
        if(dirRva==0||dirBytes<40||dirRva>=imageSize||
           dirBytes>imageSize-dirRva)
            throw new IOException("pe_forwarder_export_directory_bounds");
        long dirEnd=dirRva+dirBytes;
        byte[] dir=PeImportProbe.read(dll,map.map(dirRva,40),40);
        long eatRva=u32(dir,28);
        List<Target> targets=new ArrayList<>();
        boolean complete=true;
        for(String requested:new LinkedHashSet<>(requestedNames)) {
            if(requested==null||requested.length()>1024)
                throw new IOException("pe_forwarder_requested_name_invalid");
            if(!"FORWARDED_EXPORT".equals(exports.lookupName(requested))) {
                targets.add(new Target(requested,"NOT_A_FORWARDED_EXPORT","","","",false));
                complete=false;continue;
            }
            Integer index=exports.namedOrdinalIndexes.get(requested);
            if(index==null||index<0||index>=exports.exportedFunctions)
                throw new IOException("pe_forwarder_export_name_index_invalid");
            long address=eatRva+index*4L;
            if(address>=imageSize||imageSize-address<4)
                throw new IOException("pe_forwarder_eat_outside_image");
            long targetRva=u32(PeImportProbe.read(dll,map.map(address,4),4),0);
            String raw;
            try {
                raw=readForwarder(dll,map,targetRva,dirEnd,imageSize);
            } catch(IOException ex) {
                String error=ex.getMessage();
                if(error==null||!error.matches("pe_forwarder_[a-z0-9_]{2,90}"))
                    error="pe_forwarder_read_failure";
                targets.add(new Target(requested,error,"","","",false));
                complete=false;continue;
            }
            Target parsed=parseTarget(requested,raw);
            if(!"FORWARDER_TARGET_DECODED".equals(parsed.status))complete=false;
            targets.add(parsed);
        }
        return new Result(targets,complete);
    }
}
