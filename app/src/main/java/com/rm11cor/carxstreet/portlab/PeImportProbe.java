package com.rm11cor.carxstreet.portlab;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;

/**
 * Pure-Java bounded PE32/PE32+ import directory probe for original local
 * Windows PC executables. Uses random-access reads, NEVER loads/executes
 * Windows code. Not an ELF converter or Android game-runtime implementation.
 */
public final class PeImportProbe {
    private PeImportProbe() {}

    public interface Reader {
        byte[] readAt(long offset, int count) throws IOException;
    }

    public static final class Result {
        public boolean valid;
        public String architecture="not_verified";
        public String format="not_verified";
        public int sections=0;
        public boolean importDirectoryPresent=false;
        public boolean importDirectoryFullyRead=false;
        public boolean randomReadSupported=false;
        public final ArrayList<String> importedDlls=new ArrayList<>();
        public String error="";
    }

    private static final class Section {
        final long virtualAddress,virtualSize,rawOffset,rawSize;
        Section(long va,long vs,long off,long size) {
            virtualAddress=va; virtualSize=vs;rawOffset=off;rawSize=size;
        }
    }

    public static Result inspect(Reader reader,long length) {
        Result result=new Result();
        try {
            check(reader!=null && length>=256 && length<=1_073_741_824L,
                    "missing reader or file-size out of 1GiB inspection bound");
            // Read a bounded PE header, never entire 142MB GameAssembly.dll.
            int count=(int)Math.min(length,131072);
            byte[] h=read(reader,0,count,length);
            check(h[0]=='M'&&h[1]=='Z',"missing original MZ header");
            long peoff=u32(h,0x3c);
            check(peoff>=64 && peoff+24<=h.length,"PE header offset out of bounds");
            int offset=(int)peoff;
            check(h[offset]=='P' && h[offset+1]=='E' &&
                    h[offset+2]==0 && h[offset+3]==0,"invalid PE signature");
            int machine=u16(h,offset+4);
            int nsections=u16(h,offset+6);
            int opts=u16(h,offset+20);
            check(nsections>=1 && nsections<=128,"invalid section count");
            int optional=offset+24;
            check(opts>=112 && optional+opts<=h.length,
                    "PE optional header out of bounds");
            int magic=u16(h,optional);
            check(magic==0x20b||magic==0x10b,"not a PE32/PE32+ header");
            int directory=optional+(magic==0x20b?112:96);
            check(directory+16<=optional+opts,"missing import data directory");
            int sectionStart=optional+opts;
            check(sectionStart+nsections*40<=h.length,"section table truncated");
            List<Section> sections=new ArrayList<>();
            for(int i=0;i<nsections;i++) {
                int at=sectionStart+40*i;
                long vsize=u32(h,at+8);
                long va=u32(h,at+12);
                long rawSize=u32(h,at+16);
                long rawOffset=u32(h,at+20);
                check(rawSize==0||rawOffset<=length&&rawSize<=length-rawOffset,
                        "section raw bytes outside game file");
                sections.add(new Section(va,vsize,rawOffset,rawSize));
            }
            result.architecture=machine==0x8664?"Windows-PE-x86_64":
                    machine==0xAA64?"Windows-PE-ARM64":
                    machine==0x14c?"Windows-PE-x86":"Windows-PE-other-"+machine;
            result.format=magic==0x20b?"PE32+":"PE32";
            result.sections=nsections;
            result.valid=true;
            long importRva=u32(h,directory+8);
            long importSize=u32(h,directory+12);
            result.importDirectoryPresent=importRva!=0;
            if(importRva==0) {
                result.importDirectoryFullyRead=true;
                result.randomReadSupported=true;
                return result;
            }
            check(importSize>=20&&importSize<=65_536L,
                    "invalid or too-large PE import directory");
            long importOffset=rvaToFile(importRva,(int)importSize,length,sections);
            byte[] raw=read(reader,importOffset,(int)importSize,length);
            result.randomReadSupported=true;
            LinkedHashSet<String> names=new LinkedHashSet<>();
            boolean terminator=false;
            int max=Math.min(256,raw.length/20);
            for(int i=0;i<max;i++) {
                int off=i*20;
                long originalThunk=u32(raw,off);
                long date=u32(raw,off+4);
                long chain=u32(raw,off+8);
                long nameRva=u32(raw,off+12);
                long importThunk=u32(raw,off+16);
                if((originalThunk|date|chain|nameRva|importThunk)==0) {
                    terminator=true;
                    break;
                }
                check(nameRva!=0,"PE import descriptor missing DLL name");
                long pathOffset=rvaToFile(nameRva,1,length,sections);
                byte[] name=read(reader,pathOffset,(int)Math.min(257L,length-pathOffset),
                        length);
                int end=0;
                while(end<name.length&&name[end]!=0&&end<=256) {
                    check((name[end]&255)>=32&&(name[end]&255)<127,
                            "nonprinting PE DLL import name");
                    end++;
                }
                check(end>0&&end<=256&&end<name.length,
                        "unterminated or oversized PE DLL name");
                String nameValue=new String(name,0,end,StandardCharsets.US_ASCII)
                        .toLowerCase(Locale.ROOT);
                names.add(nameValue);
            }
            check(terminator,"PE imports truncated or have no terminating entry");
            result.importedDlls.addAll(names);
            Collections.sort(result.importedDlls);
            result.importDirectoryFullyRead=true;
        } catch(Exception failure) {
            result.error=failure.getClass().getSimpleName()+": "+failure.getMessage();
            result.importDirectoryFullyRead=false;
            result.importedDlls.clear();
        }
        return result;
    }

    private static long rvaToFile(long target,int required,long fileSize,
                                  List<Section> sections) throws IOException {
        check(target>0&&required>0,"invalid RVA");
        for(Section section:sections) {
            long cover=Math.max(section.virtualSize,section.rawSize);
            if(target>=section.virtualAddress && target-section.virtualAddress<cover) {
                long delta=target-section.virtualAddress;
                check(delta<=section.rawSize&&required<=section.rawSize-delta,
                        "PE RVA points beyond original file-backed section");
                long location=section.rawOffset+delta;
                check(location<=fileSize&&required<=fileSize-location,
                        "PE RVA outside actual file");
                return location;
            }
        }
        throw new IOException("RVA not mapped to original PE file section");
    }

    private static byte[] read(Reader reader,long off,int count,long length)
            throws IOException {
        check(off>=0&&count>0&&off<=length&&count<=length-off,
                "read beyond game file");
        byte[] data=reader.readAt(off,count);
        check(data!=null&&data.length==count,"short read from source content provider");
        return data;
    }

    private static int u16(byte[] data,int pos)throws IOException {
        check(pos>=0&&pos+2<=data.length,"truncated PE uint16");
        return (data[pos]&255)|((data[pos+1]&255)<<8);
    }
    private static long u32(byte[] data,int pos)throws IOException {
        check(pos>=0&&pos+4<=data.length,"truncated PE uint32");
        return (data[pos]&255L)|((data[pos+1]&255L)<<8)|
                ((data[pos+2]&255L)<<16)|((data[pos+3]&255L)<<24);
    }
    private static void check(boolean yes,String reason)throws IOException {
        if(!yes)throw new IOException(reason);
    }
}
