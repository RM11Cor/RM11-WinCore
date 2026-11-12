package com.rm11cor.carxstreet.portlab;

import java.io.IOException;

/**
 * Pure-Java, independently unit-testable Win64 UNWIND_INFO record layout.
 * No guest execution, no file IO, and no assumption that a pdata range
 * is a complete, callable Unity IL2CPP gameplay method.
 */
public final class Win64UnwindRecordFormat {
    private Win64UnwindRecordFormat() {}

    public static final int MAX_RECORD_BYTES=528;

    public static final class Descriptor {
        public final int version, flags, prologBytes, slotCount, byteLength;
        public final boolean chained, hasHandler;
        public final long chainedBeginRva, chainedEndRva, chainedUnwindRva;

        Descriptor(int version,int flags,int prolog,int slots,int size,
                   boolean chained,boolean handler,long b,long e,long u) {
            this.version=version;
            this.flags=flags;
            this.prologBytes=prolog;
            this.slotCount=slots;
            this.byteLength=size;
            this.chained=chained;
            this.hasHandler=handler;
            this.chainedBeginRva=b;
            this.chainedEndRva=e;
            this.chainedUnwindRva=u;
        }
    }

    private static void require(boolean valid,String reason)throws IOException {
        if(!valid)throw new IOException(reason);
    }

    private static long uint32(byte[] data,int offset) {
        return (data[offset]&255L)|((data[offset+1]&255L)<<8)|
                ((data[offset+2]&255L)<<16)|((data[offset+3]&255L)<<24);
    }

    /**
     * First pass on exactly the four-byte UNWIND_INFO header determines
     * a conservative exact record-length boundary for read-only SAF pread.
     */
    public static int requiredBytes(byte[] header)throws IOException {
        require(header!=null&&header.length>=4,"Win64 unwind header truncated");
        int version=header[0]&7, flags=(header[0]&255)>>>3;
        require(version==1,"unsupported Win64 UNWIND_INFO version");
        require((flags&~7)==0,"unsupported Win64 unwind flags");
        require(!((flags&4)!=0 && (flags&3)!=0),
                "invalid Win64 chained plus handler flags");
        int slots=header[2]&255;
        int bytes=(4+slots*2+3)&~3;
        if((flags&4)!=0)bytes+=12;
        else if((flags&3)!=0)bytes+=4;
        require(bytes>=4&&bytes<=MAX_RECORD_BYTES,
                "Win64 unwind record exceeds bounded source size");
        return bytes;
    }

    /** Second pass validates exact chain bounds. Handler payload is not read. */
    public static Descriptor inspect(byte[] raw)throws IOException {
        require(raw!=null&&raw.length>=4&&raw.length<=MAX_RECORD_BYTES,
                "invalid Win64 unwind record source length");
        int expected=requiredBytes(raw);
        require(raw.length==expected,"Win64 unwind record not complete");
        int version=raw[0]&7, flags=(raw[0]&255)>>>3;
        int slots=raw[2]&255;
        int offset=(4+slots*2+3)&~3;
        boolean chain=(flags&4)!=0, handler=(flags&3)!=0;
        long begin=0,end=0,unwind=0;
        if(chain) {
            begin=uint32(raw,offset);
            end=uint32(raw,offset+4);
            unwind=uint32(raw,offset+8);
            require(begin>0&&end>begin&&unwind>0,
                    "invalid Win64 chained RUNTIME_FUNCTION bounds");
        } else if(handler) {
            require(uint32(raw,offset)!=0,"invalid zero Win64 handler RVA");
        }
        return new Descriptor(version,flags,raw[1]&255,slots,raw.length,
                              chain,handler,begin,end,unwind);
    }
}
