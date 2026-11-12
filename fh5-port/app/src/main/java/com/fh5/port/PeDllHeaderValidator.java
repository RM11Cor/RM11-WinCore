package com.fh5.port;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;

/** Read-only, bounded x64 PE DLL header validation, NOT LoadLibrary. */
public final class PeDllHeaderValidator {
    private PeDllHeaderValidator() {}
    public static final int MAX_HEADER_BYTES=8192;
    public static final class Result {
        public final String status;
        public final long fileBytes;
        public final boolean amd64,pe32Plus,dllFlag;
        private Result(String status,long bytes,boolean x64,boolean plus,boolean dll) {
            this.status=status;fileBytes=bytes;amd64=x64;pe32Plus=plus;dllFlag=dll;
        }
    }
    private static int u16(byte[] a,int p) {
        return (a[p]&255)|((a[p+1]&255)<<8);
    }
    private static long u32(byte[] a,int p) {
        return (u16(a,p)&65535L)|((u16(a,p+2)&65535L)<<16);
    }
    public static Result inspect(SeekableByteChannel ch) throws IOException {
        long size=ch.size();
        if(size<256||size>1024L*1024*1024)
            return new Result("DLL_FILE_SIZE_INVALID",size,false,false,false);
        int n=(int)Math.min(size,MAX_HEADER_BYTES);
        byte[] b=new byte[n];
        ByteBuffer buf=ByteBuffer.wrap(b);
        ch.position(0);
        while(buf.hasRemaining())if(ch.read(buf)<=0)
            throw new IOException("pe_dll_header_read_incomplete");
        if(b[0]!='M'||b[1]!='Z')
            return new Result("NOT_WINDOWS_MZ",size,false,false,false);
        long off=u32(b,0x3c);
        if(off<64||off>n-26)
            return new Result("PE_NT_HEADER_NOT_IN_BOUNDED_PREFIX",size,false,false,false);
        int pe=(int)off;
        if(b[pe]!='P'||b[pe+1]!='E'||b[pe+2]!=0||b[pe+3]!=0)
            return new Result("NOT_WINDOWS_PE",size,false,false,false);
        boolean amd64=u16(b,pe+4)==0x8664;
        boolean dllFlag=(u16(b,pe+22)&0x2000)!=0;
        boolean plus=u16(b,pe+24)==0x20b;
        String status=amd64&&plus&&dllFlag?"PE64_AMD64_DLL_HEADER_VERIFIED":
            "NOT_AMD64_PE32PLUS_DLL_HEADER";
        return new Result(status,size,amd64,plus,dllFlag);
    }
}
