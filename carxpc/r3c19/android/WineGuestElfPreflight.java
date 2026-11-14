package com.r4.carxpc;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * R3C19 Wine x86_64 Linux ELF read-only preflight for Android/Bionic app.
 *
 * Purpose: prove that the real SHA-pinned guest rootfs contains an actual
 * amd64 Linux ELF wine64, its exact host-incompatible Linux interpreter,
 * authentic PT_LOAD/DT_NEEDED metadata and a Windows PE64 kernel32.dll.
 *
 * Does NOT perform Wine execution, guest mmap, x86 JIT or Android execve.
 * Never passes untrusted guest pointers to Bionic or changes host TLS.
 */
public final class WineGuestElfPreflight {
    private static final String ROOTFS="wine-guest-x86_64";
    public static final String ROOTFS_SHA256=
        "86fafa2f5072aa2c47b7025ca591d945007584ecda37ae92eee208a95283f4b0";
    private static final String RECEIPT=".r4-rootfs-receipt";
    private static final String WINE="usr/lib/wine/wine64";
    private static final String PE="usr/lib/x86_64-linux-gnu/wine/x86_64-windows/kernel32.dll";
    private static final long MAX_EXEC_FILE=256L*1024*1024;
    private static final int MAX_PHDRS=128, MAX_DYN=1024*1024;
    private static final int PT_LOAD=1,PT_DYNAMIC=2,PT_INTERP=3,PT_GNU_STACK=0x6474e551;

    public static final class Elf {
        public final String name,sha256,interpreter;
        public final long fileSize,entryPoint;
        public final int loadSegments;
        public final boolean writableExecutableSegment,executableStack;
        public final List<String> dtNeeded;
        private Elf(String n,String h,String i,long bytes,long entry,int loads,
                    boolean wx,boolean xs,List<String> needed){
            name=n;sha256=h;interpreter=i;fileSize=bytes;entryPoint=entry;
            loadSegments=loads;writableExecutableSegment=wx;executableStack=xs;
            dtNeeded=Collections.unmodifiableList(needed);
        }
    }
    public static final class Result {
        public final String rootfsSha256, wineElfSha256, interpreterElfSha256,
                kernel32PeSha256, interpreter;
        public final int winePtLoadSegments, interpreterPtLoadSegments;
        public final List<String> wineDtNeeded, unresolvedImmediateLibraries;
        public final boolean realX86LinuxElfVerified, guestInterpreterElfVerified,
                kernel32Pe64Amd64Verified, immediateNeededLibrariesPresent;
        public final boolean guestLinuxX64Executed, androidWineExecuted,
                win64PeAndroidExecuted, carxGameBootProven, vulkanTrianglePresented;
        private Result(Elf w,Elf ld,String pe,List<String> missing){
            rootfsSha256=ROOTFS_SHA256;wineElfSha256=w.sha256;
            interpreterElfSha256=ld.sha256;kernel32PeSha256=pe;
            interpreter=w.interpreter;
            winePtLoadSegments=w.loadSegments;
            interpreterPtLoadSegments=ld.loadSegments;
            wineDtNeeded=w.dtNeeded;
            unresolvedImmediateLibraries=Collections.unmodifiableList(missing);
            realX86LinuxElfVerified=true;guestInterpreterElfVerified=true;
            kernel32Pe64Amd64Verified=true;
            immediateNeededLibrariesPresent=missing.isEmpty();
            guestLinuxX64Executed=false;androidWineExecuted=false;
            win64PeAndroidExecuted=false;carxGameBootProven=false;
            vulkanTrianglePresented=false;
        }
    }
    private static final class Segment{
        final int type, flags;
        final long offset,vaddr,filesz,memsz,align;
        Segment(int t,int f,long o,long v,long z,long m,long a){
            type=t;flags=f;offset=o;vaddr=v;filesz=z;memsz=m;align=a;
        }
    }

    private WineGuestElfPreflight(){}

    public static Result inspect(Path androidAppFilesDir)throws IOException{
        if(androidAppFilesDir==null)throw fail("FILES_DIR_NULL");
        Path owned=androidAppFilesDir.toAbsolutePath().normalize();
        if(!Files.isDirectory(owned,LinkOption.NOFOLLOW_LINKS)||
           Files.isSymbolicLink(owned))throw fail("INVALID_APP_PRIVATE_FILES_DIR");
        Path root=owned.resolve(ROOTFS);
        if(!Files.isDirectory(root,LinkOption.NOFOLLOW_LINKS) ||
            Files.isSymbolicLink(root))throw fail("GUEST_ROOTFS_NOT_INSTALLED");
        Path realOwned=owned.toRealPath();
        Path realRoot=root.toRealPath();
        if(!realRoot.getParent().equals(realOwned))
            throw fail("GUEST_ROOTFS_REPARSE_ESCAPE");
        Path receipt=source(realRoot,RECEIPT);
        if(Files.size(receipt)>8192)throw fail("GUEST_RECEIPT_TOO_LARGE");
        String stamp=new String(Files.readAllBytes(receipt),StandardCharsets.UTF_8);
        if(!stamp.startsWith("schema=r4.carx.r3c18.owned-linux-x64-rootfs.v1\n") ||
           !stamp.contains("\nsource_archive_sha256="+ROOTFS_SHA256+"\n"))
            throw fail("GUEST_ROOTFS_ORIGINAL_ARCHIVE_RECEIPT_UNTRUSTED");

        Path wine=source(realRoot,WINE);
        Elf x64=readElf(wine,WINE,true);
        if(x64.interpreter==null||!x64.interpreter.startsWith("/") ||
           x64.interpreter.contains("..") ||
           x64.interpreter.indexOf('\\')>=0)
            throw fail("GUEST_WINE_INTERPRETER_NOT_ABSOLUTE_LINUX");
        String interp=x64.interpreter.substring(1);
        Path interpreter=source(realRoot,interp);
        Elf loader=readElf(interpreter,interp,false);
        if(loader.interpreter!=null)
            throw fail("GUEST_DYNAMIC_INTERPRETER_HAS_ANOTHER_INTERPRETER");
        if(loader.loadSegments<1)
            throw fail("GUEST_LDSO_NO_PTLOAD");
        Path kernel32=source(realRoot,PE);
        String kh=checkKernel32PE64(kernel32);
        Path inf=source(realRoot,"usr/share/wine/wine.inf");
        if(Files.size(inf)<64)throw fail("GUEST_WINE_INF_MISSING_OR_TOO_SMALL");

        List<String> missing=new ArrayList<>();
        for(String name:x64.dtNeeded) {
            if(!hasNeeded(realRoot,name))missing.add(name);
        }
        return new Result(x64,loader,kh,missing);
    }

    // Anchored to app-private installed tree. Paths are compile-time constants,
    // guest ELF interpreter or DT_NEEDED names. Validate traversal and symlinks.
    private static Path source(Path root,String rel)throws IOException{
        if(rel==null||rel.isEmpty()||rel.startsWith("/")||rel.contains("\\")||
           rel.contains("//")||rel.length()>4096)
            throw fail("UNSAFE_GUEST_PATH");
        for(String p:rel.split("/",-1)) {
            if(p.isEmpty()||p.equals(".")||p.equals(".."))throw fail("GUEST_PATH_TRAVERSAL");
        }
        Path p=root.resolve(rel).normalize();
        if(!p.startsWith(root))throw fail("GUEST_PATH_OUTSIDE_ROOTFS");
        Path real;
        try{real=p.toRealPath();}
        catch(IOException e){throw new IOException("GUEST_FILE_NOT_FOUND:"+rel,e);}
        if(!real.startsWith(root))throw fail("GUEST_SYMLINK_ESCAPED_ROOTFS");
        if(!Files.isRegularFile(real,LinkOption.NOFOLLOW_LINKS))
            throw fail("GUEST_SOURCE_NOT_REGULAR_FILE");
        return real;
    }

    private static boolean hasNeeded(Path root,String lib)throws IOException{
        if(lib.isEmpty()||lib.contains("/")||lib.contains("\\")||lib.contains("..")||
           lib.length()>255)throw fail("UNSAFE_DT_NEEDED_NAME");
        String[] dirs={"lib/x86_64-linux-gnu/","usr/lib/x86_64-linux-gnu/",
            "lib64/","usr/lib64/","lib/","usr/lib/",
            "usr/lib/x86_64-linux-gnu/wine/x86_64-unix/"};
        for(String dir:dirs){
            try{
                Path p=source(root,dir+lib);
                if(Files.size(p)>0)return true;
            }catch(IOException e){
                if(!e.getMessage().startsWith("GUEST_FILE_NOT_FOUND:"))throw e;
            }
        }
        return false;
    }
    private static IOException fail(String code){return new IOException(code);}
    private static void within(long pos,long count,long size,String what)throws IOException{
        if(pos<0||count<0||pos>size||count>size-pos)throw fail("ELF_BOUNDS_"+what);
    }
    private static byte[] bytes(FileChannel f,long offset,int count)throws IOException {
        within(offset,count,f.size(),"READ");
        ByteBuffer b=ByteBuffer.allocate(count);
        while(b.hasRemaining()){
            int n=f.read(b,offset+b.position());
            if(n<0)throw fail("ELF_READ_EOF");
            if(n==0)throw fail("ELF_READ_STALL");
        }
        return b.array();
    }
    private static int u16(ByteBuffer b,int o){return b.getShort(o)&65535;}
    private static long u32(ByteBuffer b,int o){return b.getInt(o)&0xffffffffL;}
    private static long u64(ByteBuffer b,int o){
        long n=b.getLong(o);return n;
    }

    private static Elf readElf(Path path,String guestName,boolean requireInterp)
            throws IOException{
        long size=Files.size(path);
        if(size<64||size>MAX_EXEC_FILE)throw fail("GUEST_ELF_SIZE_REJECTED");
        try(FileChannel f=FileChannel.open(path,StandardOpenOption.READ)) {
            ByteBuffer h=ByteBuffer.wrap(bytes(f,0,64)).order(ByteOrder.LITTLE_ENDIAN);
            if(h.get(0)!=0x7f||h.get(1)!='E'||h.get(2)!='L'||h.get(3)!='F'||
               h.get(4)!=2||h.get(5)!=1||h.get(6)!=1)
                throw fail("NOT_LINUX_ELF64_LE");
            int type=u16(h,16),machine=u16(h,18);
            if(machine!=62 || (type!=2&&type!=3) || u32(h,20)!=1)
                throw fail("NOT_GUEST_AMD64_ELF_EXEC_OR_PIE");
            long entry=u64(h,24),phoff=u64(h,32);
            int phsize=u16(h,54),count=u16(h,56);
            if(phsize!=56||count<1||count>MAX_PHDRS)
                throw fail("INVALID_GUEST_ELF_PROGRAM_HEADERS");
            within(phoff,(long)count*56,size,"PHDRS");
            if(u16(h,52)!=64)throw fail("INVALID_ELF_EHSIZE");
            ByteBuffer ph=ByteBuffer.wrap(bytes(f,phoff,count*56)).order(ByteOrder.LITTLE_ENDIAN);
            List<Segment> segs=new ArrayList<>();
            Segment dynamic=null, interpreter=null;
            int loads=0;boolean wx=false,xs=false;
            for(int i=0;i<count;i++) {
                int at=i*56;
                int pt=(int)u32(ph,at),flags=(int)u32(ph,at+4);
                long off=u64(ph,at+8),vaddr=u64(ph,at+16);
                long files=u64(ph,at+32),mem=u64(ph,at+40),align=u64(ph,at+48);
                if(off<0||files<0||mem<0||vaddr<0||align<0)
                    throw fail("GUEST_ELF_UNSIGNED_OVERFLOW");
                if((pt==PT_LOAD||pt==PT_INTERP||pt==PT_DYNAMIC) &&
                   (files>mem||!safeRange(off,files,size)))
                    throw fail("GUEST_ELF_SEGMENT_SIZE_INVALID");
                Segment seg=new Segment(pt,flags,off,vaddr,files,mem,align);
                if(pt==PT_LOAD){
                    if(mem<=0||(flags&~7)!=0||(flags&3)==3)
                        throw fail("GUEST_ELF_WX_OR_BAD_PTLOAD");
                    if(align>1 && ((align&(align-1))!=0||off%align!=vaddr%align))
                        throw fail("GUEST_ELF_PTLOAD_ALIGNMENT_INVALID");
                    ++loads;segs.add(seg);
                }else if(pt==PT_INTERP){
                    if(interpreter!=null||files<2||files>4096)
                        throw fail("GUEST_INTERPRETER_INVALID");
                    interpreter=seg;
                }else if(pt==PT_DYNAMIC){
                    if(dynamic!=null||files>MAX_DYN||files%16!=0)
                        throw fail("GUEST_DYNAMIC_METADATA_INVALID");
                    dynamic=seg;
                }else if(pt==PT_GNU_STACK&&(flags&1)!=0)xs=true;
            }
            if(loads<1||loads>24||xs)throw fail("GUEST_ELF_NO_PTLOAD_OR_EXEC_STACK");
            String interp=null;
            if(interpreter!=null){
                byte[] raw=bytes(f,interpreter.offset,(int)interpreter.filesz);
                if(raw[raw.length-1]!=0)throw fail("ELF_INTERP_NOT_NUL_TERMINATED");
                for(int i=0;i<raw.length-1;i++)
                    if(raw[i]<32||raw[i]>126)throw fail("ELF_INTERP_CONTROL_BYTES");
                interp=new String(raw,0,raw.length-1,StandardCharsets.US_ASCII);
            }
            if(requireInterp&&interp==null)
                throw fail("WINE_MAIN_ELF_PT_INTERP_REQUIRED");
            List<String> needed=new ArrayList<>();
            if(dynamic!=null) {
                ByteBuffer dyn=ByteBuffer.wrap(bytes(f,dynamic.offset,(int)dynamic.filesz))
                    .order(ByteOrder.LITTLE_ENDIAN);
                long strtab=-1,strsz=-1;
                List<Long> offsets=new ArrayList<>();
                boolean nullTerminated=false;
                for(int i=0;i<dyn.limit();i+=16) {
                    long tag=u64(dyn,i),value=u64(dyn,i+8);
                    if(tag==0){nullTerminated=true;break;}
                    if(tag==1)offsets.add(value);
                    if(tag==5)strtab=value;
                    if(tag==10)strsz=value;
                }
                if(!nullTerminated)throw fail("DYNAMIC_NO_DT_NULL");
                if(!offsets.isEmpty()) {
                    if(strtab<0||strsz<1||strsz>MAX_DYN)
                        throw fail("DT_NEEDED_STRTAB_OR_SIZE_INVALID");
                    long offset=strtabFileOffset(segs,strtab,strsz);
                    byte[] table=bytes(f,offset,(int)strsz);
                    for(long nameOff:offsets){
                        if(nameOff<0||nameOff>=strsz)
                            throw fail("DT_NEEDED_NAME_OFFSET_INVALID");
                        int i=(int)nameOff,j=i;
                        while(j<table.length&&table[j]!=0){
                            if(table[j]<33||table[j]>126)
                                throw fail("DT_NEEDED_NON_ASCII_NAME");
                            ++j;
                        }
                        if(j==i||j==table.length||j-i>255)
                            throw fail("DT_NEEDED_NAME_UNTERMINATED");
                        String name=new String(table,i,j-i,StandardCharsets.US_ASCII);
                        if(name.contains("/")||name.contains("\\")||name.contains(".."))
                            throw fail("DT_NEEDED_NAME_PATH_REJECTED");
                        needed.add(name);
                    }
                }
            }
            return new Elf(guestName,sha256(path),interp,size,entry,loads,wx,xs,needed);
        }
    }
    private static boolean safeRange(long o,long n,long size){
        return o>=0&&n>=0&&o<=size&&n<=size-o;
    }
    private static long strtabFileOffset(List<Segment> segs,long vaddr,long count)
            throws IOException{
        for(Segment p:segs){
            if(vaddr>=p.vaddr && count<=p.filesz &&
               vaddr-p.vaddr<=p.filesz-count)
                return p.offset+(vaddr-p.vaddr);
        }
        throw fail("DT_STRTAB_NOT_FILE_BACKED_PTLOAD");
    }

    private static String checkKernel32PE64(Path p)throws IOException {
        try(FileChannel f=FileChannel.open(p,StandardOpenOption.READ)){
            if(f.size()<512||f.size()>MAX_EXEC_FILE)throw fail("KERNEL32_PE_SIZE_REJECTED");
            ByteBuffer mz=ByteBuffer.wrap(bytes(f,0,64)).order(ByteOrder.LITTLE_ENDIAN);
            if(mz.get(0)!='M'||mz.get(1)!='Z')throw fail("KERNEL32_NOT_MZ");
            long off=u32(mz,60);
            within(off,128,f.size(),"PE_NT_HEADER");
            ByteBuffer pe=ByteBuffer.wrap(bytes(f,off,128)).order(ByteOrder.LITTLE_ENDIAN);
            if(pe.get(0)!='P'||pe.get(1)!='E'||pe.get(2)!=0||pe.get(3)!=0)
                throw fail("KERNEL32_NOT_PE_SIGNATURE");
            if(u16(pe,4)!=0x8664||u16(pe,24)!=0x20b ||
               (u16(pe,22)&0x2000)==0)
                throw fail("KERNEL32_NOT_AMD64_PE32PLUS_DLL");
            return sha256(p);
        }
    }
    private static String sha256(Path file)throws IOException{
        MessageDigest digest;
        try{digest=MessageDigest.getInstance("SHA-256");}
        catch(NoSuchAlgorithmException e){throw new IllegalStateException(e);}
        try(InputStream in=Files.newInputStream(file)){
            byte[] block=new byte[65536];int n;
            while((n=in.read(block))!=-1){if(n>0)digest.update(block,0,n);}
        }
        StringBuilder s=new StringBuilder();
        for(byte b:digest.digest())s.append(String.format(java.util.Locale.ROOT,"%02x",b&255));
        return s.toString();
    }
}
