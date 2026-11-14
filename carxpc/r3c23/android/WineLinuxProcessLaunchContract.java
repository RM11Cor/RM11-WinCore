package com.r4.carxpc;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * R3C23 source-authentic Wine64 x86_64 Linux process launch CONTRACT.
 *
 * This builds an actual ABI-formatted synthetic GUEST STACK IMAGE:
 * argc/argv[]/envp[]/auxv[], AT_PHDR/AT_BASE/AT_ENTRY/AT_RANDOM/AT_EXECFN,
 * using source SHA-256-authenticated Wine64 + GNU interpreter ELFs.
 *
 * All addresses are a purely VIRTUAL PLAN and never host-mapped by this
 * class; bytes are never executed by FEX, Wine, Android linker or kernel.
 * Separate on-device native memory reservation, FEX context, syscall
 * dispatcher and wineserver process bridge are required before running Wine.
 * No shortcuts using Bionic execve of downloaded Linux-x86_64 binaries.
 */
public final class WineLinuxProcessLaunchContract {
    public static final long MAIN_BIAS=0x0000004000000000L;
    public static final long LDSO_BIAS=0x0000004100000000L;
    public static final long STACK_TOP=0x0000007000000000L;
    public static final int STACK_BYTES=65536;
    public static final String GUEST_EXECFN="/usr/lib/wine/wine64";
    private static final String WINE="usr/lib/wine/wine64";
    private static final int PT_LOAD=1,PT_PHDR=6;
    private static final int PF_X=1,PF_W=2;
    private static final long AT_NULL=0,AT_PHDR=3,AT_PHENT=4,AT_PHNUM=5,
        AT_PAGESZ=6,AT_BASE=7,AT_ENTRY=9,AT_UID=11,AT_EUID=12,
        AT_GID=13,AT_EGID=14,AT_RANDOM=25,AT_EXECFN=31;
    private static final long USER_VA_LIMIT=0x00007fffffffffffL;
    private WineLinuxProcessLaunchContract(){}

    public static final class Segment {
        public final long fileOffset,guestVaddr,fileBytes,memoryBytes,alignment;
        public final int flags;
        private Segment(long off,long va,long fs,long ms,long align,int f){
            fileOffset=off;guestVaddr=va;fileBytes=fs;memoryBytes=ms;
            alignment=align;flags=f;
        }
    }
    public static final class Elf {
        public final String sourcePath;
        public final long fileSize,entry,programHeaderVaddr;
        public final int type,programHeaderBytes,programHeaderCount,programHeaderEntryBytes;
        public final List<Segment> loadSegments;
        private Elf(String name,long bytes,long e,long ph,long phBytes,
                    int et,int n,int ents,List<Segment> segs){
            sourcePath=name;fileSize=bytes;entry=e;programHeaderVaddr=ph;
            programHeaderBytes=(int)phBytes;type=et;programHeaderCount=n;
            programHeaderEntryBytes=ents;
            loadSegments=Collections.unmodifiableList(segs);
        }
    }
    public static final class Plan {
        public final Elf wine,ldso;
        public final byte[] guestInitialStack;
        public final long stackRSP,stackGuestStart,stackGuestEnd,guestWineEntry,
            guestLoaderEntry,guestPHDR,guestATRandom,guestATExecfn;
        public final boolean sourceShaVerified,actualX86InitialStackEncoded,
            guestHostMemoryReserved,guestWineCodeTranslated,wineProcessExecuted,
            wineserverSpawned,guestSyscallBridgeComplete;
        public final int guestPageSize,observedHostNativePageSize;
        public final boolean requires16kNativeSubpageProtection;
        private Plan(Elf a,Elf b,byte[] stack,long rsp,long random,long exec,int hostPage){
            wine=a;ldso=b;guestInitialStack=stack;
            stackRSP=rsp;stackGuestStart=STACK_TOP-STACK_BYTES;
            stackGuestEnd=STACK_TOP;
            guestWineEntry=safeStaticAdd(MAIN_BIAS,a.entry);
            guestLoaderEntry=safeStaticAdd(LDSO_BIAS,b.entry);
            guestPHDR=safeStaticAdd(MAIN_BIAS,a.programHeaderVaddr);
            guestATRandom=random;guestATExecfn=exec;
            sourceShaVerified=true;actualX86InitialStackEncoded=true;
            guestHostMemoryReserved=false;guestWineCodeTranslated=false;
            wineProcessExecuted=false;wineserverSpawned=false;
            guestSyscallBridgeComplete=false;
            guestPageSize=4096;observedHostNativePageSize=hostPage;
            requires16kNativeSubpageProtection=hostPage==16384;
        }
    }
    private static long safeStaticAdd(long a,long b){
        if(a<0||b<0||a>USER_VA_LIMIT-b)
            throw new IllegalArgumentException("VIRTUAL_X86_ADDRESS_OVERFLOW");
        return a+b;
    }
    private static IOException reject(String code){return new IOException(code);}
    private static long safe(long a,long b)throws IOException {
        if(a<0||b<0||a>USER_VA_LIMIT-b)
            throw reject("GUEST_LINUX_X86_VA_OVERFLOW");
        return a+b;
    }
    private static boolean range(long offset,long length,long fileLength){
        return offset>=0&&length>=0&&offset<=fileLength&&length<=fileLength-offset;
    }
    private static long u32(ByteBuffer b,int at){return b.getInt(at)&0xffffffffL;}
    private static int u16(ByteBuffer b,int at){return b.getShort(at)&0xffff;}
    private static byte[] read(FileChannel ch,long offset,int count)throws IOException {
        ByteBuffer dst=ByteBuffer.allocate(count);
        while(dst.hasRemaining()){
            int n=ch.read(dst,offset+dst.position());
            if(n<=0)throw reject("ELF_PROCESS_HEADER_TRUNCATED");
        }
        return dst.array();
    }

    private static Elf elf(Path path,String name)throws IOException {
        long size=Files.size(path);
        if(size<64||size>256L*1024*1024)
            throw reject("WINE_PROCESS_ELF_SIZE_OUT_OF_BOUNDS");
        try(FileChannel f=FileChannel.open(path,StandardOpenOption.READ)){
            ByteBuffer head=ByteBuffer.wrap(read(f,0,64)).order(ByteOrder.LITTLE_ENDIAN);
            if(head.get(0)!=0x7f||head.get(1)!='E'||head.get(2)!='L'||
               head.get(3)!='F'||head.get(4)!=2||head.get(5)!=1)
                throw reject("WINE_PROCESS_NOT_ELF64_LE");
            int type=u16(head,16),machine=u16(head,18);
            if((type!=2&&type!=3)||machine!=62||u32(head,20)!=1)
                throw reject("WINE_PROCESS_NOT_X86_64_EXEC_OR_PIE");
            long entry=head.getLong(24),phoff=head.getLong(32);
            int ehsz=u16(head,52),phentsz=u16(head,54),phnum=u16(head,56);
            if(ehsz!=64||phentsz!=56||phnum<1||phnum>128 ||
               !range(phoff,phentsz*(long)phnum,size))
                throw reject("WINE_PROCESS_ELF_PROGRAM_HEADER_BOUNDS");
            ByteBuffer table=ByteBuffer.wrap(read(f,phoff,phentsz*phnum))
                .order(ByteOrder.LITTLE_ENDIAN);
            List<Segment> loads=new ArrayList<>();
            long phdrVA=-1;
            boolean entryInsideRX=false;
            for(int i=0;i<phnum;i++){
                int o=i*phentsz,typePH=table.getInt(o),flags=table.getInt(o+4);
                long off=table.getLong(o+8),vaddr=table.getLong(o+16),
                    fileBytes=table.getLong(o+32),memBytes=table.getLong(o+40),
                    align=table.getLong(o+48);
                if(typePH==PT_PHDR)phdrVA=vaddr;
                if(typePH!=PT_LOAD)continue;
                if(fileBytes>memBytes||!range(off,fileBytes,size) ||
                   vaddr<0||memBytes<0||vaddr>USER_VA_LIMIT-memBytes ||
                   (flags&PF_W)!=0&&(flags&PF_X)!=0 ||
                   align!=0 && ((align&(align-1))!=0 || vaddr%align!=off%align))
                    throw reject("WINE_PROCESS_PTLOAD_SIZE_ALIGNMENT_OR_WX");
                loads.add(new Segment(off,vaddr,fileBytes,memBytes,align,flags));
                if((flags&PF_X)!=0 && entry>=vaddr && entry-vaddr<fileBytes)
                    entryInsideRX=true;
            }
            if(loads.isEmpty()||loads.size()>24||!entryInsideRX)
                throw reject("WINE_PROCESS_ENTRY_NOT_IN_AUTHENTIC_FILE_BACKED_RX_PTLOAD");
            if(phdrVA<0){
                for(Segment seg:loads){
                    if(phoff>=seg.fileOffset &&
                       phoff-seg.fileOffset<=seg.fileBytes &&
                       phentsz*(long)phnum<=seg.fileBytes-(phoff-seg.fileOffset)){
                        phdrVA=safe(seg.guestVaddr,phoff-seg.fileOffset);
                        break;
                    }
                }
            }
            if(phdrVA<0||phdrVA>USER_VA_LIMIT)
                throw reject("WINE_PROCESS_AT_PHDR_NOT_IN_FILE_BACKED_PTLOAD");
            return new Elf(name,size,entry,phdrVA,phentsz*(long)phnum,
                           type,phnum,phentsz,loads);
        }
    }

    private static final class StackWriter {
        final byte[] data=new byte[STACK_BYTES];
        int top=STACK_BYTES;
        long guest(int offset){return STACK_TOP-STACK_BYTES+offset;}
        void align(int size){top &= ~(size-1);}
        void pushBytes(byte[] b)throws IOException{
            if(b.length>top)throw reject("GUEST_INITIAL_STACK_OVERFLOW");
            top-=b.length;System.arraycopy(b,0,data,top,b.length);
        }
        long pushString(String s)throws IOException{
            byte[] b=s.getBytes(StandardCharsets.UTF_8);
            if(b.length>=4096)throw reject("GUEST_ENV_OR_ARG_TOO_LONG");
            byte[] z=Arrays.copyOf(b,b.length+1);
            pushBytes(z);return guest(top);
        }
        void push64(long v)throws IOException{
            if(top<8)throw reject("GUEST_STACK_POINTER_TABLE_OVERFLOW");
            top-=8;ByteBuffer.wrap(data,top,8).order(ByteOrder.LITTLE_ENDIAN).putLong(v);
        }
        void pushPair(long key,long val)throws IOException{
            push64(val);push64(key);
        }
    }

    public static Plan prepare(Path appFilesDir,int nativePage,int hostUid,int hostGid)
        throws IOException {
        if(nativePage!=4096&&nativePage!=16384)
            throw reject("UNSUPPORTED_ANDROID_NATIVE_PAGE_SIZE");
        if(hostUid<0||hostGid<0)
            throw reject("UNEXPECTED_ANDROID_IDENTITY");
        // Fail closed: all three original Wine, interpreter and Win64 PE
        // bytes must first match immutable source hashes, plus rootfs receipt.
        WineGuestElfPreflight.Result authenticated=
            WineGuestElfPreflight.inspect(appFilesDir);
        if(!authenticated.realX86LinuxElfVerified ||
           !authenticated.guestInterpreterElfVerified ||
           !authenticated.kernel32Pe64Amd64Verified ||
           !authenticated.immediateNeededLibrariesPresent)
            throw reject("WINE_SOURCE_GUEST_ELF_PREFLIGHT_NOT_COMPLETE");
        Path root=appFilesDir.toRealPath().resolve(GuestRootfsInstaller.ROOTFS_NAME);
        if(!Files.isDirectory(root,LinkOption.NOFOLLOW_LINKS)||
           Files.isSymbolicLink(root))
            throw reject("INVALID_APP_PRIVATE_ROOTFS_FOR_PROCESS");
        Path wine=root.resolve(WINE).toRealPath();
        Path ldso=root.resolve(authenticated.interpreter.substring(1)).toRealPath();
        if(!wine.startsWith(root)||!ldso.startsWith(root))
            throw reject("WINE_INTERPRETER_OUTSIDE_APP_PRIVATE_ROOTFS");
        Elf main=elf(wine,WINE),loader=elf(ldso,authenticated.interpreter);
        if(main.type!=3||loader.type!=3 ||
           safe(MAIN_BIAS,main.entry)>USER_VA_LIMIT ||
           safe(LDSO_BIAS,loader.entry)>USER_VA_LIMIT ||
           safe(MAIN_BIAS,main.programHeaderVaddr)>USER_VA_LIMIT)
            throw reject("WINE_PROCESS_EXPECTED_SOURCE_GUEST_PIE");
        StackWriter st=new StackWriter();
        byte[] random=new byte[16];new SecureRandom().nextBytes(random);
        st.pushBytes(random);long randomVA=st.guest(st.top);
        long[] argv=new long[2],envp=new long[3];
        // Original Wine Linux argv; real Wine process has not run.
        argv[0]=st.pushString(GUEST_EXECFN);
        argv[1]=st.pushString("--version");
        envp[0]=st.pushString("LANG=C");
        envp[1]=st.pushString("WINEDEBUG=-all");
        envp[2]=st.pushString("PATH=/usr/bin");
        long execVA=st.pushString(GUEST_EXECFN);
        st.align(16);
        st.pushPair(AT_NULL,0);
        st.pushPair(AT_EXECFN,execVA);
        st.pushPair(AT_RANDOM,randomVA);
        st.pushPair(AT_EGID,hostGid);
        st.pushPair(AT_GID,hostGid);
        st.pushPair(AT_EUID,hostUid);
        st.pushPair(AT_UID,hostUid);
        st.pushPair(AT_ENTRY,safe(MAIN_BIAS,main.entry));
        st.pushPair(AT_BASE,safe(LDSO_BIAS,loader.entry)-loader.entry);
        st.pushPair(AT_PAGESZ,4096);
        st.pushPair(AT_PHNUM,main.programHeaderCount);
        st.pushPair(AT_PHENT,main.programHeaderEntryBytes);
        st.pushPair(AT_PHDR,safe(MAIN_BIAS,main.programHeaderVaddr));
        st.push64(0);for(int i=envp.length-1;i>=0;i--)st.push64(envp[i]);
        st.push64(0);for(int i=argv.length-1;i>=0;i--)st.push64(argv[i]);
        // Linux initial RSP must be 16-byte aligned. The pointer table
        // is 8 words long and AUXV is a multiple of 16 bytes; no padding
        // may be placed between argc and argv pointers.
        st.push64(argv.length);
        if((st.guest(st.top)&15L)!=0)
            throw reject("ORIGINAL_LINUX_STACK_INITIAL_RSP_NOT_16_ALIGNED");
        Plan p=new Plan(main,loader,st.data,st.guest(st.top),randomVA,execVA,nativePage);
        validate(p,hostUid,hostGid);
        return p;
    }

    public static void validate(Plan p,int hostUid,int hostGid)throws IOException {
        if(p==null || p.guestInitialStack.length!=STACK_BYTES ||
           p.stackRSP%16!=0 || p.guestWineEntry<=0 || p.guestLoaderEntry<=0 ||
           p.guestPHDR<=0||p.guestATRandom<=p.stackGuestStart ||
           p.guestATExecfn<=p.stackGuestStart||
           p.stackRSP<p.stackGuestStart ||p.stackRSP>=p.stackGuestEnd)
            throw reject("GUEST_ABI_STACK_OR_ENTRY_INVALID");
        ByteBuffer b=ByteBuffer.wrap(p.guestInitialStack).order(ByteOrder.LITTLE_ENDIAN);
        int o=(int)(p.stackRSP-p.stackGuestStart);
        if(b.getLong(o)!=2)throw reject("LINUX_GUEST_ARGC_NOT_2");
        int aux=o+8+8*3+8*4;
        boolean[] found=new boolean[5];
        // Validate all ABI auxv entries with non-bogus pointers.
        for(int index=0;index<48;index++){
            if(aux+16>STACK_BYTES)throw reject("AUXV_STACK_OVERFLOW");
            long k=b.getLong(aux),v=b.getLong(aux+8);aux+=16;
            if(k==AT_PHDR){found[0]=v==p.guestPHDR;}
            if(k==AT_BASE){found[1]=v==LDSO_BIAS;}
            if(k==AT_ENTRY){found[2]=v==p.guestWineEntry;}
            if(k==AT_RANDOM){found[3]=v==p.guestATRandom;}
            if(k==AT_EXECFN){found[4]=v==p.guestATExecfn;}
            if(k==AT_NULL)break;
        }
        for(boolean v:found)if(!v)
            throw reject("LINUX_AUXV_SOURCE_POINTER_OR_VALUE_MISMATCH");
        if(p.guestHostMemoryReserved||p.guestWineCodeTranslated ||
           p.wineProcessExecuted||p.wineserverSpawned||p.guestSyscallBridgeComplete)
            throw reject("SPOOFED_GUEST_WINE_EXECUTION_FROM_PLANNING");
    }
}
