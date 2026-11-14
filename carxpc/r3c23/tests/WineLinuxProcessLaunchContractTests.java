package com.r4.carxpc;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;

/** Authenticate actual original Wine64/ldso/kernel32 and build read-only
 * ABI guest stack layouts on x86 host CI (not Android FEX execution). */
public final class WineLinuxProcessLaunchContractTests {
    private static void check(boolean b,String message) {
        if(!b)throw new AssertionError(message);
    }
    private static long word(WineLinuxProcessLaunchContract.Plan p,int byteOffset) {
        return ByteBuffer.wrap(p.guestInitialStack).order(ByteOrder.LITTLE_ENDIAN)
            .getLong((int)(p.stackRSP-p.stackGuestStart)+byteOffset);
    }
    private static String guestString(WineLinuxProcessLaunchContract.Plan p,long va){
        check(va>=p.stackGuestStart&&va<p.stackGuestEnd,"BAD_STRING_ADDRESS");
        int i=(int)(va-p.stackGuestStart),end=i;
        while(end<p.guestInitialStack.length&&p.guestInitialStack[end]!=0)end++;
        check(end<p.guestInitialStack.length,"GUEST_STRING_NOT_TERMINATED");
        return new String(p.guestInitialStack,i,end-i,
            java.nio.charset.StandardCharsets.UTF_8);
    }
    private static void runPlan(Path app,int hostPageSize)throws Exception {
        WineLinuxProcessLaunchContract.Plan p=
            WineLinuxProcessLaunchContract.prepare(app,hostPageSize,10123,10123);
        check(p.sourceShaVerified&&p.actualX86InitialStackEncoded,
              "REAL_SOURCE_AND_LINUX_STACK_REQUIRED");
        check(p.guestPageSize==4096&&p.observedHostNativePageSize==hostPageSize,
              "GUEST4K_NATIVEPAGE_POLICY_MISMATCH");
        check(p.requires16kNativeSubpageProtection==(hostPageSize==16384),
              "HOST_NATIVE_16K_SUBPAGE_NOT_TRACKED");
        check(p.wine.loadSegments.size()==4&&p.ldso.loadSegments.size()==4,
              "ACTUAL_ORIGINAL_WINE_ELF_SEGMENTS_CHANGED");
        check(p.guestWineEntry!=p.guestLoaderEntry&&p.guestLoaderEntry>0,
              "WINE_LDSO_EXEC_ENTRY_NOT_DISTINCT");
        check(p.wine.programHeaderCount>0&&p.guestPHDR>0&&p.stackRSP%16==0,
              "ORIGINAL_PHDR_LINUX_STACK_MISSING");
        check(word(p,0)==2&&word(p,8)!=0&&word(p,16)!=0 &&
              word(p,24)==0&&word(p,32)!=0&&word(p,56)==0,
              "LINUX_ARGV_ENVP_POINTER_TABLE_INVALID");
        check("/usr/lib/wine/wine64".equals(guestString(p,word(p,8))),
              "ORIGINAL_WINE_ARGV0_WRONG");
        check("--version".equals(guestString(p,word(p,16))),
              "ORIGINAL_WINE_ARGV1_WRONG");
        check("LANG=C".equals(guestString(p,word(p,32))),
              "SOURCE_GUEST_ENV1_WRONG");
        check("WINEDEBUG=-all".equals(guestString(p,word(p,40))),
              "SOURCE_GUEST_ENV2_WRONG");
        check("PATH=/usr/bin".equals(guestString(p,word(p,48))),
              "SOURCE_GUEST_ENV3_WRONG");
        check(!p.guestHostMemoryReserved&&!p.guestWineCodeTranslated &&
              !p.wineProcessExecuted&&!p.wineserverSpawned &&
              !p.guestSyscallBridgeComplete,"SYNTHETIC_LAUNCH_EXECUTION_SPOOF");
        WineLinuxProcessLaunchContract.validate(p,10123,10123);
        long old=word(p,0);
        ByteBuffer.wrap(p.guestInitialStack).order(ByteOrder.LITTLE_ENDIAN)
            .putLong((int)(p.stackRSP-p.stackGuestStart),999);
        boolean detected=false;
        try{WineLinuxProcessLaunchContract.validate(p,10123,10123);}
        catch(IOException expected){detected=true;}
        check(detected,"FORGED_ARGC_NOT_REJECTED");
        ByteBuffer.wrap(p.guestInitialStack).order(ByteOrder.LITTLE_ENDIAN)
            .putLong((int)(p.stackRSP-p.stackGuestStart),old);
        WineLinuxProcessLaunchContract.validate(p,10123,10123);
        check(p.guestATRandom>p.stackRSP&&p.guestATExecfn>p.stackRSP,
              "AT_RANDOM_AT_EXECFN_NOT_IN_OWNED_GUEST_STACK");
        System.out.println("CARX_R3C23_REAL_ORIGINAL_WINE_X86_LINUX_PROCESS_ABI_STACK_AUXV_PASS host_page="+
           hostPageSize+" wine_entry="+Long.toHexString(p.guestWineEntry)+
           " loader_entry="+Long.toHexString(p.guestLoaderEntry)+
           " phdr="+Long.toHexString(p.guestPHDR)+
           " argc=2 env=3 original_elf_segments=4,4");
    }
    public static void main(String[] args)throws Exception {
        check(args.length==2,"USAGE original-archive.tar.gz appfiles");
        Path source=Paths.get(args[0]),app=Paths.get(args[1]);
        Files.createDirectories(app);
        GuestRootfsInstaller.Receipt r;
        try(InputStream input=Files.newInputStream(source)){
            r=GuestRootfsInstaller.install(input,app);
        }
        check(r.sha256.equals(GuestRootfsInstaller.ARCHIVE_SHA256),
              "ORIGINAL_ARCHIVE_SOURCE_SHA_MISMATCH");
        check(r.entries>10000,"AUTHENTIC_ROOTFS_EXTRACTION_FAILED");
        runPlan(app,4096);
        runPlan(app,16384);
        WineLinuxProcessLaunchContract.Plan p=
            WineLinuxProcessLaunchContract.prepare(app,4096,10123,10123);
        Path root=app.resolve(GuestRootfsInstaller.ROOTFS_NAME);
        Path wine=root.resolve("usr/lib/wine/wine64");
        // One malicious byte in real executable entry metadata must fail the
        // original-source SHA-256 preflight, without materializing guest RX.
        byte[] original=Files.readAllBytes(wine);
        try {
            try(java.nio.channels.FileChannel f=java.nio.channels.FileChannel.open(wine,
                    java.nio.file.StandardOpenOption.WRITE)){
                f.write(ByteBuffer.wrap(new byte[]{0}),
                        18); // e_machine from x86_64 to invalid EM_NONE
            }
            boolean rejected=false;
            try{WineLinuxProcessLaunchContract.prepare(app,4096,10123,10123);}
            catch(IOException expected){rejected=true;}
            check(rejected,"ALTERED_GUEST_WINE_SOURCE_ACCEPTED");
        } finally{Files.write(wine,original);}
        // Restore pristine original Wine input data and verify again.
        WineLinuxProcessLaunchContract.Plan restored=
            WineLinuxProcessLaunchContract.prepare(app,4096,10123,10123);
        check(restored.sourceShaVerified && !restored.wineProcessExecuted,
              "RESTORED_GUEST_ELF_CONTRACT_REGRESSION");
        System.out.println("CARX_R3C23_REAL_WINE_BINARY_MUTATION_DENIED_AND_RESTORED");
        System.out.println("CARX_R3C23_ONLY_READONLY_VIRTUAL_X86_LINUX_PROCESS_PLAN_NOT_ANDROID_FEX_WINE_EXEC");
    }
}
