#!/usr/bin/env python3
"""R3D17: real read-only libc file opened from verified app-owned Wine rootfs.

Continues exactly the 4th source-locked original GNU ld.so openat, returning
virtual guest FD 100 backed by a Java-preopened regular x86-64 ELF libc FD.
The raw Android host descriptor is never returned to guest and no unknown
guest syscalls are forwarded to the host. Later read/fstat/mmap are NOT faked:
they will be captured by the 32-slot original x86 syscall journal and stop.
Earlier 07D/07E/07F/07G and cacheless policy remain unchanged.
"""
from pathlib import Path
import re,sys
if len(sys.argv)!=2: raise SystemExit("usage: promote_libc_fd_bridge.py /tmp/carxpc")
app=Path(sys.argv[1])
java=app/"app/src/main/java/com/r4/carxpc"
native=app/"app/src/main/cpp/carx_r3d4_first_syscall.cpp"
service=java/"R3D4ProbeService.java"
activity=java/"R3D4ProbeActivity.java"
main=java/"MainActivity.java"
gradle=app/"app/build.gradle"
store=java/"R3D8JsonReportStore.java"
assert all(x.is_file() for x in (native,service,activity,main,gradle,store))
def one(s,a,b):
    n=s.count(a)
    assert n==1,("R3D17_ANCHOR_CHANGED",a[:100],n)
    return s.replace(a,b,1)
def reone(s,a,b):
    s,n=re.subn(a,b,s,count=1)
    assert n==1,("R3D17_REGEX_ANCHOR_CHANGED",a,n)
    return s

s=gradle.read_text()
s=reone(s,r"\bversionCode\s+44\b","versionCode 45")
s=reone(s,r"versionName\s+'[^']+'",
        "versionName '0.45-r3d17-libc-real-readonly-fd-bridge'")
gradle.write_text(s)
s=main.read_text()
s=one(s,"10 | R3D16 — تشخيص مسار openat الرابع",
      "10 | R3D17 — ربط libc الحقيقي وفحص الاستدعاء التالي")
main.write_text(s)
s=store.read_text()
s=one(s,'"CarX_PC_R3D16_Openat_Path_Diagnostics_"',
      '"CarX_PC_R3D17_LibcFD_Batch_Diagnostics_"')
store.write_text(s)

# Make the child read only the preopened file from the owned and normalized
# rootfs. Root/host symlink escape and non-ELF data fail closed.
s=service.read_text()
s=one(s,
'''        long sessionNonce, int traceFd, int progressFd, int probeMode);''',
'''        long sessionNonce, int traceFd, int progressFd, int probeMode,
        int libcReadonlyFd);''')
s=one(s,
'''    private static synchronized void loadNative() {''',
'''    private static Path verifiedRootfsLibc(Path root) throws java.io.IOException {
        Path base=root.toRealPath();
        if(!Files.isDirectory(base,LinkOption.NOFOLLOW_LINKS))return null;
        String[] candidates={"lib/x86_64-linux-gnu/libc.so.6",
                             "usr/lib/x86_64-linux-gnu/libc.so.6"};
        for(String rel:candidates){
            Path candidate=base.resolve(rel);
            if(!Files.exists(candidate,LinkOption.NOFOLLOW_LINKS))continue;
            Path actual;
            try{actual=candidate.toRealPath();}catch(java.io.IOException e){continue;}
            if(!actual.startsWith(base) ||
               !Files.isRegularFile(actual,LinkOption.NOFOLLOW_LINKS))continue;
            long size=Files.size(actual);
            if(size<4096 || size>32L*1024*1024)continue;
            byte[] h=new byte[64];
            try(java.io.InputStream in=Files.newInputStream(actual)){
                int off=0;
                while(off<h.length){
                    int n=in.read(h,off,h.length-off);
                    if(n<=0)break;
                    off+=n;
                }
                if(off!=h.length)continue;
            }
            if((h[0]&255)!=127 || h[1]!='E' || h[2]!='L' || h[3]!='F' ||
               h[4]!=2 || h[5]!=1 || (h[18]&255)!=62 || h[19]!=0)continue;
            return actual;
        }
        return null;
    }
    private static synchronized void loadNative() {''')
s=one(s,'''            int progressFd = -1;''',
'''            int progressFd = -1;
            int libcReadonlyFd = -1;''')
s=one(s,
'''                phase("J6_LDSO_SHA256_VERIFIED");''',
'''                phase("J6_LDSO_SHA256_VERIFIED");
                if(probeMode==4){
                    Path realLibc=verifiedRootfsLibc(root);
                    if(realLibc==null){
                        phase("E_R3D17_LIBC_NOT_SAFE_REGULAR_X86_64_IN_ROOTFS");
                        return;
                    }
                    ParcelFileDescriptor guestLibc=ParcelFileDescriptor.open(
                        realLibc.toFile(),ParcelFileDescriptor.MODE_READ_ONLY);
                    libcReadonlyFd=guestLibc.detachFd();
                    guestLibc.close();
                    phase("J3D_R3D17_LIBC_ROOTFS_READONLY_FD_VERIFIED");
                }''')
s=one(s,
'''                    plan.stackRSP, nonce, rawFd, progressFd, probeMode);''',
'''                    plan.stackRSP, nonce, rawFd, progressFd, probeMode,
                    libcReadonlyFd);''')
s=one(s,
'''                if (rawFd >= 0) {''',
'''                if (libcReadonlyFd >= 0) {
                    try { ParcelFileDescriptor.adoptFd(libcReadonlyFd).close(); }
                    catch (Throwable ignored) {}
                }
                if (rawFd >= 0) {''')
service.write_text(s)

# Bound original x86-64 openat to the one canonical guest pathname and exact
# O_CLOEXEC flags. Return virtual FD100, NEVER actual host fd or generic open.
s=native.read_text()
s=one(s,
'#include "carxpc/r3d16/native/safe_guest_stack_path.hpp"',
'#include "carxpc/r3d16/native/safe_guest_stack_path.hpp"\n'
'#include "carxpc/r3d17/native/verified_libc_fd.hpp"')
s=one(s,
'''int traceFd,uint64_t nonce,uint64_t brkBase,int mode)''',
'''int traceFd,uint64_t nonce,uint64_t brkBase,int mode,int libcFd)''')
s=one(s,
'''BRKBase(brkBase),Mode(mode) {''',
'''BRKBase(brkBase),Mode(mode),LibcHostFD(libcFd) {''')
s=one(s,'''  int Mode{0};''',
'''  int Mode{0};
  int LibcHostFD{-1};''')
s=one(s,
'''            carx_r3d6::note("E_BATCH_GUEST_PATH_CAPTURED_NEEDS_VFS");''',
'''            // The fourth actual x86 source-witnessed openat asks for libc.
            // This app-private regular ELF64 x86_64 file was already opened
            // O_RDONLY by Java; never forward an unchecked guest pathname.
            if(Seen==3 &&
               std::strcmp(guestPath,carx_r3d17::kGuestLibcPath)==0){
              if(!carx_r3d17::verified_readonly_libc_fd(LibcHostFD)){
                carx_r3d6::note("E_R3D17_PREOPENED_LIBC_FD_REJECTED");
                ::_exit(119);
              }
              state.gregs[FEXCore::X86State::REG_RAX]=
                  static_cast<uint64_t>(carx_r3d17::kGuestLibcFd);
              state.rip=newRIP;
              ++Seen;
              carx_r3d6::note("N24_R3D17_LIBC_REAL_FD_SOURCE_VERIFIED");
              carx_r3d6::note("N22_BATCH_RETURN_OPENAT_LIBC_FD100");
              return;
            }
            carx_r3d6::note("E_BATCH_GUEST_PATH_CAPTURED_NEEDS_VFS");''')
s=reone(s,r"(int traceFd,uint64_t nonce,int mode)(,\s*std::string& reason\) \{)",
        r"\1,int libcFd\2")
s=reone(s,r"(uint64_t rsp,int traceFd,uint64_t nonce,int mode)(,\s*std::string &message\)\{)",
        r"\1,int libcFd\2")
s=one(s,'''originalLdso,ldso,traceFd,nonce,brkHeap.base(),mode};''',
      '''originalLdso,ldso,traceFd,nonce,brkHeap.base(),mode,libcFd};''')
s=one(s,'''we,le,ldso,traceFd,nonce,mode,message)){''',
      '''we,le,ldso,traceFd,nonce,mode,libcFd,message)){''')
s=one(s,'''jint progressFd,jint probeMode){''',
      '''jint progressFd,jint probeMode,jint libcReadonlyFd){''')
s=one(s,'''int(traceFd),uint64_t(nonce),int(probeMode),msg);''',
      '''int(traceFd),uint64_t(nonce),int(probeMode),
                             int(libcReadonlyFd),msg);''')
assert all(x in s for x in [
  'N22_BATCH_RETURN_OPENAT_LIBC_FD100','N24_R3D17_LIBC_REAL_FD_SOURCE_VERIFIED',
  'verified_readonly_libc_fd','context->ExecuteThread(thread)',
  'N22_BATCH_RETURN_OPENAT_CACHE_ENOENT'])
native.write_text(s)

s=activity.read_text()
s=one(s,
'''runCacheless.setText("تشغيل 07H — R3D16 فحص مسار openat");''',
'''runCacheless.setText("تشغيل 07H — R3D17 libc حقيقي + Batch");''')
s=one(s,'"r4.carx.r3d16.stack-path-source-locked-openat-batch.v1"',
      '"r4.carx.r3d17.real-libc-fd-source-locked-batch.v1"')
s=one(s,'"07H_GUEST_STACK_OPENAT_PATH_WITNESS_WITH_FEX_ALIGN_FIX"',
      '"07H_REAL_ROOTFS_LIBC_READONLY_FD_GUEST_BRIDGE"')
s=one(s,'"07H_R3D16_GUEST_STACK_OPENAT_PATH_BATCH_32"',
      '"07H_R3D17_LIBC_READONLY_FD_BATCH_32"')
s=one(s,
'''        report.put("batch_stop_marker",stop);''',
'''        report.put("batch_stop_marker",stop);
        final boolean bridgedLibc=phases.toString().contains(
            "N22_BATCH_RETURN_OPENAT_LIBC_FD100");
        report.put("batch_libc_guest_fd100_returned",bridgedLibc);
        report.put("batch_libc_host_fd_preopened_in_rootfs",
            phases.toString().contains(
                "J3D_R3D17_LIBC_ROOTFS_READONLY_FD_VERIFIED"));
        if(bridgedLibc) {
            String path=decodeR3D16PathChunks(phases);
            if(!"/lib/x86_64-linux-gnu/libc.so.6".equals(path) ||
               count<4 || events.optJSONObject(3)==null ||
               events.optJSONObject(3).optLong("guest_syscall_number")!=257 ||
               !phases.toString().contains(
                   "J3D_R3D17_LIBC_ROOTFS_READONLY_FD_VERIFIED")) {
                return "BATCH_REJECTED_UNVERIFIED_LIBC_OPENAT_BRIDGE";
            }
            report.put("batch_libc_guest_path",path);
            report.put("batch_libc_guest_fd_number",100);
            report.put("batch_libc_fd_semantics_scope",
               "REAL_HOST_READONLY_FD_MAPPED_TO_GUEST_FD100_ONLY");
            report.put("batch_libc_read_fstat_mmap_implemented",false);
        }''')
s=one(s,
'''            report.put("evidence_limit",currentProbeMode==4 ?
                "Diagnostic unaligned-safe FEX JIT full barriers, source-pinned to original FEX commit, paired with limited cacheless guest view. Original x86 GNU ld.so x86 syscalls are source-witnessed; synthetic responses do not prove full Linux, Wine startup, Windows PE, DXVK, Vulkan or gameplay. This alignment fallback is not a performance benchmark." :''',
'''            report.put("evidence_limit",currentProbeMode==4 ?
                "R3D17 original source-witnessed fourth GNU ld.so openat can receive only guest FD100 mapped to Java preopened read-only original guest libc ELF64 x86_64; next unknown syscall stops. Previous brk/access/cache responses remain diagnostic shims. No full Linux VFS, libc read/mmap, Wine boot, PE, DXVK or gameplay proven." :''')
activity.write_text(s)
print("R3D17_LIBC_APP_PRIVATE_SAFE_REAL_FILE_DESCRIPTOR_PROMOTION_PASS")
print("R3D17_GUEST_FD_100_NOT_HOST_FD_AND_UNKNOWN_SYSCALLS_HALT_PASS")
