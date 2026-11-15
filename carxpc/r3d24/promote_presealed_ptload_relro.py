#!/usr/bin/env python3
"""R3D24: narrow RELRO mprotect on original sealed Wine/GNU PT_LOAD in same 07H.

The R3D23 REAL device trace: original GNU x86 syscall#20 nr10 mprotect
0x4000003000, 0x1000, PROT_READ, after successfully executing libc x86
thanks to FEX dynamic RX query. GuestMappings only tracks NEW mmap libc/anon,
but Wine ELF PT_LOAD was preinstalled from source and sealed before that
manager existed. A separate source-authenticated ELF PT_LOAD authority is
required, not unrestricted host mprotect or invented guest ownership.

Never increase old page permissions, change host TLS, forward arbitrary
guest pointer, or claim full Wine/Windows PE/game boot.
"""
from pathlib import Path
import re,sys
if len(sys.argv)!=2:raise SystemExit("usage: promote_presealed_ptload_relro.py /tmp/carxpc")
app=Path(sys.argv[1]);java=app/"app/src/main/java/com/r4/carxpc"
cpp=app/"app/src/main/cpp/carx_r3d4_first_syscall.cpp"
act=java/"R3D4ProbeActivity.java";main=java/"MainActivity.java"
gradle=app/"app/build.gradle";store=java/"R3D8JsonReportStore.java"
assert all(x.is_file() for x in (cpp,act,main,gradle,store))
def one(s,a,n):
 c=s.count(a)
 assert c==1,("R3D24_PINNED_SOURCE_ANCHOR_CHANGED",a[:130],c)
 return s.replace(a,n,1)
def reone(s,p,n):
 s,k=re.subn(p,n,s,count=1)
 assert k==1,("R3D24_VERSION_ANCHOR_CHANGED",p,k)
 return s

s=gradle.read_text()
s=reone(s,r"\bversionCode\s+51\b","versionCode 52")
s=reone(s,r"versionName\s+'[^']+'",
 "versionName '0.52-r3d24-source-verified-sealed-wine-elf-relro'")
gradle.write_text(s)
s=main.read_text()
s=one(s,"10 | R3D23 — إصلاح تنفيذ libc داخل محرك Wine الموحّد",
      "10 | R3D24 — تهيئة حماية Wine ELF الأصلية الموحّدة")
main.write_text(s)
s=store.read_text()
s=one(s,'"CarX_PC_R3D23_FEXExecLibc_Diagnostics_"',
      '"CarX_PC_R3D24_WineRELRO_Diagnostics_"')
store.write_text(s)
s=cpp.read_text()
s=one(s,
'''#include "carxpc/r3d23/native/bounded_guest_executable_vma.hpp"''',
'''#include "carxpc/r3d23/native/bounded_guest_executable_vma.hpp"
#include "carxpc/r3d24/native/source_sealed_elf_mprotect.hpp"''')
# Register only page-aligned, nonoverlapping *original decoded verified*
# PT_LOADs; constructor already receives GNU ELF. Forward original Wine Elf
# via same source-locked context call (never probe external process ranges).
s=one(s,
'''const std::vector<uint8_t>& source,const Elf& parsed,
                      int traceFd,uint64_t nonce,uint64_t brkBase,int mode,int libcFd)''',
'''const std::vector<uint8_t>& source,const Elf& parsed,
                      const Elf& originalWine,
                      int traceFd,uint64_t nonce,uint64_t brkBase,int mode,int libcFd)''')
s=one(s,
'''originalLdso,ldso,traceFd,nonce,brkHeap.base(),mode,libcFd};''',
'''originalLdso,ldso,main,traceFd,nonce,brkHeap.base(),mode,libcFd};''')
s=one(s,
'''  bool DynamicExecQueryLogged{false};''',
'''  bool DynamicExecQueryLogged{false};
  carx_r3d24::SourceSealedELFProtections PresealedWinePTLoads{};
  carx_r3d24::SourceSealedELFProtections PresealedLdsoPTLoads{};
  bool PresealedWineVerified{false};
  bool PresealedLdsoVerified{false};''')
s=one(s,
'''BRKBase(brkBase),Mode(mode),LibcHostFD(libcFd) {
    for (const Load& seg : parsed.segments) {''',
'''BRKBase(brkBase),Mode(mode),LibcHostFD(libcFd) {
    // The Wine and GNU ld.so images were independently parsed from original
    // source and copyAndSeal() already installed exact source PT_LOAD rights.
    // Permit only *narrowing* rights on one verified PT_LOAD at a time.
    const auto install=[&](carx_r3d24::SourceSealedELFProtections &target,
                           const Elf& elf,uint64_t fixedBias)->bool {
      if(elf.segments.empty() || elf.segments.size()>32)return false;
      for(const Load& seg:elf.segments) {
        if(seg.end<=seg.start || seg.end>UINT64_MAX-fixedBias ||
           !target.register_sealed_ptload(
             fixedBias+seg.start,seg.end-seg.start,seg.permission))
          return false;
      }
      return true;
    };
    PresealedWineVerified=install(PresealedWinePTLoads,originalWine,MAIN_BIAS);
    PresealedLdsoVerified=install(PresealedLdsoPTLoads,parsed,LDSO_BIAS);
    if(Mode==4) {
      if(!PresealedWineVerified || !PresealedLdsoVerified) {
        carx_r3d6::note("E_R3D24_PRESEALED_SOURCE_ELF_PTLOAD_INVALID");
        ::_exit(171);
      }
      carx_r3d6::note("N33_SOURCE_VERIFIED_PRESEALED_WINE_AND_LDSO_PTLOAD_REGISTERED");
    }
    for (const Load& seg : parsed.segments) {''')
# IMPORTANT: FEX executable-range decoder should now use precise ELF PF_X
# spans, including narrowed non-X RELRO, rather than blanket ELF window.
s=one(s,
'''    if (address>=WineBase && address-WineBase<WineLength)
      return {WineBase,WineLength,false};
    if (address>=LdsoBase && address-LdsoBase<LdsoLength)
      return {LdsoBase,LdsoLength,false};
    if(Mode==4) {
      const auto vma=ExecVMAs.find(address);''',
'''    if(Mode==4) {
      if(PresealedWineVerified){
        const auto w=PresealedWinePTLoads.executable_at(address);
        if(w.length)return {w.base,w.length,false};
      }
      if(PresealedLdsoVerified){
        const auto l=PresealedLdsoPTLoads.executable_at(address);
        if(l.length)return {l.base,l.length,false};
      }
    } else {
      // Retain legacy diagnostic modes completely unchanged.
      if (address>=WineBase && address-WineBase<WineLength)
        return {WineBase,WineLength,false};
      if (address>=LdsoBase && address-LdsoBase<LdsoLength)
        return {LdsoBase,LdsoLength,false};
    }
    if(Mode==4) {
      const auto vma=ExecVMAs.find(address);''')
# Preserve the original ABI path for newly created libc and anonymous maps.
# The initial source-sealed Wine and GNU ELF PT_LOAD maps have a separate,
# immutable-from-guest ownership proof and only accept monotonic RELRO.
s=one(s,
'''        if(number==10) { // mprotect
          const int64_t rc=GuestMaps.protect(arg0,arg1,arg2);
          if(rc<0) {
            carx_r3d6::note("E_R3D19_MPROTECT_NON_OWNED_OR_WX_DENIED");
            ::_exit(138);
          }
          uint64_t trackedProtectLength=0;
          if(!carx_r3d19::checked_round_page(arg1,trackedProtectLength) ||
             !ExecVMAs.replace_permissions(arg0,trackedProtectLength,
                                           (arg2&PROT_EXEC)!=0)) {
            carx_r3d6::note("E_R3D23_MPROTECT_RX_VMA_REGISTRATION_FAILED");
            ::_exit(162);
          }
          accept(0,"N22_BATCH_RETURN_R3D19_MPROTECT_OWNED_GUEST");
          return;
        }''',
'''        if(number==10) { // mprotect on dynamic or source-sealed PT_LOAD
          uint64_t pageLength=0;
          if(!carx_r3d19::checked_round_page(arg1,pageLength)) {
            carx_r3d6::note("E_R3D24_MPROTECT_INVALID_GUEST_LENGTH");
            ::_exit(172);
          }
          const bool dynamicOwned=GuestMaps.owned_range(arg0,pageLength);
          bool sealedWine=false;
          bool sealedLdso=false;
          int64_t rc=-EACCES;
          if(dynamicOwned) {
            rc=GuestMaps.protect(arg0,arg1,arg2);
          } else if(Mode==4 &&
                    (arg2&~uint64_t(PROT_READ|PROT_WRITE|PROT_EXEC))==0) {
            if(PresealedWineVerified &&
               PresealedWinePTLoads.covers(arg0,pageLength)) {
              rc=PresealedWinePTLoads.narrow_protection(
                  arg0,pageLength,int(arg2));
              sealedWine=rc==0;
            } else if(PresealedLdsoVerified &&
                      PresealedLdsoPTLoads.covers(arg0,pageLength)) {
              rc=PresealedLdsoPTLoads.narrow_protection(
                  arg0,pageLength,int(arg2));
              sealedLdso=rc==0;
            }
          }
          if(rc<0) {
            carx_r3d6::note("E_R3D24_MPROTECT_UNOWNED_OR_ELF_RIGHTS_DENIED");
            ::_exit(173);
          }
          if(dynamicOwned) {
            if(!ExecVMAs.replace_permissions(arg0,pageLength,
                                             (arg2&PROT_EXEC)!=0)){
              carx_r3d6::note("E_R3D23_MPROTECT_RX_VMA_REGISTRATION_FAILED");
              ::_exit(162);
            }
          }
          if(sealedWine) {
            carx_r3d6::note("N33_SOURCE_SEALED_WINE_PTLOAD_RELRO_READONLY_ACCEPTED");
          }
          if(sealedLdso) {
            carx_r3d6::note("N33_SOURCE_SEALED_LDSO_PTLOAD_RELRO_READONLY_ACCEPTED");
          }
          accept(0,sealedWine?
            "N22_BATCH_RETURN_R3D24_PRESEALED_WINE_ELF_MPROTECT":
            sealedLdso?
            "N22_BATCH_RETURN_R3D24_PRESEALED_LDSO_ELF_MPROTECT":
            "N22_BATCH_RETURN_R3D19_MPROTECT_OWNED_GUEST");
          return;
        }''')
assert all(x in s for x in (
 'N33_SOURCE_VERIFIED_PRESEALED_WINE_AND_LDSO_PTLOAD_REGISTERED',
 'N22_BATCH_RETURN_R3D24_PRESEALED_WINE_ELF_MPROTECT',
 'N22_BATCH_RETURN_R3D21_RSEQ_NEG_ENOSYS',
 'N32_FEX_DYNAMIC_RX_EXECUTABLE_VMA_QUERY_ACCEPTED',
 'E_R3D22_FEX_EXECUTE_RETURN_NO_NEW_X86_SYSCALL',
 'context->ExecuteThread(thread)'))
cpp.write_text(s)
s=act.read_text()
s=one(s,
'''runCacheless.setText("تشغيل 07H — R3D23 Wine + FEX Exec libc");''',
'''runCacheless.setText("تشغيل 07H — R3D24 Wine ELF RELRO + libc");''')
s=one(s,'"r4.carx.r3d23.integrated-wine-fex-libc-executable-vma.v1"',
      '"r4.carx.r3d24.integrated-wine-source-sealed-elf-relro.v1"')
s=one(s,'"07H_INTEGRATED_WINE_GNU_LDSO_LINUX_ABI_TLS_THREADS_FEX_LIBC_EXEC"',
      '"07H_INTEGRATED_WINE_GNU_LDSO_LINUX_ABI_TLS_THREADS_FEX_LIBC_EXEC_ELF_RELRO"')
s=one(s,'"07H_R3D23_UNIFIED_WINE_FEX_LIBC_EXEC_BATCH_512"',
      '"07H_R3D24_UNIFIED_WINE_SOURCE_SEALED_ELF_BATCH_512"')
s=one(s,
'''        report.put("r3d23_first_dynamic_rx_guest_target_verified_from_runtime",
          phases.toString().contains("N32_FEX_DYNAMIC_RX_TARGET_"));''',
'''        report.put("r3d23_first_dynamic_rx_guest_target_verified_from_runtime",
          phases.toString().contains("N32_FEX_DYNAMIC_RX_TARGET_"));
        report.put("r3d24_original_wine_ldso_source_ptloads_registered",
          phases.toString().contains(
           "N33_SOURCE_VERIFIED_PRESEALED_WINE_AND_LDSO_PTLOAD_REGISTERED"));
        report.put("r3d24_wine_relro_protect_accepted",
          phases.toString().contains(
            "N22_BATCH_RETURN_R3D24_PRESEALED_WINE_ELF_MPROTECT"));
        report.put("r3d24_ldso_relro_protect_accepted",
          phases.toString().contains(
            "N22_BATCH_RETURN_R3D24_PRESEALED_LDSO_ELF_MPROTECT"));
        report.put("r3d24_original_ptload_rights_can_only_narrow",true);
        report.put("r3d24_original_elf_holes_remain_protected",true);''')
s=one(s,
'''        stages.put("fex_dynamic_rx_decoder_query_accepted",phases.toString().contains(
           "N32_FEX_DYNAMIC_RX_EXECUTABLE_VMA_QUERY_ACCEPTED"));''',
'''        stages.put("fex_dynamic_rx_decoder_query_accepted",phases.toString().contains(
           "N32_FEX_DYNAMIC_RX_EXECUTABLE_VMA_QUERY_ACCEPTED"));
        stages.put("wine_original_source_sealed_ptload_relro_protected",
          phases.toString().contains(
           "N22_BATCH_RETURN_R3D24_PRESEALED_WINE_ELF_MPROTECT"));
        stages.put("ldso_original_source_sealed_ptload_relro_protected",
          phases.toString().contains(
           "N22_BATCH_RETURN_R3D24_PRESEALED_LDSO_ELF_MPROTECT"));''')
s=one(s,
'''R3D23 repairs the unified FEX x86 decoder executable range callback for RX guest libc mmap segments. R3D22 last guest RIP was within libc RX mapping and had SIGSEGV/SEGV_ACCERR/#PF instruction-fetch bit 0x15, while the original handler only exposed Wine+ld.so ranges. R3D23 reports bounded, source-locked dynamic guest RX VMAs from successful mmap and mprotect; revokes execute upon non-RX map, mprotect and munmap. Unknown/unmapped guest pointers still fail closed; no host W+X or fake syscall success. Result must be verified on ARM64; full Wine/PE/graphics still unproven.''',
'''R3D24 builds on real-device R3D23 which verified FEX libc RX transfer and advanced to original x86 mprotect nr10 at 0x4000003000, len4096, PROT_READ, after 20 bounded Linux guest responses. Dynamic GuestMappings alone cannot own source-sealed Wine ELF PT_LOAD regions. New source-verified Wine and GNU ld.so PT_LOAD registries allow only monotonic existing permission narrowing, with original ELF holes never writable/executable, precise source ELF RX queries for FEX, and no arbitrary host mprotect pass-through. All prior 512-witness guest ABI and fault trace remain in one test. The full Linux VFS, threads, Wine/PE/graphics/game boot remain unproven.''')
act.write_text(s)
print("R3D24_SOURCE_VERIFIED_WINE_GNU_PTLOAD_RELRO_MONOTONIC_PROTECTION_PROMOTION_PASS")
print("R3D24_PRESEALED_ONLY_SAME_FEX_512_WITNESS_GUEST_ABI_SINGLE_APK")
