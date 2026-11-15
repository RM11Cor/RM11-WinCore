#!/usr/bin/env python3
"""R3D25: trusted multi-ELF x86 syscall evidence in ONE Wine Linux ABI batch.

After R3D24 source-authenticated ld.so mapped libc executable RX and narrowed
Wine + GNU PT_LOAD RELRO, the next syscall callback exited 93 before any N12.
That is the legacy R3D3 source matcher failing for callbacks outside GNU ld.so.
Extend the *same* 512-syscall batch to witness original x86 0F05 in:
  (1) original verified GNU ld.so ELF source bytes (unchanged)
  (2) original verified Wine ELF source bytes and decoded original PT_LOADs
  (3) verified read-only rootfs libc FD100 + file-backed RX mmap offset and
      exact still-unchanged guest RX opcode bytes.
If no unique source is verified, record the guest RIP/syscall domain and STOP.
Never assume an unknown binary is Wine or forward it to host Android Linux.
"""
from pathlib import Path
import re,sys
if len(sys.argv)!=2:raise SystemExit("usage: promote_multi_elf_syscalls.py /tmp/carxpc")
app=Path(sys.argv[1]);java=app/"app/src/main/java/com/r4/carxpc"
cpp=app/"app/src/main/cpp/carx_r3d4_first_syscall.cpp"
act=java/"R3D4ProbeActivity.java";main=java/"MainActivity.java"
gradle=app/"app/build.gradle";store=java/"R3D8JsonReportStore.java"
assert all(x.is_file() for x in (cpp,act,main,gradle,store))
def one(s,a,n):
 c=s.count(a)
 assert c==1,("R3D25_SOURCE_LOCK_ANCHOR_CHANGED",a[:145],c)
 return s.replace(a,n,1)
def reone(s,p,n):
 s,k=re.subn(p,n,s,count=1)
 assert k==1,("R3D25_VERSION_SOURCE_CHANGED",p,k)
 return s
s=gradle.read_text()
s=reone(s,r"\bversionCode\s+52\b","versionCode 53")
s=reone(s,r"versionName\s+'[^']+'",
 "versionName '0.53-r3d25-verified-multi-elf-wine-libc-syscall-source'")
gradle.write_text(s)
s=main.read_text()
s=one(s,"10 | R3D24 — تهيئة حماية Wine ELF الأصلية الموحّدة",
      "10 | R3D25 — إثبات استدعاءات Wine وGNU وlibc الموحّدة")
main.write_text(s)
s=store.read_text()
s=one(s,'"CarX_PC_R3D24_WineRELRO_Diagnostics_"',
      '"CarX_PC_R3D25_MultiELFSource_Diagnostics_"')
store.write_text(s)

s=cpp.read_text()
s=one(s,
'''#include "carxpc/r3d24/native/source_sealed_elf_mprotect.hpp"''',
'''#include "carxpc/r3d24/native/source_sealed_elf_mprotect.hpp"
#include "carxpc/r3d25/native/verified_multi_elf_syscall.hpp"''')
s=one(s,
'''const std::vector<uint8_t>& source,const Elf& parsed,
                      const Elf& originalWine,
                      int traceFd,uint64_t nonce,uint64_t brkBase,int mode,int libcFd)''',
'''const std::vector<uint8_t>& source,const Elf& parsed,
                      const std::vector<uint8_t>& wineSource,
                      const Elf& originalWine,
                      int traceFd,uint64_t nonce,uint64_t brkBase,int mode,int libcFd)''')
s=one(s,
'''originalLdso,ldso,main,traceFd,nonce,brkHeap.base(),mode,libcFd};''',
'''originalLdso,ldso,originalWine,main,
    traceFd,nonce,brkHeap.base(),mode,libcFd};''')
# The existing source-bound context has originalLdso + parsed Elf. Include
# Wine bytes from the original JNI payload, never a guest-edited memory range.
s=one(s,
'''const std::vector<uint8_t>& originalLdso,
                                int traceFd,uint64_t nonce,int mode,int libcFd,''',
'''const std::vector<uint8_t>& originalLdso,
                                const std::vector<uint8_t>& originalWine,
                                int traceFd,uint64_t nonce,int mode,int libcFd,''')
# The original R3D4 payload call is now pinned and needs a Wine source ref.
s=one(s,
'''we,le,ldso,traceFd,nonce,mode,libcFd,message)){''',
'''we,le,ldso,wine,traceFd,nonce,mode,libcFd,message)){''')
s=one(s,
'''Source(source.data()),SourceLen(source.size()),Fd(traceFd),Nonce(nonce),''',
'''Source(source.data()),SourceLen(source.size()),
      WineSource(wineSource.data()),WineSourceLen(wineSource.size()),
      Fd(traceFd),Nonce(nonce),''')
s=one(s,
'''  std::array<carx_r3d3::Load,96> Loads{};
  size_t Count{0};
  const uint8_t* Source;
  size_t SourceLen;''',
'''  std::array<carx_r3d3::Load,96> Loads{};
  size_t Count{0};
  std::array<carx_r3d3::Load,96> WineLoads{};
  size_t WineCount{0};
  const uint8_t* Source;
  size_t SourceLen;
  const uint8_t* WineSource;
  size_t WineSourceLen;''')
s=one(s,
'''  carx_r3d23::BoundedExecVMAs ExecVMAs{};''',
'''  carx_r3d23::BoundedExecVMAs ExecVMAs{};
  carx_r3d25::RootfsLibcSource LibcOpcodeSource{};''')
s=one(s,
'''    PresealedWineVerified=install(PresealedWinePTLoads,originalWine,MAIN_BIAS);''',
'''    // The Wine byte array and parsed PT_LOADs are both the JNI-source
    // SHA-verified ELF, not a newly synthesized guest image.
    if(wineSource.empty() || !WineSource) {
      if(Mode==4){
        carx_r3d6::note("E_R3D25_ORIGINAL_WINE_ELF_BYTES_MISSING");
        ::_exit(181);
      }
    }
    for (const Load& seg : originalWine.segments) {
      if(WineCount>=WineLoads.size())break;
      WineLoads[WineCount++]=carx_r3d3::Load{
        MAIN_BIAS,seg.va,seg.fileOff,seg.fileSize,
        bool(seg.permission&PROT_EXEC)};
    }
    PresealedWineVerified=install(PresealedWinePTLoads,originalWine,MAIN_BIAS);''')
# Source-proved callback dispatch: 07D legacy remains GNU-only; 07H is
# strict source mux. No guessing or inference from previous report.
s=one(s,
'''    if (!carx_r3d3::make_record(Source,SourceLen,Loads.data(),Count,
          state.rip,state.gregs[FEXCore::X86State::REG_RAX],Nonce,&record))
      ::_exit(93);
    carx_r3d6::note("N12_ORIGINAL_LDSO_SYSCALL_OPCODE_VERIFIED");''',
'''    carx_r3d25::Source owner=carx_r3d25::Source::GNU_LDSO;
    bool verified=false;
    if(Mode==4) {
      const auto sourceGNU=[&](carx_r3d3::Record* out) {
        return carx_r3d3::make_record(
          Source,SourceLen,Loads.data(),Count,state.rip,
          state.gregs[FEXCore::X86State::REG_RAX],Nonce,out);
      };
      const auto sourceWine=[&](carx_r3d3::Record* out) {
        return PresealedWineVerified &&
          carx_r3d3::make_record(
            WineSource,WineSourceLen,WineLoads.data(),WineCount,
            state.rip,state.gregs[FEXCore::X86State::REG_RAX],Nonce,out);
      };
      const auto executable=[this](uint64_t guestRip) {
        return ExecVMAs.find(guestRip);
      };
      const auto sourceLibc=[&](carx_r3d3::Record* out) {
        return LibcOpcodeSource.make_record(
          LibcHostFD,state.rip,
          state.gregs[FEXCore::X86State::REG_RAX],Nonce,executable,out);
      };
      verified=carx_r3d25::select_exactly_one(
        sourceGNU,sourceWine,sourceLibc,owner,record);
      if(!verified) {
        char detail[144]{};
        std::snprintf(detail,sizeof(detail),"N34_UNVERIFIED_X86_SYSCALL_RIP_%016llX",
          static_cast<unsigned long long>(state.rip));
        carx_r3d6::note(detail);
        std::snprintf(detail,sizeof(detail),"N34_UNVERIFIED_X86_SYSCALL_NR_%llu",
          static_cast<unsigned long long>(
            state.gregs[FEXCore::X86State::REG_RAX]));
        carx_r3d6::note(detail);
        const bool inWine=state.rip>=WineBase &&
                          state.rip-WineBase<WineLength;
        const bool inLdso=state.rip>=LdsoBase &&
                          state.rip-LdsoBase<LdsoLength;
        if(inWine)carx_r3d6::note("N34_UNVERIFIED_RIP_WINDOW_WINE");
        else if(inLdso)carx_r3d6::note("N34_UNVERIFIED_RIP_WINDOW_GNU_LDSO");
        else if(ExecVMAs.find(state.rip).length)
          carx_r3d6::note("N34_UNVERIFIED_RIP_WINDOW_DYNAMIC_RX_GUEST");
        else carx_r3d6::note("N34_UNVERIFIED_RIP_WINDOW_UNKNOWN");
        carx_r3d6::note("E_R3D25_SYSCALL_SOURCE_UNPROVEN_OR_AMBIGUOUS");
        ::_exit(174);
      }
      carx_r3d6::note(owner==carx_r3d25::Source::GNU_LDSO?
        "N34_SOURCE_DOMAIN_GNU_LDSO" :
        owner==carx_r3d25::Source::WINE_ELF?
        "N34_SOURCE_DOMAIN_WINE_ELF":
        "N34_SOURCE_DOMAIN_VERIFIED_LIBC_FD100");
    } else {
      verified=carx_r3d3::make_record(
        Source,SourceLen,Loads.data(),Count,state.rip,
        state.gregs[FEXCore::X86State::REG_RAX],Nonce,&record);
      if(!verified)::_exit(93);
    }
    carx_r3d6::note(owner==carx_r3d25::Source::GNU_LDSO?
      "N12_ORIGINAL_LDSO_SYSCALL_OPCODE_VERIFIED":
      "N12_ORIGINAL_ELF_SYSCALL_OPCODE_SOURCE_VERIFIED");''')
# File offset source for rootfs libc is the requested original mmap file
# offset. Only RX + original fd100 may contribute syscall opcode witness.
s=one(s,
'''          if((arg2&PROT_EXEC)!=0) {
            carx_r3d6::note("N32_GUEST_LIBC_RX_MMAP_REGISTERED_FOR_FEX");
          }''',
'''          if(!LibcOpcodeSource.observe_mmap(uint64_t(mapped),
               trackedMapLength,
               (arg2&(PROT_READ|PROT_EXEC))==(PROT_READ|PROT_EXEC),
               LibcGuestOpen &&
                 arg4==uint64_t(carx_r3d17::kGuestLibcFd) &&
                 carx_r3d17::verified_readonly_libc_fd(LibcHostFD),
               arg5)){
            carx_r3d6::note("E_R3D25_VERIFIED_LIBC_RX_OFFSET_REGISTRATION_FAILED");
            ::_exit(175);
          }
          if((arg2&PROT_EXEC)!=0) {
            carx_r3d6::note("N32_GUEST_LIBC_RX_MMAP_REGISTERED_FOR_FEX");
          }''')
s=one(s,
'''          if(dynamicOwned) {
            if(!ExecVMAs.replace_permissions(arg0,pageLength,''',
'''          if(dynamicOwned) {
            // Do not reuse the original libc file-offset claim after any
            // successful mprotect; the guest page's content may have changed.
            LibcOpcodeSource.invalidate(arg0,pageLength);
            if(!ExecVMAs.replace_permissions(arg0,pageLength,''')
s=one(s,
'''          accept(0,"N22_BATCH_RETURN_R3D19_MUNMAP_OWNED_GUEST");''',
'''          LibcOpcodeSource.invalidate(arg0,arg1);
          accept(0,"N22_BATCH_RETURN_R3D19_MUNMAP_OWNED_GUEST");''')
assert all(k in s for k in (
 'N34_SOURCE_DOMAIN_WINE_ELF',
 'N34_SOURCE_DOMAIN_VERIFIED_LIBC_FD100',
 'N34_UNVERIFIED_X86_SYSCALL_RIP_',
 'N22_BATCH_RETURN_R3D24_PRESEALED_WINE_ELF_MPROTECT',
 'N32_FEX_DYNAMIC_RX_EXECUTABLE_VMA_QUERY_ACCEPTED',
 'context->ExecuteThread(thread)',
 'E_R3D25_SYSCALL_SOURCE_UNPROVEN_OR_AMBIGUOUS'))
cpp.write_text(s)

s=act.read_text()
s=one(s,
'''runCacheless.setText("تشغيل 07H — R3D24 Wine ELF RELRO + libc");''',
'''runCacheless.setText("تشغيل 07H — R3D25 Wine + GNU + libc Source");''')
s=one(s,
'''r4.carx.r3d24.integrated-wine-source-sealed-elf-relro.v1''',
'''r4.carx.r3d25.integrated-source-verified-multi-elf-syscalls.v1''')
s=one(s,
'''07H_INTEGRATED_WINE_GNU_LDSO_LINUX_ABI_TLS_THREADS_FEX_LIBC_EXEC_ELF_RELRO''',
'''07H_INTEGRATED_WINE_GNU_LDSO_LINUX_ABI_TLS_THREADS_FEX_LIBC_EXEC_ELF_MULTI_SOURCE''')
s=one(s,
'''07H_R3D24_UNIFIED_WINE_SOURCE_SEALED_ELF_BATCH_512''',
'''07H_R3D25_UNIFIED_WINE_MULTI_ELF_SOURCE_BATCH_512''')
s=one(s,
'''if(p.startsWith("E_BATCH_") || p.startsWith("E_R3D22_")) stop=p;''',
'''if(p.startsWith("E_BATCH_") || p.startsWith("E_R3D22_") ||
             p.startsWith("E_R3D25_")) stop=p;''')
s=one(s,
'''        report.put("r3d24_original_elf_holes_remain_protected",true);''',
'''        report.put("r3d24_original_elf_holes_remain_protected",true);
        JSONArray elfWitnessSources=new JSONArray();
        for(int i=0;i<phases.length();i++) {
          String marker=phases.optString(i,"");
          if(marker.startsWith("N34_SOURCE_DOMAIN_"))
            elfWitnessSources.put(marker.substring("N34_SOURCE_DOMAIN_".length()));
        }
        report.put("r3d25_accepted_original_elf_syscall_sources",elfWitnessSources);
        report.put("r3d25_cross_elf_witness_count",elfWitnessSources.length());
        report.put("r3d25_gnu_only_source_limit_removed_from_mode4",true);
        report.put("r3d25_last_unknown_callback_rip_logged",
          phases.toString().contains("N34_UNVERIFIED_X86_SYSCALL_RIP_"));
        report.put("r3d25_unknown_guest_syscall_host_forwarding",false);
        report.put("r3d25_verified_guest_elf_domain_required",true);''')
s=one(s,
'''        stages.put("ldso_original_source_sealed_ptload_relro_protected",
          phases.toString().contains(
           "N22_BATCH_RETURN_R3D24_PRESEALED_LDSO_ELF_MPROTECT"));''',
'''        stages.put("ldso_original_source_sealed_ptload_relro_protected",
          phases.toString().contains(
           "N22_BATCH_RETURN_R3D24_PRESEALED_LDSO_ELF_MPROTECT"));
        stages.put("new_wine_elf_syscalls_source_verified",
          phases.toString().contains("N34_SOURCE_DOMAIN_WINE_ELF"));
        stages.put("new_libc_syscalls_source_verified",
          phases.toString().contains("N34_SOURCE_DOMAIN_VERIFIED_LIBC_FD100"));
        stages.put("unknown_original_x86_syscall_source_rejected",
          phases.toString().contains(
           "E_R3D25_SYSCALL_SOURCE_UNPROVEN_OR_AMBIGUOUS"));''')
s=one(s,
'''R3D24 builds on real-device R3D23 which verified FEX libc RX transfer and advanced to original x86 mprotect nr10 at 0x4000003000, len4096, PROT_READ, after 20 bounded Linux guest responses. Dynamic GuestMappings alone cannot own source-sealed Wine ELF PT_LOAD regions. New source-verified Wine and GNU ld.so PT_LOAD registries allow only monotonic existing permission narrowing, with original ELF holes never writable/executable, precise source ELF RX queries for FEX, and no arbitrary host mprotect pass-through. All prior 512-witness guest ABI and fault trace remain in one test. The full Linux VFS, threads, Wine/PE/graphics/game boot remain unproven.''',
'''R3D25 preserves all R3D24 RELRO/FEX TLS/syscall work. Actual R3D24 phone trace: original GNU ld.so completed 22/22 x86 guest callbacks, including Wine and GNU source-sealed RELRO; then callback entered but exited with legacy witness failure 93 before syscall identity logging. The R3D3 original witness checker matched GNU ld.so ELF only. R3D25 requires a unique authentic x86 opcode in one of THREE original verified ELF sources: GNU ld.so original byte-backed PT_LOAD, Wine original byte-backed PT_LOAD, or verified readonly libc fd100 file offset from owned, still source-identical RX guest mapping. Unknown/ambiguous callback RIP and syscall number are recorded and rejected without host forwarding, with per-witness source domain in one batch JSON. Does NOT prove full Wine Linux ABI/Win64 PE/graphics/game.''')
act.write_text(s)
print("R3D25_TRIPLE_ORIGINAL_ELF_SOURCE_LOCKED_X86_SYSCALL_PROMOTION_PASS")
print("R3D25_NO_UNKNOWN_SYSCALL_FORWARDING_OR_UNVERIFIED_SOURCE_ACCEPTANCE")
