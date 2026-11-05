#pragma once
// SPDX-License-Identifier: MIT
// KERNIX G2-E/C3-D7J — authenticated x86_64 Linux original PT_TLS
// initializer, Variant II NEGATIVE TP-offset MODEL and ld-linux runtime
// relocation dependency BARRIER. No kernel FS/GS mutation, no FEX
// CpuState assignment, DTV/TCB creation, relocation, RELRO or execution.
// The model is NOT a valid glibc TCB and must never be installed as FS.
// The actual source-locked libc PT_TLS is 16 file/136 memory, align 8.
#include "kernix_g2e_c3d7i_original_x86_dynamic_tls_relocation_contract.h"
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
namespace kernix::g2e::c3d7j {
inline constexpr size_t kScratchBytes=4096;
enum class Reject : uint8_t {
  None, SourceNotAttested, AbsentOriginalTLS, MultipleTLSModules,
  InvalidTLS, OversizeTLS, OriginalTLSInitializerMismatch,
  RelocationOrderingUnresolved, GuestRuntimeNotStarted
};
struct TLSModel {
  std::array<uint8_t,kScratchBytes> bytes{};
  size_t modelThreadPointerIndex=kScratchBytes; // ONE PAST array. NEVER deref!
  size_t negativeTLSBlockStart=0;
  size_t alignedStaticBlockBytes=0;
  int64_t negativeTPRelativeStart=0;
  size_t originalInitializerBytes=0;
  size_t zeroFilledTBSSBytes=0;
  size_t totalTLSMemoryBytes=0;
  size_t originalModule=0;
  uint64_t originalGuestTLSVirtualAddress=0;
  bool sourceInitializerMatchesOriginalELF=false;
  bool zeroFillMatchesOriginalPTTLSMemsz=false;
  bool x86VariantIIModelOnly=true;
  bool nativeHostFSGSRegistersUnchanged=true;
  bool realGuestTCBInitialized=false;
  bool realGuestDTVInitialized=false;
  bool realGuestFSBaseAssigned=false;
  bool originalLdsoExecuted=false;
};
struct DependencyGate {
  size_t sourceOriginalRelrTargets=0;
  size_t sourceOriginalRelaAndPltEntries=0;
  size_t sourceOriginalIRelativeResolvers=0;
  size_t sourceOriginalSymbolicRelaEntries=0;
  size_t sourceOriginalTLSModules=0;
  bool authenticateThreeOriginalELFs=false;
  bool linuxX86VariantIIInitializerModeled=false;
  bool requiresGuestSymbolVersionResolution=true;
  bool requiresRealGuestTCBAndDTV=true;
  bool requiresActualGuestFSBase=true;
  bool requiresRealIFUNCResolverGuestExecution=true;
  bool requiresActualRelocationWrites=true;
  bool requiresPostRelocationRELRO=true;
  bool anyOriginalX86InstructionExecuted=false;
  bool realRelocationWritePerformed=false;
  bool guestFSBaseAssigned=false;
  bool guestRelroApplied=false;
  bool androidDeviceTested=false;
};
inline bool AlignedBlockBytes(uint64_t mem,uint64_t alignment,
                              size_t& bytes) noexcept {
  bytes=0;
  if(!mem || !alignment || (alignment&(alignment-1)) ||
     mem>kScratchBytes || alignment>kScratchBytes ||
     mem>UINT64_MAX-(alignment-1))return false;
  const uint64_t value=(mem+alignment-1)&~(alignment-1);
  if(value>kScratchBytes || value<mem)return false;
  bytes=static_cast<size_t>(value);
  return true;
}
// Copies *authentic* x86 libc PT_TLS initializer into a bounded
// host-only zeroed test buffer ending before a hypothetical TP.
// It does not infer the real glibc DTV, pthread TCB, module ID, or
// actual FS base. That is a separate real-loader runtime requirement.
inline bool BuildOriginalStaticTLSModel(
  const GuestPreflight& source,
  const c3d7b::NativeChosenPIEGuestLayout& owned,
  const c3d7i::Plan& dynamic,
  const c3d7h::Plan& relro,
  TLSModel& model,DependencyGate& dep,Reject& reject) noexcept {
  model={};dep={};
  reject=Reject::SourceNotAttested;
  if(!source.exactSha256Matched ||
     !source.readOnlyAnonymousSnapshots ||
     !source.exactInterpreterAndGlibcClosure ||
     source.guestCodeExecuted || source.dynamicLinkerExecuted ||
     source.fexAttached || source.wineExecuted ||
     !dynamic.originalThreeSHA256SourcesVerified ||
     !dynamic.allOriginalDynamicTablesBounded ||
     !dynamic.allOriginalTLSRangesBounded ||
     dynamic.originalELFRelocationsApplied ||
     dynamic.x86GuestFSGSInitialized ||
     dynamic.originalLinuxLdsoExecuted ||
     dynamic.relroSealed || dynamic.androidDeviceTested ||
     !relro.exactOriginalSHA256Sources ||
     !relro.noNativeMprotectApplied ||
     !relro.noGuestELFRelocationsApplied ||
     owned.WindowsHeld()!=4 || ::sysconf(_SC_PAGESIZE)!=4096)
    return false;
  reject=Reject::AbsentOriginalTLS;
  if(dynamic.totalTLSHeaders==0)return false;
  reject=Reject::MultipleTLSModules;
  if(dynamic.totalTLSHeaders!=1 ||
     dynamic.modules[0].tlsHeaders ||
     dynamic.modules[1].tlsHeaders ||
     dynamic.modules[2].tlsHeaders!=1)
    return false;
  constexpr size_t idx=2; // source-pinned glibc is only PT_TLS module
  const auto& m=dynamic.modules[idx];
  const auto* region=owned.Module(idx);
  const auto& blob=source.snapshots[idx];
  reject=Reject::InvalidTLS;
  if(!region || !blob.readOnlySnapshot() ||
     blob.size()<sizeof(Elf64_Ehdr) || !blob.bytes() ||
     !m.tlsHasSourceBacking ||
     !m.tlsTotalMemorySize ||
     m.tlsInitFileSize>m.tlsTotalMemorySize ||
     !m.tlsAlignment ||
     (m.tlsAlignment&(m.tlsAlignment-1)) ||
     m.tlsOriginalGuestVA<region->chosenImageStart ||
     m.tlsOriginalGuestVA-region->chosenImageStart>=
       c3d7b::kImageCapacity)
    return false;
  size_t aligned=0;
  reject=Reject::OversizeTLS;
  if(!AlignedBlockBytes(m.tlsTotalMemorySize,
                        m.tlsAlignment,aligned))return false;
  // Once the size contract is validated, any PHDR/source/bias
  // discrepancy must report InvalidTLS, not a stale OversizeTLS.
  reject=Reject::InvalidTLS;
  Elf64_Ehdr elf{};
  std::memcpy(&elf,blob.bytes(),sizeof(elf));
  if(!g2b::GuestElfHeader(elf) ||
     !g2b::ElfRange(elf.e_phoff,
          uint64_t(elf.e_phnum)*sizeof(Elf64_Phdr),blob.size()))
    return false;
  // Compare PHDR directly, not only the C3D7I struct. This is a
  // separate witness that libc PT_TLS truly matches its immutable
  // exact file bytes and the kernel-selected guest shadow.
  size_t matched=0;
  for(uint16_t i=0;i<elf.e_phnum;++i) {
    Elf64_Phdr ph{};
    std::memcpy(&ph,blob.bytes()+elf.e_phoff+
                 size_t(i)*sizeof(ph),sizeof(ph));
    if(ph.p_type!=PT_TLS)continue;
    if(++matched!=1 ||
       ph.p_memsz!=m.tlsTotalMemorySize ||
       ph.p_filesz!=m.tlsInitFileSize ||
       ph.p_align!=m.tlsAlignment ||
       ph.p_vaddr>UINT64_MAX-region->loadBias ||
       region->loadBias+ph.p_vaddr!=m.tlsOriginalGuestVA ||
       ph.p_offset>blob.size() ||
       ph.p_filesz>blob.size()-ph.p_offset)
      return false;
    if(m.tlsInitFileSize) {
      size_t sourceLoadOffset=0;
      if(!c3d7i::SourceFileVA(blob.bytes(),blob.size(),elf,
          ph.p_vaddr,ph.p_filesz,sourceLoadOffset) ||
         sourceLoadOffset!=ph.p_offset)return false;
      const auto* guestTLS=owned.GuestReadOnlyBytes(
        idx,m.tlsOriginalGuestVA,
        static_cast<size_t>(m.tlsInitFileSize));
      reject=Reject::OriginalTLSInitializerMismatch;
      if(!guestTLS ||
         std::memcmp(guestTLS,blob.bytes()+ph.p_offset,
                     static_cast<size_t>(ph.p_filesz))!=0)return false;
    }
    const size_t start=kScratchBytes-aligned;
    // scratch is all zero, representing TBSS and alignment padding.
    if(ph.p_filesz)
      std::memcpy(model.bytes.data()+start,
                  blob.bytes()+ph.p_offset,
                  static_cast<size_t>(ph.p_filesz));
  }
  reject=Reject::InvalidTLS;
  if(matched!=1)return false;
  model.modelThreadPointerIndex=kScratchBytes;
  model.negativeTLSBlockStart=kScratchBytes-aligned;
  model.alignedStaticBlockBytes=aligned;
  model.negativeTPRelativeStart=-static_cast<int64_t>(aligned);
  model.originalInitializerBytes=static_cast<size_t>(m.tlsInitFileSize);
  model.zeroFilledTBSSBytes=static_cast<size_t>(
    m.tlsTotalMemorySize-m.tlsInitFileSize);
  model.totalTLSMemoryBytes=static_cast<size_t>(m.tlsTotalMemorySize);
  model.originalModule=idx;
  model.originalGuestTLSVirtualAddress=m.tlsOriginalGuestVA;
  model.sourceInitializerMatchesOriginalELF=true;
  model.zeroFillMatchesOriginalPTTLSMemsz=true;

  for(const auto& module:dynamic.modules) {
    dep.sourceOriginalIRelativeResolvers+=
      module.irelativeRelaEntries;
    dep.sourceOriginalSymbolicRelaEntries+=
      module.symbolicRelaEntries;
  }
  dep.sourceOriginalRelrTargets=dynamic.totalRelrTargets;
  dep.sourceOriginalRelaAndPltEntries=
    dynamic.totalRelaEntries+dynamic.totalPltRelaEntries;
  dep.sourceOriginalTLSModules=dynamic.totalTLSHeaders;
  dep.authenticateThreeOriginalELFs=true;
  dep.linuxX86VariantIIInitializerModeled=true;
  // Every runtime-dependent flag remains FALSE or "requires";
  // this source-only contract never creates a false completion token.
  reject=Reject::None;
  return true;
}
// A caller cannot authorize actual IFUNC/IRELATIVE, FS/GS, RELRO or
// entering the original ld-linux using this data-only plan. Only a
// later independently verified guest-execution implementation may
// introduce an execution gate.
inline bool AuthorizeOriginalLdsoRelocationOrRelroFromMetadataOnly(
  const DependencyGate&,Reject& reject) noexcept {
  reject=Reject::GuestRuntimeNotStarted;
  return false;
}
} // namespace kernix::g2e::c3d7j
