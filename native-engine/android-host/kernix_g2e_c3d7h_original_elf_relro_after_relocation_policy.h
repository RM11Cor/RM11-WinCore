#pragma once
// SPDX-License-Identifier: MIT
// KERNIX G2-E/C3-D7H — original SHA-locked x86 Linux ELF PT_GNU_RELRO
// *POST-RELOCATION* page protection PLAN ONLY. Never mprotect RELRO
// during initial segment staging, before real glibc relocation, or
// based on a caller-controlled boolean claiming relocations completed.
//
// Original GNU glibc _dl_protect_relro uses PAGE_ALIGN_DOWN on BOTH
// (load_bias + vaddr) and (load_bias + vaddr + memsz).
// The partial trailing page must stay at its original protection.
// See glibc elf/dl-reloc.c. This header intentionally does not seal.
//
// Source integrity inherited from GuestPreflight and C3-D7G W^X plan.
// Any denied layout fails closed; NO FEX, Wine, games or device proof.
#include "kernix_g2e_c3d7g_original_elf_pt_load_page_policy.h"
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <elf.h>
#include <limits>

namespace kernix::g2e::c3d7h {
enum class Reject : uint8_t {
  None, SourceNotAttested, InvalidELF, MissingOwnedWindow,
  InvalidRELROBounds, RELROUnmappedOrExecutable, NoRelocationProof
};
struct ModuleRELRO {
  std::array<uint8_t,c3d7g::kModulePages> sealedAfterRealRelocation{};
  uint64_t imageVA=0;
  size_t relroHeaders=0;
  size_t relroFullPages=0;
  size_t relroInitiallyWritablePages=0;
  size_t relroAlreadyReadOnlyPages=0;
  size_t partialUnsealedTailPages=0;
};
struct Plan {
  std::array<ModuleRELRO,3> modules{};
  size_t relroHeaderCount=0;
  size_t totalFullPages=0;
  size_t totalInitiallyWritablePages=0;
  bool exactOriginalSHA256Sources=false;
  bool glibcBothEndpointsRoundedDown=false;
  bool noNativeMprotectApplied=true;
  bool noGuestELFRelocationsApplied=true;
  bool noFEXOriginalLdsoExecuted=true;
  bool androidDeviceTested=false;
};
inline bool BuildModule(
   const unsigned char* raw,size_t rawBytes,
   const c3d7b::ImageMeta& region,
   const c3d7g::ModulePolicy& load,
   ModuleRELRO& out,Reject& reject) noexcept {
  out={};
  reject=Reject::InvalidELF;
  if(!raw || rawBytes<sizeof(Elf64_Ehdr))return false;
  Elf64_Ehdr eh{};
  std::memcpy(&eh,raw,sizeof(eh));
  if(!g2b::GuestElfHeader(eh) ||
     eh.e_type!=ET_DYN || eh.e_machine!=EM_X86_64 ||
     eh.e_phentsize!=sizeof(Elf64_Phdr) ||
     !eh.e_phnum || eh.e_phnum>128 ||
     !g2b::ElfRange(eh.e_phoff,
         uint64_t(eh.e_phnum)*sizeof(Elf64_Phdr),rawBytes))
    return false;
  reject=Reject::MissingOwnedWindow;
  if(load.nativeOwnedStart!=region.chosenImageStart ||
     region.chosenImageStart<65536 ||
     !c1::GuestRange(region.chosenImageStart,c3d7b::kImageCapacity) ||
     region.highestAlignedELFVA<=region.lowestAlignedELFVA ||
     region.highestAlignedELFVA-region.lowestAlignedELFVA>
         c3d7b::kImageCapacity)
    return false;
  out.imageVA=region.chosenImageStart;
  for(uint16_t i=0;i<eh.e_phnum;++i) {
    Elf64_Phdr ph{};
    std::memcpy(&ph,raw+eh.e_phoff+
        size_t(i)*sizeof(ph),sizeof(ph));
    if(ph.p_type!=PT_GNU_RELRO)continue;
    ++out.relroHeaders;
    reject=Reject::InvalidRELROBounds;
    // Zero-sized GNU_RELRO is not a region to seal.
    if(!ph.p_memsz || ph.p_vaddr>UINT64_MAX-ph.p_memsz ||
       ph.p_vaddr<region.lowestAlignedELFVA ||
       region.loadBias>UINT64_MAX-ph.p_vaddr)
      return false;
    const uint64_t start=region.loadBias+ph.p_vaddr;
    if(region.loadBias>UINT64_MAX-(ph.p_vaddr+ph.p_memsz))
      return false;
    const uint64_t end=region.loadBias+ph.p_vaddr+ph.p_memsz;
    if(start>=end || end>UINT64_MAX-4095)return false;
    const uint64_t floorStart=start&~uint64_t(4095);
    const uint64_t floorEnd=end&~uint64_t(4095);
    if(floorStart<out.imageVA || floorEnd<floorStart ||
       floorEnd>out.imageVA+c3d7b::kImageCapacity)
      return false;
    if(end!=floorEnd)++out.partialUnsealedTailPages;
    const size_t beginPage=
       size_t((floorStart-out.imageVA)/4096);
    const size_t endPage=
       size_t((floorEnd-out.imageVA)/4096);
    reject=Reject::RELROUnmappedOrExecutable;
    for(size_t page=beginPage;page<endPage;++page) {
      const uint8_t flags=load.rights[page];
      // A RELRO page must be actual source-backed *data*, never RX or
      // PROT_NONE. A page already RO remains RO after relocation.
      if(!(flags&c3d7g::kRead) ||
          (flags&c3d7g::kExecute))
        return false;
      out.sealedAfterRealRelocation[page]=1;
    }
  }
  reject=Reject::None;
  for(size_t i=0;i<c3d7g::kModulePages;++i) {
    if(out.sealedAfterRealRelocation[i]) {
      ++out.relroFullPages;
      if(load.rights[i]&c3d7g::kWrite)
        ++out.relroInitiallyWritablePages;
      else
        ++out.relroAlreadyReadOnlyPages;
    }
  }
  return true;
}
inline bool BuildVerifiedOriginalThreeELFRelroPlan(
     const GuestPreflight& source,
     const c3d7b::NativeChosenPIEGuestLayout& owned,
     const c3d7g::PermissionPlan& initial,
     Plan& result,Reject& rejected) noexcept {
  result={};
  rejected=Reject::SourceNotAttested;
  if(!source.exactSha256Matched ||
     !source.readOnlyAnonymousSnapshots ||
     !source.exactInterpreterAndGlibcClosure ||
     source.guestCodeExecuted || source.dynamicLinkerExecuted ||
     source.fexAttached || source.wineExecuted ||
     !initial.sourceShaVerified ||
     !initial.nativeGuestVAIdentityOwned ||
     !initial.allPTLoadPagesPlanned ||
     !initial.deniedWritableExecutablePages ||
     owned.WindowsHeld()!=4 || !owned.LaunchPlan() ||
     ::sysconf(_SC_PAGESIZE)!=4096)
    return false;
  for(size_t i=0;i<3;++i) {
    const auto* meta=owned.Module(i);
    rejected=Reject::MissingOwnedWindow;
    if(!meta || !source.snapshots[i].bytes() ||
       !source.snapshots[i].readOnlySnapshot() ||
       source.snapshots[i].size()!=kGuest[i].bytes)
      return false;
    if(!BuildModule(source.snapshots[i].bytes(),
         source.snapshots[i].size(),*meta,
         initial.modules[i],result.modules[i],rejected))
      return false;
    result.relroHeaderCount+=result.modules[i].relroHeaders;
    result.totalFullPages+=result.modules[i].relroFullPages;
    result.totalInitiallyWritablePages+=
      result.modules[i].relroInitiallyWritablePages;
  }
  // All original snapshots and the source W^X staging have succeeded.
  // This does not attest that any relocation has executed.
  result.exactOriginalSHA256Sources=true;
  result.glibcBothEndpointsRoundedDown=true;
  rejected=Reject::None;
  return true;
}
// Without a cryptographically/ABI-attested real relocation completion
// witness from a future genuine x86 ld-linux loader, sealing the
// writable RELRO pages is explicitly prohibited. No fake "test pass"
// can set the witness in this source-only phase.
inline bool SealOriginalRelroBeforeVerifiedRealRelocations(
     const Plan&,Reject& rejected) noexcept {
  rejected=Reject::NoRelocationProof;
  return false;
}
} // namespace kernix::g2e::c3d7h
