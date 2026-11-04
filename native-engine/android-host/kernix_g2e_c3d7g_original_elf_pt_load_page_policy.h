#pragma once
// SPDX-License-Identifier: MIT
// KERNIX G2-E/C3-D7G: SOURCE-ATTESTED original Linux x86-64 ELF PT_LOAD
// page-level permission policy. No mmap/mprotect, JIT, guest/syscall
// execution or Android device claim in this gate. Runtime applies a
// separately audited plan only after a source-pinned gate passes.
//
// This is intentionally fail closed on W+X PT_LOAD segments and on
// conflicting page-rounded PT_LOAD rights, even when the OS ELF loader
// might resolve that conflict using another remapping strategy.
#include "kernix_g2e_c3d7b_kernel_selected_pie_guest_vas.h"
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <elf.h>
#include <limits>
#include <sys/mman.h>
#include <unistd.h>

namespace kernix::g2e::c3d7g {
inline constexpr size_t kModulePages=
    c3d7b::kImageCapacity/c3d7b::kPagesize;
inline constexpr uint8_t kRead=1;
inline constexpr uint8_t kWrite=2;
inline constexpr uint8_t kExecute=4;
enum class Reject : uint8_t {
  None, SourceNotAttested, UnsupportedKernelPage, InvalidELF,
  InvalidRegion, BadSegment, ConflictingWXPage,
  EntryNotExecutable, StackNotIsolated
};
struct ModulePolicy {
  std::array<uint8_t,kModulePages> rights{}; // 0 = inaccessible hole
  uint64_t nativeOwnedStart=0;
  uint64_t nativeEntry=0;
  size_t loadSegments=0;
  size_t mappedPages=0;
  size_t executablePages=0;
  size_t writablePages=0;
  size_t inaccessiblePages=0;
};
struct PermissionPlan {
  std::array<ModulePolicy,3> modules{};
  uint64_t stackBottom=0;
  uint64_t stackRSP=0;
  size_t guardBytes=4096;
  size_t stackBytes=0;
  bool sourceShaVerified=false;
  bool nativeGuestVAIdentityOwned=false;
  bool allPTLoadPagesPlanned=false;
  bool deniedWritableExecutablePages=false;
  bool originalLdsoExecuted=false;
  bool androidRuntimeTested=false;
};
inline uint8_t RightsFromPHDR(uint32_t flags) noexcept {
  return static_cast<uint8_t>(
      ((flags&PF_R)?kRead:0) |
      ((flags&PF_W)?kWrite:0) |
      ((flags&PF_X)?kExecute:0));
}
// Pure parser used by CI both for the exact source-locked original
// three modules and synthetic malformed ELF / conflicting permission
// rejection fixtures. Synthetic fixtures NEVER count as source proof.
inline bool BuildModulePolicy(const unsigned char* src,size_t srcBytes,
                              const c3d7b::ImageMeta& region,
                              uint64_t expectedEntry,
                              ModulePolicy& out,Reject& rejected) noexcept {
  out={};
  rejected=Reject::InvalidELF;
  if(!src || srcBytes<sizeof(Elf64_Ehdr))return false;
  Elf64_Ehdr eh{};
  std::memcpy(&eh,src,sizeof(eh));
  if(!g2b::GuestElfHeader(eh) || eh.e_type!=ET_DYN ||
     eh.e_machine!=EM_X86_64 ||
     eh.e_phentsize!=sizeof(Elf64_Phdr) ||
     eh.e_phnum==0 || eh.e_phnum>128 ||
     !g2b::ElfRange(eh.e_phoff,
       uint64_t(eh.e_phnum)*sizeof(Elf64_Phdr),srcBytes))
    return false;
  rejected=Reject::InvalidRegion;
  if(region.chosenImageStart<65536 ||
     region.lowestAlignedELFVA>eh.e_entry ||
     region.highestAlignedELFVA<=region.lowestAlignedELFVA ||
     region.highestAlignedELFVA-
       region.lowestAlignedELFVA>c3d7b::kImageCapacity ||
     region.loadBias>UINT64_MAX-eh.e_entry ||
     expectedEntry!=region.loadBias+eh.e_entry ||
     !c1::GuestRange(region.chosenImageStart,c3d7b::kImageCapacity))
    return false;
  out.nativeOwnedStart=region.chosenImageStart;
  out.nativeEntry=expectedEntry;
  for(uint16_t i=0;i<eh.e_phnum;++i) {
    Elf64_Phdr ph{};
    std::memcpy(&ph,src+eh.e_phoff+size_t(i)*sizeof(ph),sizeof(ph));
    if(ph.p_type!=PT_LOAD || ph.p_memsz==0)continue;
    rejected=Reject::BadSegment;
    if(ph.p_filesz>ph.p_memsz ||
       ph.p_vaddr>UINT64_MAX-ph.p_memsz ||
       ph.p_offset>UINT64_MAX-ph.p_filesz ||
       !g2b::ElfRange(ph.p_offset,ph.p_filesz,srcBytes) ||
       (ph.p_offset%4096)!=(ph.p_vaddr%4096) ||
       ph.p_vaddr<region.lowestAlignedELFVA ||
       ph.p_flags & ~(uint32_t(PF_R|PF_W|PF_X)) ||
       ((ph.p_flags&PF_R)==0) ||
       ((ph.p_flags&(PF_W|PF_X))==(PF_W|PF_X)))
      return false;
    const uint64_t end=ph.p_vaddr+ph.p_memsz;
    if(end>UINT64_MAX-4095)return false;
    const uint64_t first=ph.p_vaddr&~uint64_t(4095);
    const uint64_t past=(end+4095)&~uint64_t(4095);
    if(past>region.highestAlignedELFVA || past<=first)return false;
    const size_t beginPage=static_cast<size_t>(
      (first-region.lowestAlignedELFVA)/4096);
    const size_t endPage=static_cast<size_t>(
      (past-region.lowestAlignedELFVA)/4096);
    if(endPage>kModulePages || beginPage>=endPage)return false;
    const uint8_t rights=RightsFromPHDR(ph.p_flags);
    ++out.loadSegments;
    for(size_t p=beginPage;p<endPage;++p) {
      const uint8_t merged=out.rights[p]|rights;
      if((merged&(kWrite|kExecute))==(kWrite|kExecute)) {
        rejected=Reject::ConflictingWXPage;
        out={};
        return false;
      }
      out.rights[p]=merged;
    }
  }
  if(!out.loadSegments || out.loadSegments!=region.loadSegments) {
    rejected=Reject::BadSegment;out={};return false;
  }
  for(uint8_t rights:out.rights) {
    if(rights==0)++out.inaccessiblePages;
    else {
      ++out.mappedPages;
      if(rights&kWrite)++out.writablePages;
      if(rights&kExecute)++out.executablePages;
    }
  }
  if(out.mappedPages==0 || !out.executablePages ||
     out.mappedPages+out.inaccessiblePages!=kModulePages) {
    rejected=Reject::BadSegment;out={};return false;
  }
  const uint64_t page=(expectedEntry-region.chosenImageStart)/4096;
  if(expectedEntry<region.chosenImageStart || page>=kModulePages ||
     (out.rights[static_cast<size_t>(page)]&(kRead|kExecute))!=
       (kRead|kExecute) ||
     (out.rights[static_cast<size_t>(page)]&kWrite)) {
    rejected=Reject::EntryNotExecutable;
    out={};return false;
  }
  rejected=Reject::None;
  return true;
}
inline bool BuildVerifiedOriginalPermissionPlan(
    const GuestPreflight& pinned,
    const c3d7b::NativeChosenPIEGuestLayout& owned,
    PermissionPlan& plan,Reject& rejected) noexcept {
  plan={};
  rejected=Reject::SourceNotAttested;
  if(!pinned.exactSha256Matched ||
     !pinned.readOnlyAnonymousSnapshots ||
     !pinned.exactInterpreterAndGlibcClosure ||
     pinned.guestCodeExecuted || pinned.dynamicLinkerExecuted ||
     pinned.fexAttached || pinned.wineExecuted ||
     owned.WindowsHeld()!=4 || !owned.LaunchPlan())
    return false;
  rejected=Reject::UnsupportedKernelPage;
  if(::sysconf(_SC_PAGESIZE)!=4096)return false;
  const auto* entry=owned.LaunchPlan();
  for(size_t i=0;i<3;++i) {
    rejected=Reject::SourceNotAttested;
    if(!owned.Module(i) ||
       !pinned.snapshots[i].readOnlySnapshot() ||
       !pinned.snapshots[i].bytes() ||
       pinned.snapshots[i].size()!=kGuest[i].bytes)
      return false;
    const uint64_t expectedEntry=
      (i==0)?entry->guestMainEntry:
      (i==1)?entry->guestInterpreterEntry:0;
    uint64_t moduleEntry=expectedEntry;
    if(i==2) {
      Elf64_Ehdr eh{};
      std::memcpy(&eh,pinned.snapshots[i].bytes(),sizeof(eh));
      if(eh.e_entry>UINT64_MAX-owned.Module(i)->loadBias) {
        rejected=Reject::InvalidELF;return false;
      }
      moduleEntry=owned.Module(i)->loadBias+eh.e_entry;
    }
    if(!BuildModulePolicy(
        pinned.snapshots[i].bytes(),pinned.snapshots[i].size(),
        *owned.Module(i),moduleEntry,plan.modules[i],rejected))
      return false;
  }
  rejected=Reject::StackNotIsolated;
  const auto& stack=entry->stack;
  if(stack.guestBottom<65536 ||
     !c1::GuestRange(stack.guestBottom,c3d7b::kStackCapacity) ||
     stack.bytes.size()!=c3d7b::kStackCapacity ||
     stack.guestRSP<stack.guestBottom+4096 ||
     stack.guestRSP>=stack.guestBottom+c3d7b::kStackCapacity ||
     (stack.guestRSP&15)!=0)
    return false;
  const auto* guestStack=
      reinterpret_cast<const unsigned char*>(
         static_cast<uintptr_t>(stack.guestBottom));
  if(std::memcmp(guestStack,stack.bytes.data(),stack.bytes.size())!=0)
    return false;
  plan.stackBottom=stack.guestBottom;
  plan.stackRSP=stack.guestRSP;
  plan.stackBytes=stack.bytes.size();
  plan.sourceShaVerified=true;
  plan.nativeGuestVAIdentityOwned=true;
  plan.allPTLoadPagesPlanned=true;
  plan.deniedWritableExecutablePages=true;
  rejected=Reject::None;
  return true;
}
} // namespace kernix::g2e::c3d7g
