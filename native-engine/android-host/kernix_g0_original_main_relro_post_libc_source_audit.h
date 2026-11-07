// SPDX-License-Identifier: MIT
#pragma once
// G0 source-only Linux ARM64 diagnostic. Original GNU ld-linux has
// already executed libc's source-attested RELRO mprotect(10), then makes
// a new authentic guest syscall for original MAIN ELF PT_GNU_RELRO.
// Verify this separate original source-page boundary WITHOUT sealing:
// full original dynamic relocation closure has not been demonstrated.
// The callback MUST fail closed on the first next unsupported syscall.
// No host mprotect, mmap, native-path/FD forwarding or code modification.

#include "kernix_g2e_c3d7g_native_pt_load_wx_apply_gate.h"
#include "kernix_g2e_c1_x86_linux_syscall_boundary.h"
#include <cstdint>
#include <cstring>
#include <elf.h>
#include <unistd.h>

namespace kernix::g0::mainrelroaudit {
struct Witness {
  uint64_t start=0;
  uint64_t end=0;
  uint64_t originalGuestRequest=0;
  bool authenticatedGuestMprotect10=false;
  bool originalSourceELF64PTGNURelroFullPage=false;
  bool sourceOwnedOriginalMainRWPage=false;
  bool noGuestVMRightsModified=true;
  bool realDynamicRelocationClosureAttested=false;
};
inline Witness ObserveNextOriginalMainRELRO(
    const kernix::g2e::c1::TrapClassification& t,
    const kernix::g2e::c3d7b::NativeChosenPIEGuestLayout& owned,
    const kernix::g2e::c3d7g::PermissionPlan& plan,
    const kernix::g2e::c3d7g::ApplyWitness& applied,
    uint64_t expectedOriginalMainRelroRWPage,
    bool currentPageNativeRW) noexcept {
  namespace c1=kernix::g2e::c1;
  namespace g=kernix::g2e::c3d7g;
  Witness out{};
  const auto* main=owned.Module(0);
  if(!main || main->lowestAlignedELFVA!=0 ||
     main->loadBias!=main->chosenImageStart ||
     main->loadBias>UINT64_MAX-g::kModulePages*4096ULL ||
     !expectedOriginalMainRelroRWPage ||
     !currentPageNativeRW ||
     ::sysconf(_SC_PAGESIZE)!=4096 ||
     owned.WindowsHeld()!=4 || !owned.LaunchPlan() ||
     !plan.sourceShaVerified ||
     !plan.nativeGuestVAIdentityOwned ||
     !plan.allPTLoadPagesPlanned ||
     !plan.deniedWritableExecutablePages ||
     !applied.originalPinnedSourceValidated ||
     !applied.eachPTLoadFlagTranslatedToNative ||
     !applied.nativeNoWritableExecutablePage ||
     !applied.nativeNonPTLoadHolesDenied ||
     applied.androidDeviceTested ||
     !t.trapBoundaryAuthenticated ||
     !t.sourceRegisterMappingChecked ||
     t.hostSyscallDispatched || t.guestMemoryDereferenced ||
     t.guestNumber!=c1::kMprotect ||
     t.category!=c1::CallCategory::NeedsGuestKernel ||
     t.args[0]!=expectedOriginalMainRelroRWPage ||
     t.args[1]!=4096 ||
     t.args[2]!=1 ||
     !c1::GuestRange(t.args[0],4096) ||
     t.args[0]<main->chosenImageStart ||
     t.args[0]-main->chosenImageStart>=g::kModulePages*4096ULL)
    return out;
  out.authenticatedGuestMprotect10=true;
  out.originalGuestRequest=t.args[0];
  const size_t page=static_cast<size_t>(
      (t.args[0]-main->chosenImageStart)/4096);
  if(plan.modules[0].nativeOwnedStart!=main->chosenImageStart ||
     plan.modules[0].rights[page]!=(g::kRead|g::kWrite) ||
     !owned.GuestReadOnlyBytes(0,t.args[0],4096))
    return out;
  out.sourceOwnedOriginalMainRWPage=true;

  // PT_GNU_RELRO end is deliberately rounded DOWN, matching original
  // glibc, so a partially writable trailing page cannot be sealed.
  const auto* hdr=owned.GuestReadOnlyBytes(
      0,main->chosenImageStart,4096);
  if(!hdr)return out;
  Elf64_Ehdr eh{};
  std::memcpy(&eh,hdr,sizeof(eh));
  if(std::memcmp(eh.e_ident,ELFMAG,SELFMAG)!=0 ||
     eh.e_ident[EI_CLASS]!=ELFCLASS64 ||
     eh.e_ident[EI_DATA]!=ELFDATA2LSB ||
     eh.e_type!=ET_DYN || eh.e_machine!=EM_X86_64 ||
     eh.e_phentsize!=sizeof(Elf64_Phdr) ||
     eh.e_phnum==0 || eh.e_phnum>64 ||
     eh.e_phoff>4096 ||
     static_cast<size_t>(eh.e_phnum)>
        (4096-eh.e_phoff)/sizeof(Elf64_Phdr))
    return out;
  unsigned count=0;
  for(unsigned i=0;i<eh.e_phnum;++i) {
    Elf64_Phdr ph{};
    std::memcpy(&ph,hdr+eh.e_phoff+
      static_cast<size_t>(i)*sizeof(ph),sizeof(ph));
    if(ph.p_type!=PT_GNU_RELRO)continue;
    ++count;
    if(!ph.p_memsz || ph.p_vaddr>UINT64_MAX-ph.p_memsz ||
       main->loadBias>UINT64_MAX-ph.p_vaddr-ph.p_memsz)
      return out;
    const uint64_t first=
       (main->loadBias+ph.p_vaddr)&~uint64_t(4095);
    const uint64_t end=
       (main->loadBias+ph.p_vaddr+ph.p_memsz)&~uint64_t(4095);
    out.start=first;out.end=end;
    if(first!=expectedOriginalMainRelroRWPage ||
       end-first!=4096)
      return out;
  }
  out.originalSourceELF64PTGNURelroFullPage=count==1;
  return out;
}
} // namespace kernix::g0::mainrelroaudit
