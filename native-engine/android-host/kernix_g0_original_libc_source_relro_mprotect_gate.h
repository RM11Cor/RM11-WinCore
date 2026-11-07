// SPDX-License-Identifier: MIT
#pragma once
// G0 Linux ARM64 observation/test only: genuine original x86-64 GNU ldso
// mprotect(10) against the *second*, synthetic-libc-FD100-owned mmap.
// Only the SHA-pinned original libc ELF PT_GNU_RELRO full-page source
// span may be changed from guest RW to R. No guest-selected arbitrary VA,
// native MAP_FIXED, host path, executable mapping or general mprotect.
//
// This does NOT prove other libc relocations or complete dynamic linking.
// It can ONLY be used in an isolated diagnostic following real FEX rseq
// and one source-authorized _rtld_global_ro GOT relocation.
#include "kernix_g0_source_pinned_libc_large_ro_guest_map.h"
#include "kernix_g2e_c1_x86_linux_syscall_boundary.h"
#include <cstdint>
#include <cstring>
#include <elf.h>
#include <sys/mman.h>
#include <unistd.h>

namespace kernix::g0::originalrelro {
struct Witness {
  int64_t guestReturn=-ENOSYS;
  uint64_t sourceRelroBegin=0;
  uint64_t sourceRelroEnd=0;
  bool originalELF64GNURELROPageSpanMatched=false;
  bool sourceOriginalLibcRWPTLoadMatched=false;
  bool genuineGuestMprotect10Authenticated=false;
  bool originalGuestOwnerWasRWBeforeSeal=false;
  bool nativeGuestRELROPageRangeChangedToReadOnly=false;
  bool noGuestExecutablePageGranted=true;
  bool noHostGuestFdPathOrMAPFIXED=true;
  bool completeDynamicRelocations=false;
};

inline Witness SealOriginalLibcSourceRELRO(
    const kernix::g2e::c1::TrapClassification& t,
    const PinnedLibcLargeReadonlyGuestMap& libc,
    bool guestOriginalLibcFDClosed,
    bool originalRseqENOSYS,
    bool oneExactOriginalLibcGLOB_DATApplied,
    bool allFourRelroPagesNativeRW) noexcept {
  namespace c1=kernix::g2e::c1;
  Witness out{};
  constexpr uint64_t kRelroOffset=0x1ff000ULL;
  constexpr uint64_t kRelroLength=0x4000ULL;
  constexpr uint64_t kNextRWOffset=kRelroOffset+kRelroLength;
  const uint64_t base=libc.Address();
  if(!base || base>UINT64_MAX-kNextRWOffset ||
     !guestOriginalLibcFDClosed || !originalRseqENOSYS ||
     !oneExactOriginalLibcGLOB_DATApplied ||
     !allFourRelroPagesNativeRW ||
     !libc.OriginalSourceTextRXSealed() ||
     !libc.OriginalSourceReadOnlyPTLoadConfirmed() ||
     !libc.OriginalSourceWritablePTLoadConfirmed() ||
     !libc.OriginalOwnedBSSZeroed() ||
     libc.CopiedSourceBytes()!=PinnedLibcLargeReadonlyGuestMap::kOriginalLibcSize ||
     libc.BytesHeld()<kNextRWOffset+4096 ||
     ::sysconf(_SC_PAGESIZE)!=4096 ||
     !t.trapBoundaryAuthenticated ||
     !t.sourceRegisterMappingChecked ||
     t.hostSyscallDispatched || t.guestMemoryDereferenced ||
     t.guestNumber!=c1::kMprotect ||
     t.category!=c1::CallCategory::NeedsGuestKernel ||
     t.args[0]!=base+kRelroOffset ||
     t.args[1]!=kRelroLength ||
     t.args[2]!=uint64_t(PROT_READ) ||
     !c1::GuestRange(base+kRelroOffset,kRelroLength))
    return out;
  out.genuineGuestMprotect10Authenticated=true;

  // Read only the mapped guest source header known to be identical to the
  // original source snapshot, including its program-header table.
  // GNU_RELRO itself is source metadata; guest-provided syscall args alone
  // never authorize changing a page.
  constexpr size_t kMaxHeader=4096;
  const auto* bytes=libc.AuthenticatedReadonlyBytes(base,kMaxHeader);
  if(!bytes)return out;
  Elf64_Ehdr e{};
  std::memcpy(&e,bytes,sizeof(e));
  if(std::memcmp(e.e_ident,ELFMAG,SELFMAG)!=0 ||
     e.e_ident[EI_CLASS]!=ELFCLASS64 ||
     e.e_ident[EI_DATA]!=ELFDATA2LSB ||
     e.e_ident[EI_VERSION]!=EV_CURRENT ||
     e.e_machine!=EM_X86_64 || e.e_type!=ET_DYN ||
     e.e_phentsize!=sizeof(Elf64_Phdr) ||
     e.e_phnum==0 || e.e_phnum>128 ||
     e.e_phoff>kMaxHeader ||
     static_cast<size_t>(e.e_phnum)>
       (kMaxHeader-e.e_phoff)/sizeof(Elf64_Phdr))
     return out;
  bool exactRelro=false, originalRW=false;
  for(uint16_t i=0;i<e.e_phnum;++i) {
    Elf64_Phdr ph{};
    std::memcpy(&ph,bytes+e.e_phoff+size_t(i)*sizeof(ph),sizeof(ph));
    if(ph.p_vaddr>UINT64_MAX-ph.p_memsz || !ph.p_memsz)
      continue;
    const uint64_t first=ph.p_vaddr&~uint64_t(4095);
    const uint64_t end=ph.p_vaddr+ph.p_memsz;
    if(end>UINT64_MAX-4095)continue;
    const uint64_t past=(end+4095)&~uint64_t(4095);
    if(ph.p_type==PT_GNU_RELRO) {
      out.sourceRelroBegin=first;
      out.sourceRelroEnd=past;
      if(first==kRelroOffset && past==kNextRWOffset)
        exactRelro=true;
    }
    if(ph.p_type==PT_LOAD && ph.p_flags==(PF_R|PF_W) &&
       first<=kRelroOffset && past>=kNextRWOffset &&
       ph.p_filesz<=ph.p_memsz)
      originalRW=true;
  }
  out.originalELF64GNURELROPageSpanMatched=exactRelro;
  out.sourceOriginalLibcRWPTLoadMatched=originalRW;
  if(!exactRelro || !originalRW)return out;
  out.originalGuestOwnerWasRWBeforeSeal=true;
  const auto addr=reinterpret_cast<void*>(
      static_cast<uintptr_t>(base+kRelroOffset));
  if(::mprotect(addr,static_cast<size_t>(kRelroLength),PROT_READ)!=0) {
    out.guestReturn=-EACCES;
    return out;
  }
  out.nativeGuestRELROPageRangeChangedToReadOnly=true;
  out.guestReturn=0;
  return out;
}
} // namespace kernix::g0::originalrelro
