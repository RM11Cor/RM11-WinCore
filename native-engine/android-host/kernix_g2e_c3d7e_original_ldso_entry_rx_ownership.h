#pragma once
// SPDX-License-Identifier: MIT
// KERNIX C3-D7E: real original SHA-pinned Linux x86-64 dynamic linker
// instruction entry bytes and host-owned W^X page readiness only.
// Must NEVER execute ld-linux here or claim Wine/PE support.
#include "kernix_g2e_c3d7b_kernel_selected_pie_guest_vas.h"
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cerrno>
#include <elf.h>
#include <sys/mman.h>
#include <unistd.h>

namespace kernix::g2e::c3d7e {
struct EntryProof {
  uint64_t guestRIP=0;
  uint64_t entrySourceELFVirtual=0;
  uint64_t selectedImageBase=0;
  size_t testedOriginalCodeBytes=0;
  size_t executableSegments=0;
  int lastErrno=0;
  bool originalSha256Source=true;
  bool entryIsInsideOriginalFileBackedRXSegment=false;
  bool instructionBytesMatchOriginalSource=false;
  bool kernelNativeRXTemporarilyEstablished=false;
  bool nativeRORestored=false;
  bool originalGuestInstructionsExecuted=false;
  bool originalDynamicLinkerStarted=false;
  bool fexGuestRIPAssigned=false;
};
// With the staged guest windows already checked SHA and left RO, perform
// non-overwriting permission toggling ONLY on an owned 4K entry page.
// This is *not* the actual loader startup or the complete ELF page policy.
inline bool VerifyOriginalGuestEntryAndTemporaryHostRX(
    const c3d7b::NativeChosenPIEGuestLayout& owned,
    const GuestPreflight& originals,
    size_t which,EntryProof& w) noexcept {
  w={};
  if(which>1 || !originals.exactSha256Matched ||
     !originals.readOnlyAnonymousSnapshots ||
     !originals.exactInterpreterAndGlibcClosure ||
     ::sysconf(_SC_PAGESIZE)!=4096 || owned.WindowsHeld()!=4 ||
     !owned.LaunchPlan() || !owned.Module(which)) {
    w.lastErrno=EINVAL;
    return false;
  }
  const auto* meta=owned.Module(which);
  const auto* launch=owned.LaunchPlan();
  const uint64_t entry=(which==0)
      ?launch->guestMainEntry:launch->guestInterpreterEntry;
  if(entry==0 || entry<0x10000 ||
     !c1::GuestRange(entry,16) ||
     !meta->loadBias || entry<meta->chosenImageStart ||
     entry-meta->chosenImageStart>=c3d7b::kImageCapacity) {
    w.lastErrno=ERANGE;
    return false;
  }
  const auto& src=originals.snapshots[which];
  if(!src.readOnlySnapshot() || !src.bytes() ||
     src.size()<sizeof(Elf64_Ehdr)) {
    w.lastErrno=ENOEXEC;
    return false;
  }
  Elf64_Ehdr eh{};
  std::memcpy(&eh,src.bytes(),sizeof(eh));
  if(!g2b::GuestElfHeader(eh) || eh.e_machine!=EM_X86_64 ||
     eh.e_type!=ET_DYN ||
     eh.e_phentsize!=sizeof(Elf64_Phdr) ||
     !g2b::ElfRange(eh.e_phoff,
         uint64_t(eh.e_phnum)*sizeof(Elf64_Phdr),src.size()) ||
     eh.e_entry>UINT64_MAX-meta->loadBias ||
     entry!=eh.e_entry+meta->loadBias) {
    w.lastErrno=ENOEXEC;
    return false;
  }
  w.guestRIP=entry;
  w.entrySourceELFVirtual=eh.e_entry;
  w.selectedImageBase=meta->chosenImageStart;
  constexpr size_t kReadBytes=16;
  const unsigned char* source=nullptr;
  for(uint16_t i=0;i<eh.e_phnum;++i) {
    Elf64_Phdr ph{};
    std::memcpy(&ph,src.bytes()+eh.e_phoff+
                  size_t(i)*sizeof(ph),sizeof(ph));
    if(ph.p_type!=PT_LOAD || !ph.p_memsz)continue;
    if((ph.p_flags&PF_X)!=0)++w.executableSegments;
    if((ph.p_flags&(PF_X|PF_W))==(PF_X|PF_W)) {
      w.lastErrno=EACCES;return false;
    }
    if((ph.p_flags&PF_X)==0 || (ph.p_flags&PF_W)!=0 ||
       eh.e_entry<ph.p_vaddr)continue;
    const uint64_t within=eh.e_entry-ph.p_vaddr;
    if(ph.p_filesz<kReadBytes || within>ph.p_filesz-kReadBytes ||
       ph.p_offset>src.size() ||
       within>src.size()-ph.p_offset ||
       kReadBytes>src.size()-ph.p_offset-within)continue;
    if(source) {
      w.lastErrno=ENOEXEC;return false;
    }
    source=src.bytes()+ph.p_offset+within;
  }
  if(!source || !w.executableSegments) {
    w.lastErrno=ENOEXEC;return false;
  }
  w.entryIsInsideOriginalFileBackedRXSegment=true;
  const auto* selected=owned.GuestReadOnlyBytes(which,entry,kReadBytes);
  if(!selected || reinterpret_cast<uintptr_t>(selected)!=entry ||
     std::memcmp(selected,source,kReadBytes)!=0) {
    w.lastErrno=EIO;return false;
  }
  w.instructionBytesMatchOriginalSource=true;
  w.testedOriginalCodeBytes=kReadBytes;
  // The owned region remains RO; page is briefly RX, then RO again.
  // This operation cannot create writable+executable permissions.
  const uintptr_t aligned=static_cast<uintptr_t>(entry)&~uintptr_t(4095);
  if(!owned.GuestReadOnlyBytes(which,aligned,c3d7b::kPagesize)) {
    w.lastErrno=ERANGE;return false;
  }
  if(::mprotect(reinterpret_cast<void*>(aligned),4096,
               PROT_READ|PROT_EXEC)!=0) {
    w.lastErrno=errno;return false;
  }
  w.kernelNativeRXTemporarilyEstablished=true;
  // Fail closed on rollback failure; all regions still belong to owned
  // and its destructor frees them. Never jump to executable bytes.
  if(::mprotect(reinterpret_cast<void*>(aligned),4096,PROT_READ)!=0) {
    w.lastErrno=errno;return false;
  }
  w.nativeRORestored=true;
  if(std::memcmp(selected,source,kReadBytes)!=0) {
    w.lastErrno=EIO;return false;
  }
  return true;
}
} // namespace kernix::g2e::c3d7e
