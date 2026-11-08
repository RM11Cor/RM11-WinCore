// SPDX-License-Identifier: MIT
#pragma once
// EXPERIMENTAL KERNIX source-original x86 GNU libc write(1) after original
// 3-module kernel RELRO, prlimit64(302), fstat1(5), getrandom8(318).
//
// Original FEX Linux ARM64 trace: x86 write RIP 0x80411c432,
// guest fd=1, buffer=0x8000052a0, bytes=0x2d (45). The buffer is in the
// SHA-original MAIN ELF's owner-held, native mprotect-expanded brk heap,
// not the source PT_LOAD, original libc BSS, host/Android memory or guest
// stack. This helper denies all OTHER guest syscalls/pointers and copies
// exactly 45 source-owned bytes into a local native buffer BEFORE calling
// native ::write(STDOUT_FILENO, local, 45). No guest pointer is forwarded.
// Real native 4KiB Linux host pages ONLY, not Android 16KiB, Wine, games.
#include "kernix_g0_original_source_guest_program_break_owner.h"
#include "kernix_g2e_c3d7b_kernel_selected_pie_guest_vas.h"
#include <array>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <elf.h>
#include <limits>
#include <string>
#include <unistd.h>

namespace kernix::g0::originalwrite1 {
constexpr uint64_t kLibcGuestImageBase=0x804000000ULL;
constexpr uint64_t kOriginalWriteGuestRIP=0x80411c432ULL;
constexpr uint64_t kOriginalWriteSourceVA=kOriginalWriteGuestRIP-kLibcGuestImageBase;
constexpr uint64_t kOriginalGuestWriteFD=1;
constexpr uint64_t kOriginalGuestWriteHeapBuffer=0x8000052a0ULL;
constexpr uint64_t kExactGuestWriteLength=45;
struct Witness {
  int64_t guestReturn=-ENOSYS;
  bool originalSourceLibcRXAndLiveWriteSyscallOpcodeMatch=false;
  bool exactSourceOriginalGuestWriteFd1Arguments=false;
  bool originalGuestMainBrkHeapOwnerAndCurrentBounds=false;
  bool realNativeKernelWriteToFixedStdoutLocalBufferSucceeded=false;
  bool noGuestPointerEverForwardedToNativeKernel=true;
  bool guestWriteOutputBytesNotInvented=true;
  bool originalLinuxProgramExitZeroProven=false;
  bool androidBionicWineProtonGamesProven=false;
  uint64_t originalGuestBuffer=0;
  uint64_t heapMinimum=0;
  uint64_t heapCurrent=0;
  size_t actualNativeWritten=0;
};
inline bool OriginalSourceLibcWriteRXSyscall(
    const uint8_t* source,size_t length) noexcept {
  if(!source || length!=2118168 || length<sizeof(Elf64_Ehdr))return false;
  Elf64_Ehdr eh{};
  std::memcpy(&eh,source,sizeof(eh));
  if(std::memcmp(eh.e_ident,ELFMAG,SELFMAG)!=0 ||
     eh.e_ident[EI_CLASS]!=ELFCLASS64 ||
     eh.e_ident[EI_DATA]!=ELFDATA2LSB ||
     eh.e_type!=ET_DYN || eh.e_machine!=EM_X86_64 ||
     eh.e_phentsize!=sizeof(Elf64_Phdr) ||
     eh.e_phnum==0 || eh.e_phnum>128 ||
     eh.e_phoff>length ||
     eh.e_phnum>(length-eh.e_phoff)/sizeof(Elf64_Phdr))
    return false;
  size_t found=0,at=0;
  for(uint16_t i=0;i<eh.e_phnum;i++){
    Elf64_Phdr ph{};
    std::memcpy(&ph,source+eh.e_phoff+i*sizeof(ph),sizeof(ph));
    if(ph.p_type!=PT_LOAD || !(ph.p_flags&PF_X) || (ph.p_flags&PF_W))
      continue;
    if(ph.p_offset>length || ph.p_filesz>length-ph.p_offset ||
       ph.p_filesz>ph.p_memsz || ph.p_vaddr>UINT64_MAX-ph.p_filesz)
      return false;
    if(kOriginalWriteSourceVA<ph.p_vaddr ||
       kOriginalWriteSourceVA-ph.p_vaddr>ph.p_filesz ||
       ph.p_filesz-(kOriginalWriteSourceVA-ph.p_vaddr)<2)
      continue;
    at=ph.p_offset+kOriginalWriteSourceVA-ph.p_vaddr;
    ++found;
  }
  return found==1 && at<=length-2 && source[at]==0x0f && source[at+1]==0x05;
}

inline Witness HandleOnlyOriginalLibcStdoutWrite45(
    uint64_t guestSyscall,uint64_t guestRIP,uint64_t nextGuestRIP,
    uint64_t guestFD,uint64_t guestBuffer,uint64_t length,
    const kernix::g2e::c3d7b::NativeChosenPIEGuestLayout& owner,
    const kernix::g0::guestbrk::OriginalGuestMainProgramBreak& mainBrk,
    const uint8_t* pinnedOriginalLibcELF,size_t sourceLength,
    bool authenticOriginalFEXGNUPrlimitFstatGetrandomAndThreeRELRO,
    std::string(*rightsAt)(uint64_t)) noexcept {
  Witness w{};
  if(!rightsAt || !authenticOriginalFEXGNUPrlimitFstatGetrandomAndThreeRELRO ||
     ::sysconf(_SC_PAGESIZE)!=4096 ||
     guestSyscall!=1 || guestRIP!=kOriginalWriteGuestRIP ||
     nextGuestRIP!=guestRIP+2 ||
     guestFD!=kOriginalGuestWriteFD ||
     guestBuffer!=kOriginalGuestWriteHeapBuffer ||
     length!=kExactGuestWriteLength ||
     !owner.LaunchPlan() || owner.WindowsHeld()!=4 ||
     !owner.Module(0) ||
     owner.Module(0)->chosenImageStart!=0x800000000ULL ||
     !mainBrk.Ready() ||
     !OriginalSourceLibcWriteRXSyscall(pinnedOriginalLibcELF,sourceLength) ||
     rightsAt(guestRIP)!="r-xp" ||
     rightsAt(0x800003000ULL)!="r--p" ||
     rightsAt(0x801036000ULL)!="r--p" ||
     rightsAt(0x801037000ULL)!="r--p")
    return w;
  const auto* originalGuestInsn=reinterpret_cast<const uint8_t*>(
    static_cast<uintptr_t>(guestRIP));
  if(originalGuestInsn[0]!=0x0f || originalGuestInsn[1]!=0x05)return w;
  w.originalSourceLibcRXAndLiveWriteSyscallOpcodeMatch=true;
  w.exactSourceOriginalGuestWriteFd1Arguments=true;

  const uint64_t initial=mainBrk.Minimum(), now=mainBrk.Current(),
                 max=mainBrk.Limit();
  if(initial!=0x800005000ULL || now<initial || now>max ||
     guestBuffer<initial || guestBuffer>now ||
     length>now-guestBuffer ||
     guestBuffer>UINT64_MAX-length ||
     rightsAt(guestBuffer)!="rw-p" ||
     rightsAt(guestBuffer+length-1)!="rw-p")
    return w;
  // Source guest reads are isolated to original owner's mmap region,
  // which overlaps exactly the main brk's permission-expanded RW slice.
  const auto* live=owner.GuestReadOnlyBytes(0,guestBuffer,length);
  if(!live)return w;
  w.originalGuestMainBrkHeapOwnerAndCurrentBounds=true;
  std::array<uint8_t,kExactGuestWriteLength> local{};
  std::memcpy(local.data(),live,local.size());
  errno=0;
  const ssize_t got=::write(STDOUT_FILENO,local.data(),local.size());
  if(got!=static_cast<ssize_t>(local.size())){
    w.guestReturn=got<0?-errno:got;
    return w;
  }
  w.realNativeKernelWriteToFixedStdoutLocalBufferSucceeded=true;
  w.actualNativeWritten=static_cast<size_t>(got);
  w.originalGuestBuffer=guestBuffer;
  w.heapMinimum=initial;
  w.heapCurrent=now;
  w.guestReturn=got;
  return w;
}
} // namespace kernix::g0::originalwrite1
