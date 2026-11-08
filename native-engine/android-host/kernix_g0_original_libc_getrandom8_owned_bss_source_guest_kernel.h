// SPDX-License-Identifier: MIT
#pragma once
// EXPERIMENTAL Linux ARM64 original pinned x86 GNU libc getrandom(318).
// Only original source libc RX instruction guest RIP 0x8040a9c97,
// syscall getrandom(buffer=0x80420a178,count=8,flags=GRND_NONBLOCK=1).
// Destination is only source-verified ELF PT_LOAD/anonymous RW BSS in the
// existing original libc private VMA, never a guest-supplied arbitrary host
// pointer. Real native kernel getrandom writes to a trusted LOCAL buffer;
// only after full 8-byte success is output copied into a verified guest BSS
// slice and guest x86 RAX set to 8, not zero. No generic syscall dispatch.
//
// Linux host native page size MUST be 4096; Android 16K Bionic, Wine, Proton,
// PC gaming and full native process exit remain unproven and unsupported.
#include "kernix_g0_source_pinned_libc_large_ro_guest_map.h"
#include "kernix_g2e_c3d7b_kernel_selected_pie_guest_vas.h"
#include <array>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <elf.h>
#include <limits>
#include <string>
#include <sys/random.h>
#include <unistd.h>

namespace kernix::g0::originalgetrandom8 {
constexpr uint64_t kSourceGuestLibcBase=0x804000000ULL;
constexpr uint64_t kGuestSyscallRIP=0x8040a9c97ULL;
constexpr uint64_t kGuestSourceLibcVA=kGuestSyscallRIP-kSourceGuestLibcBase;
constexpr uint64_t kGuestOriginalDestination=0x80420a178ULL;
constexpr uint64_t kExpectedGuestBytes=8ULL;
constexpr uint64_t kGRNDNonblock=1ULL;
constexpr uint64_t kGuestSyscallNumber=318ULL;
constexpr uint64_t kOwnedLibcBSSStart=kSourceGuestLibcBase+0x205000ULL;
constexpr uint64_t kOwnedLibcBSSEnd=kSourceGuestLibcBase+0x212000ULL;
struct Witness {
  int64_t guestReturn=-ENOSYS;
  bool sourceOriginalLibcX86SyscallRXBytesAttested=false;
  bool exactGetrandomGuestArgumentsAndAuthenticatedTrap=false;
  bool libcOwnedBSSRWOnlyAndNonRELRO=false;
  bool realNativeKernelGetrandomFullEightBytesSucceeded=false;
  bool allEightGuestBytesCopiedAndReadBackExact=false;
  bool noArbitraryGuestPointerPassedToHostKernel=true;
  bool completeOriginalGuestProcessExitZeroProven=false;
  bool androidBionicWineProtonGamesProven=false;
  uint64_t guestDestination=0;
  size_t returnedNativeBytes=0;
};

inline bool OriginalPinnedLibcGetrandomRXOpcode(const uint8_t* source,
                                                size_t size) noexcept {
  if(!source || size!=2118168 || size<sizeof(Elf64_Ehdr))return false;
  Elf64_Ehdr eh{};
  std::memcpy(&eh,source,sizeof(eh));
  if(std::memcmp(eh.e_ident,ELFMAG,SELFMAG)!=0 ||
     eh.e_ident[EI_CLASS]!=ELFCLASS64 ||
     eh.e_ident[EI_DATA]!=ELFDATA2LSB ||
     eh.e_type!=ET_DYN || eh.e_machine!=EM_X86_64 ||
     eh.e_phentsize!=sizeof(Elf64_Phdr) ||
     eh.e_phnum==0 || eh.e_phnum>128 ||
     eh.e_phoff>size ||
     eh.e_phnum>(size-eh.e_phoff)/sizeof(Elf64_Phdr))
    return false;
  size_t found=0,at=0;
  for(uint16_t i=0;i<eh.e_phnum;i++){
    Elf64_Phdr ph{};
    std::memcpy(&ph,source+eh.e_phoff+i*sizeof(ph),sizeof(ph));
    if(ph.p_type!=PT_LOAD || (ph.p_flags&PF_X)==0 ||
       (ph.p_flags&PF_W)!=0)continue;
    if(ph.p_offset>size || ph.p_filesz>size-ph.p_offset ||
       ph.p_filesz>ph.p_memsz ||
       ph.p_vaddr>UINT64_MAX-ph.p_filesz)return false;
    if(kGuestSourceLibcVA<ph.p_vaddr ||
       kGuestSourceLibcVA-ph.p_vaddr>ph.p_filesz ||
       ph.p_filesz-(kGuestSourceLibcVA-ph.p_vaddr)<2)continue;
    at=ph.p_offset+kGuestSourceLibcVA-ph.p_vaddr;
    ++found;
  }
  return found==1 && at<=size-2 &&
         source[at]==0x0f && source[at+1]==0x05;
}

inline Witness HandleExactlyOriginalLibcGetrandom8(
    uint64_t syscallNumber,uint64_t guestRIP,uint64_t nextGuestRIP,
    uint64_t destination,uint64_t count,uint64_t flags,
    const kernix::g2e::c3d7b::NativeChosenPIEGuestLayout& owner,
    const kernix::g0::PinnedLibcLargeReadonlyGuestMap& originalLibcOwner,
    const uint8_t* originalLibcELF,size_t sourceSize,
    bool originalThreeSourceSHAAndGuestTrap,
    bool sourceThreeELFRELROSealedAndFstat1AlreadySucceeded,
    std::string(*rightsAt)(uint64_t)) noexcept {
  Witness w{};
  if(!rightsAt || !originalThreeSourceSHAAndGuestTrap ||
     !sourceThreeELFRELROSealedAndFstat1AlreadySucceeded ||
     ::sysconf(_SC_PAGESIZE)!=4096 ||
     syscallNumber!=kGuestSyscallNumber ||
     guestRIP!=kGuestSyscallRIP || nextGuestRIP!=kGuestSyscallRIP+2 ||
     destination!=kGuestOriginalDestination ||
     count!=kExpectedGuestBytes || flags!=kGRNDNonblock ||
     owner.WindowsHeld()!=4 || !owner.LaunchPlan() ||
     !originalLibcOwner.OriginalOwnedBSSZeroed() ||
     originalLibcOwner.Address()!=kSourceGuestLibcBase ||
     !OriginalPinnedLibcGetrandomRXOpcode(originalLibcELF,sourceSize) ||
     rightsAt(guestRIP)!="r-xp" ||
     rightsAt(0x800003000ULL)!="r--p" ||
     rightsAt(0x801036000ULL)!="r--p" ||
     rightsAt(0x801037000ULL)!="r--p")
    return w;
  const auto* live=reinterpret_cast<const uint8_t*>(static_cast<uintptr_t>(guestRIP));
  if(live[0]!=0x0f || live[1]!=0x05)return w;
  w.sourceOriginalLibcX86SyscallRXBytesAttested=true;
  w.exactGetrandomGuestArgumentsAndAuthenticatedTrap=true;
  if(destination<kOwnedLibcBSSStart ||
     destination>kOwnedLibcBSSEnd ||
     kExpectedGuestBytes>kOwnedLibcBSSEnd-destination ||
     destination%8!=0 || // guest source compiler normally uses qword-aligned
     rightsAt(destination)!="rw-p" ||
     rightsAt(destination+kExpectedGuestBytes-1)!="rw-p")
    return w;
  w.libcOwnedBSSRWOnlyAndNonRELRO=true;

  std::array<uint8_t,8> trustedLocal{};
  errno=0;
  const auto got=::getrandom(trustedLocal.data(),trustedLocal.size(),GRND_NONBLOCK);
  if(got!=static_cast<ssize_t>(trustedLocal.size())){
    w.guestReturn=got<0?-errno:-EAGAIN;
    return w;
  }
  w.realNativeKernelGetrandomFullEightBytesSucceeded=true;
  w.returnedNativeBytes=static_cast<size_t>(got);
  // NEVER use destination as host getrandom pointer.
  void* guestOut=reinterpret_cast<void*>(static_cast<uintptr_t>(destination));
  std::memcpy(guestOut,trustedLocal.data(),trustedLocal.size());
  std::array<uint8_t,8> checked{};
  std::memcpy(checked.data(),guestOut,checked.size());
  if(checked!=trustedLocal)return w;
  w.allEightGuestBytesCopiedAndReadBackExact=true;
  w.guestDestination=destination;
  w.guestReturn=8;
  return w;
}
} // namespace kernix::g0::originalgetrandom8
