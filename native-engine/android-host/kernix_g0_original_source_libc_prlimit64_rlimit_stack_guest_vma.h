// SPDX-License-Identifier: MIT
#pragma once
// EXPERIMENTAL narrow original Linux x86 GNU libc prlimit64(302) GET-only.
//
// Source original SHA-pinned libc.so.6 ELF64 + exact original live x86
// syscall instruction at 0x80411d082; pid=0, RLIMIT_STACK (3), new=NULL;
// old output is an authenticated 16-byte RW *original guest stack* slice.
// Never forward a guest-provided pointer, pid or resource to host syscall.
// Never grant a general prlimit64 or Wine permission on Android.
#include "kernix_g2e_c3d7b_kernel_selected_pie_guest_vas.h"
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <elf.h>
#include <limits>
#include <string>
#include <sys/resource.h>
#include <unistd.h>

namespace kernix::g0::originalprlimit {
constexpr uint64_t kOriginalLibcBase=0x804000000ULL;
constexpr uint64_t kOriginalLibcGuestSyscallRIP=0x80411d082ULL;
constexpr uint64_t kSourceLibcTextVA=kOriginalLibcGuestSyscallRIP-kOriginalLibcBase;
constexpr uint64_t kGuestSyscall=302;
constexpr uint64_t kGuestRLIMIT_STACK=3;
constexpr uint64_t kGuestStackOutputBytes=16;
struct Witness {
  int64_t guestReturn=-ENOSYS;
  bool exactOriginalLibcSourceRXSyscallByteAndGuestOpcode=false;
  bool exactOriginalGuestPID0RLIMIT_STACKGetOnly=false;
  bool outputOriginalOwnerStack16BytesWritable=false;
  bool realNativeKernelGetrlimitSucceeded=false;
  bool nativeLinuxRLIMITStackCopiedIntoOriginalGuestBuffer=false;
  bool originalLdsoSelfRelroNative8KAlreadySealed=false;
  bool androidBionicWineProtonGamesProven=false;
  uint64_t originalGuestOutput=0;
  uint64_t nativeSoftLimit=0;
  uint64_t nativeHardLimit=0;
};
inline bool SourceELFLibcGuestSyscallOpcode(const uint8_t* source,size_t length,
                                           uint64_t expectedGuestRIP) noexcept {
  if(!source || length!=2118168 || expectedGuestRIP!=kOriginalLibcGuestSyscallRIP ||
     length<sizeof(Elf64_Ehdr))return false;
  Elf64_Ehdr eh{};
  std::memcpy(&eh,source,sizeof(eh));
  if(std::memcmp(eh.e_ident,ELFMAG,SELFMAG)!=0 ||
     eh.e_ident[EI_CLASS]!=ELFCLASS64 ||
     eh.e_ident[EI_DATA]!=ELFDATA2LSB ||
     eh.e_machine!=EM_X86_64 || eh.e_type!=ET_DYN ||
     eh.e_phentsize!=sizeof(Elf64_Phdr) ||
     eh.e_phnum==0 || eh.e_phnum>128 ||
     eh.e_phoff>length ||
     eh.e_phnum>(length-eh.e_phoff)/sizeof(Elf64_Phdr))
    return false;
  size_t matches=0;
  size_t offset=0;
  for(unsigned i=0;i<eh.e_phnum;i++){
    Elf64_Phdr ph{};
    std::memcpy(&ph,source+eh.e_phoff+size_t(i)*sizeof(ph),sizeof(ph));
    if(ph.p_type!=PT_LOAD || (ph.p_flags&PF_X)==0 ||
       (ph.p_flags&PF_W)!=0)continue;
    if(ph.p_offset>length || ph.p_filesz>length-ph.p_offset ||
       ph.p_filesz>ph.p_memsz || ph.p_vaddr>UINT64_MAX-ph.p_filesz)
      return false;
    if(kSourceLibcTextVA<ph.p_vaddr ||
       kSourceLibcTextVA-ph.p_vaddr>ph.p_filesz ||
       ph.p_filesz-(kSourceLibcTextVA-ph.p_vaddr)<2)
      continue;
    offset=ph.p_offset+(kSourceLibcTextVA-ph.p_vaddr);
    ++matches;
  }
  return matches==1 && offset<=length-2 &&
         source[offset]==0x0f && source[offset+1]==0x05;
}
inline Witness HandleOneOriginalLibcPrlimit64GetStack(
    uint64_t originalGuestSyscallNumber,
    uint64_t sourceGuestRIP,
    uint64_t sourceNextRIP,
    uint64_t guestPID,
    uint64_t guestResource,
    uint64_t guestNewLimitPointer,
    uint64_t guestOldLimitPointer,
    const kernix::g2e::c3d7b::NativeChosenPIEGuestLayout& owner,
    const unsigned char* immutableOriginalLibcSource,
    size_t immutableOriginalLibcLength,
    bool pinnedTriadOriginalSHAAndAuthenticGuestTrap,
    bool allThreeOriginalGNUELFRELROKernelSealed,
    bool sourceLibcPTLoadNativeRXAuthenticated,
    std::string(*rightsAt)(uint64_t)) noexcept {
  Witness w{};
  if(!rightsAt || !pinnedTriadOriginalSHAAndAuthenticGuestTrap ||
     !allThreeOriginalGNUELFRELROKernelSealed ||
     !sourceLibcPTLoadNativeRXAuthenticated ||
     originalGuestSyscallNumber!=kGuestSyscall ||
     sourceGuestRIP!=kOriginalLibcGuestSyscallRIP ||
     sourceNextRIP!=sourceGuestRIP+2 ||
     guestPID!=0 || guestResource!=kGuestRLIMIT_STACK ||
     guestNewLimitPointer!=0 || guestOldLimitPointer==0 ||
     ::sysconf(_SC_PAGESIZE)!=4096 ||
     owner.WindowsHeld()!=4 || !owner.LaunchPlan() ||
     !SourceELFLibcGuestSyscallOpcode(immutableOriginalLibcSource,
                                    immutableOriginalLibcLength,sourceGuestRIP) ||
     rightsAt(sourceGuestRIP)!="r-xp" ||
     rightsAt(0x800003000ULL)!="r--p" ||
     rightsAt(0x801036000ULL)!="r--p" ||
     rightsAt(0x801037000ULL)!="r--p")
    return w;
  // Compare exact original guest RX bytes with original x86 ELF, not just
  // the file snapshot and the native VMA execute permission.
  uint8_t liveOpcode[2]{};
  std::memcpy(liveOpcode,
              reinterpret_cast<const void*>(
                static_cast<uintptr_t>(sourceGuestRIP)),sizeof(liveOpcode));
  if(liveOpcode[0]!=0x0f || liveOpcode[1]!=0x05)return w;
  w.exactOriginalLibcSourceRXSyscallByteAndGuestOpcode=true;
  w.exactOriginalGuestPID0RLIMIT_STACKGetOnly=true;
  const auto& stack=owner.LaunchPlan()->stack;
  const uint64_t begin=stack.guestBottom;
  const size_t total=stack.bytes.size();
  if(!begin || total!=64*1024 ||
     guestOldLimitPointer<begin ||
     guestOldLimitPointer-begin>total ||
     kGuestStackOutputBytes>total-(guestOldLimitPointer-begin) ||
     (guestOldLimitPointer%8)!=0 ||
     rightsAt(guestOldLimitPointer)!="rw-p" ||
     rightsAt(guestOldLimitPointer+kGuestStackOutputBytes-1)!="rw-p")
    return w;
  w.outputOriginalOwnerStack16BytesWritable=true;
  rlimit native{};
  errno=0;
  if(::getrlimit(RLIMIT_STACK,&native)!=0){
    w.guestReturn=-errno;
    return w;
  }
  w.realNativeKernelGetrlimitSucceeded=true;
  const uint64_t values[2]{
    static_cast<uint64_t>(native.rlim_cur),
    static_cast<uint64_t>(native.rlim_max)
  };
  std::memcpy(reinterpret_cast<void*>(static_cast<uintptr_t>(guestOldLimitPointer)),
              values,sizeof(values));
  uint64_t confirm[2]{};
  std::memcpy(confirm,reinterpret_cast<const void*>(static_cast<uintptr_t>(guestOldLimitPointer)),
              sizeof(confirm));
  if(confirm[0]!=values[0] || confirm[1]!=values[1])return w;
  w.originalGuestOutput=guestOldLimitPointer;
  w.nativeSoftLimit=confirm[0];
  w.nativeHardLimit=confirm[1];
  w.nativeLinuxRLIMITStackCopiedIntoOriginalGuestBuffer=true;
  w.originalLdsoSelfRelroNative8KAlreadySealed=true;
  w.guestReturn=0;
  return w;
}
}  // namespace kernix::g0::originalprlimit
