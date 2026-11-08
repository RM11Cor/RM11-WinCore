// SPDX-License-Identifier: MIT
#pragma once
// EXPERIMENTAL exact original Linux x86 libc fstat(5) of stdout FD=1,
// after pinned original FEX guest libc prlimit64 and all three ELF RELRO.
//
// Linux ARM64 host struct stat is NOT binary compatible with Linux x86_64
// struct stat. Convert explicitly using the existing exact 144-byte x86
// guest ABI. Never pass guest FD or any guest output pointer to host fstat.
// Only host STDOUT_FILENO is used after source-original syscall validation.
// No Android, Bionic, Wine, Proton or game use is authorized.
#include "kernix_g0_original_libc_synthetic_x86_stat_abi.h"
#include "kernix_g2e_c3d7b_kernel_selected_pie_guest_vas.h"
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <elf.h>
#include <limits>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

namespace kernix::g0::originalfstat1 {
inline constexpr uint64_t kLibcSourceGuestBase=0x804000000ULL;
inline constexpr uint64_t kOriginalGuestRIP=0x804117249ULL;
inline constexpr uint64_t kOriginalSourceVA=kOriginalGuestRIP-kLibcSourceGuestBase;
inline constexpr uint64_t kGuestFstat=5ULL;
inline constexpr uint64_t kGuestStdout=1ULL;
inline constexpr uint64_t kSourceOutputBytes=sizeof(kernix::g0::statabi::LinuxX86_64Stat);
static_assert(kSourceOutputBytes==144);
struct Witness {
  int64_t guestReturn=-ENOSYS;
  bool originalLibcSourceRxAndGuestSyscallBytesMatch=false;
  bool originalGuestFstat1OnlyAuthenticated=false;
  bool originalGuestStack144BytesOwnedAndWritable=false;
  bool nativeKernelFstatOnOnlyTrustedFD1Succeeded=false;
  bool nativeARM64StatConvertedToExactX86_64Stat144=false;
  bool guestStat144WrittenAndReadBackMatched=false;
  bool guestProgramExitZeroProven=false;
  bool androidBionicWineProtonGamesProven=false;
  uint64_t guestDestination=0;
  uint32_t statMode=0;
  int64_t statSize=0;
};

inline bool ExactSourceLibcX86FstatSyscallBytes(
    const uint8_t* source,size_t length,uint64_t originalGuestRip) noexcept {
  if(!source || length!=2118168 || originalGuestRip!=kOriginalGuestRIP ||
     length<sizeof(Elf64_Ehdr))return false;
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
  size_t at=0,found=0;
  for(uint16_t i=0;i<eh.e_phnum;i++){
    Elf64_Phdr p{};
    std::memcpy(&p,source+eh.e_phoff+size_t(i)*sizeof(p),sizeof(p));
    if(p.p_type!=PT_LOAD || !(p.p_flags&PF_X) || (p.p_flags&PF_W))
      continue;
    if(p.p_offset>length || p.p_filesz>length-p.p_offset ||
       p.p_filesz>p.p_memsz || p.p_vaddr>UINT64_MAX-p.p_filesz)
      return false;
    if(kOriginalSourceVA<p.p_vaddr ||
       kOriginalSourceVA-p.p_vaddr>p.p_filesz ||
       p.p_filesz-(kOriginalSourceVA-p.p_vaddr)<2)continue;
    at=p.p_offset+kOriginalSourceVA-p.p_vaddr;
    ++found;
  }
  return found==1 && at<=length-2 && source[at]==0x0f && source[at+1]==0x05;
}

inline Witness HandleOnlyOriginalLibcStdoutFstat(
    uint64_t guestSyscallNumber,uint64_t sourceGuestRIP,
    uint64_t sourceNextGuestRIP,uint64_t guestFd,
    uint64_t guestStatOutputPointer,
    const kernix::g2e::c3d7b::NativeChosenPIEGuestLayout& owner,
    const uint8_t* immutableLibcSource,size_t immutableLibcSourceBytes,
    bool sourceOriginalTriadSHAAndAuthenticGuestTrap,
    bool originalGuestLibcPrlimit64AlreadySucceeded,
    bool originalLibcMainLdsoKernelRELROAlreadySealed,
    std::string(*rightsAt)(uint64_t)) noexcept {
  Witness w{};
  if(!rightsAt || !sourceOriginalTriadSHAAndAuthenticGuestTrap ||
     !originalGuestLibcPrlimit64AlreadySucceeded ||
     !originalLibcMainLdsoKernelRELROAlreadySealed ||
     ::sysconf(_SC_PAGESIZE)!=4096 ||
     guestSyscallNumber!=kGuestFstat ||
     sourceGuestRIP!=kOriginalGuestRIP ||
     sourceNextGuestRIP!=kOriginalGuestRIP+2 ||
     guestFd!=kGuestStdout ||
     guestStatOutputPointer==0 || guestStatOutputPointer%8!=0 ||
     !owner.LaunchPlan() || owner.WindowsHeld()!=4 ||
     !ExactSourceLibcX86FstatSyscallBytes(
       immutableLibcSource,immutableLibcSourceBytes,sourceGuestRIP) ||
     rightsAt(sourceGuestRIP)!="r-xp" ||
     rightsAt(0x800003000ULL)!="r--p" ||
     rightsAt(0x801036000ULL)!="r--p" ||
     rightsAt(0x801037000ULL)!="r--p")
    return w;
  const auto opcode=reinterpret_cast<const uint8_t*>(
    static_cast<uintptr_t>(sourceGuestRIP));
  if(opcode[0]!=0x0f || opcode[1]!=0x05)return w;
  w.originalLibcSourceRxAndGuestSyscallBytesMatch=true;
  w.originalGuestFstat1OnlyAuthenticated=true;

  const auto& stack=owner.LaunchPlan()->stack;
  const auto base=stack.guestBottom;
  const auto bytes=stack.bytes.size();
  if(base==0 || bytes!=64*1024 ||
     guestStatOutputPointer<base ||
     guestStatOutputPointer-base>bytes ||
     kSourceOutputBytes>bytes-(guestStatOutputPointer-base) ||
     rightsAt(guestStatOutputPointer)!="rw-p" ||
     rightsAt(guestStatOutputPointer+kSourceOutputBytes-1)!="rw-p")
    return w;
  w.originalGuestStack144BytesOwnedAndWritable=true;

  struct stat native{};
  errno=0;
  if(::fstat(STDOUT_FILENO,&native)!=0){
    w.guestReturn=-errno;
    return w;
  }
  w.nativeKernelFstatOnOnlyTrustedFD1Succeeded=true;
  using kernix::g0::statabi::LinuxX86_64Stat;
  LinuxX86_64Stat x86{};
  x86.device=static_cast<uint64_t>(native.st_dev);
  x86.inode=static_cast<uint64_t>(native.st_ino);
  x86.hardLinks=static_cast<uint64_t>(native.st_nlink);
  x86.mode=static_cast<uint32_t>(native.st_mode);
  x86.uid=static_cast<uint32_t>(native.st_uid);
  x86.gid=static_cast<uint32_t>(native.st_gid);
  x86.zeroPad0=0;
  x86.specialDevice=static_cast<uint64_t>(native.st_rdev);
  x86.size=static_cast<int64_t>(native.st_size);
  x86.blockSize=static_cast<int64_t>(native.st_blksize);
  x86.allocated512Blocks=static_cast<int64_t>(native.st_blocks);
  x86.accessSec=static_cast<int64_t>(native.st_atim.tv_sec);
  x86.accessNanosec=static_cast<uint64_t>(native.st_atim.tv_nsec);
  x86.modifySec=static_cast<int64_t>(native.st_mtim.tv_sec);
  x86.modifyNanosec=static_cast<uint64_t>(native.st_mtim.tv_nsec);
  x86.changeSec=static_cast<int64_t>(native.st_ctim.tv_sec);
  x86.changeNanosec=static_cast<uint64_t>(native.st_ctim.tv_nsec);
  w.nativeARM64StatConvertedToExactX86_64Stat144=true;
  const auto ptr=reinterpret_cast<void*>(
    static_cast<uintptr_t>(guestStatOutputPointer));
  std::memcpy(ptr,&x86,sizeof(x86));
  LinuxX86_64Stat verify{};
  std::memcpy(&verify,ptr,sizeof(verify));
  if(std::memcmp(&verify,&x86,sizeof(x86))!=0 ||
     verify.mode!=static_cast<uint32_t>(native.st_mode) ||
     verify.size!=static_cast<int64_t>(native.st_size))
    return w;
  w.guestStat144WrittenAndReadBackMatched=true;
  w.guestDestination=guestStatOutputPointer;
  w.statMode=verify.mode;
  w.statSize=verify.size;
  w.guestReturn=0;
  return w;
}
} // namespace kernix::g0::originalfstat1
