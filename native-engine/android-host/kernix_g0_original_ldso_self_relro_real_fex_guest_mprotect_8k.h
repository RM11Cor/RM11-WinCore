// SPDX-License-Identifier: MIT
#pragma once
// KERNIX G0 source-SHA-pinned ORIGINAL GNU ld-linux self PT_GNU_RELRO.
// REAL native Linux ARM64 kernel mprotect for exactly TWO 4KiB pages.
// This helper is experiment-only, never a generic guest syscall dispatcher.
// It is not available on host kernels with 16KiB pages and does not imply
// Android, Wine, Proton, games or full 1237-relocation closure.
#include "kernix_g0_original_main_relro_post_libc_source_audit.h"
#include <cerrno>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <elf.h>
#include <string>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

namespace kernix::g0::originalldsoself {
constexpr uint64_t kBase=0x801000000ULL;
constexpr uint64_t kPage=0x801036000ULL;
constexpr uint64_t kLength=8192;
constexpr uint64_t kSlot=0x801036360ULL;
constexpr uint64_t kOriginalSyscallRIP=0x801025db9ULL;
struct Witness {
  int64_t guestReturn=-ENOSYS;
  bool originalLdsoSourceELF64PTGNURELROExactlyTwoPages=false;
  bool genuineGuestSourceSyscall10StageAuthenticated=false;
  bool sourceOwnedTwoNativePages=false;
  bool sameValueZeroSlotBeforeAndAfter=false;
  bool realNativeMprotectTwoPagesSucceeded=false;
  bool bothOriginalLdsoPagesReadOnly=false;
  bool precedingAndFollowingOutsidePagesUnchanged=false;
  bool twoRealChildWriteDenialsSIGSEGV=false;
  bool originalSourceResolverEntryReturnProven=false;
  bool originalMainAndOtherELFCompleteRelocationClosureProven=false;
  bool androidBionicWineProtonGamesProven=false;
};
inline bool OriginalSourceRELROExactlyTwoPages(
    const uint8_t* src,size_t bytes) noexcept {
  if(!src || bytes!=235408 || bytes<sizeof(Elf64_Ehdr))return false;
  Elf64_Ehdr e{};
  std::memcpy(&e,src,sizeof(e));
  if(std::memcmp(e.e_ident,ELFMAG,SELFMAG)!=0 ||
     e.e_ident[EI_CLASS]!=ELFCLASS64 ||
     e.e_ident[EI_DATA]!=ELFDATA2LSB ||
     e.e_type!=ET_DYN || e.e_machine!=EM_X86_64 ||
     e.e_phentsize!=sizeof(Elf64_Phdr) ||
     e.e_phnum==0 || e.e_phnum>64 ||
     e.e_phoff>bytes || size_t(e.e_phnum)> (bytes-e.e_phoff)/sizeof(Elf64_Phdr))
    return false;
  size_t relroCount=0;
  bool selfSlotInWritableNonExecutableLoad=false;
  for(unsigned i=0;i<e.e_phnum;i++){
    Elf64_Phdr p{};
    std::memcpy(&p,src+e.e_phoff+size_t(i)*sizeof(p),sizeof(p));
    if(p.p_type==PT_GNU_RELRO){
      if(p.p_memsz==0 || p.p_vaddr>UINT64_MAX-p.p_memsz)return false;
      const uint64_t first=p.p_vaddr&~uint64_t(4095);
      const uint64_t last=(p.p_vaddr+p.p_memsz)&~uint64_t(4095);
      if(first!=0x36000ULL || last!=0x38000ULL ||
         !(p.p_vaddr<=0x36360ULL && 0x36360ULL+8<=p.p_vaddr+p.p_memsz))
        return false;
      ++relroCount;
    }
    if(p.p_type==PT_LOAD){
      if(p.p_vaddr>UINT64_MAX-p.p_memsz ||
         p.p_offset>bytes || p.p_filesz>bytes-p.p_offset ||
         p.p_filesz>p.p_memsz)return false;
      if((p.p_flags&PF_W)!=0 && (p.p_flags&PF_X)==0 &&
         p.p_vaddr<=0x36360ULL && p.p_vaddr+p.p_memsz>=0x36368ULL)
        selfSlotInWritableNonExecutableLoad=true;
    }
  }
  return relroCount==1 && selfSlotInWritableNonExecutableLoad;
}

inline Witness SealOriginalGNUInterpreterTwo4KPages(
    const kernix::g2e::c1::TrapClassification& call,
    const kernix::g2e::c3d7b::NativeChosenPIEGuestLayout& owner,
    const kernix::g2e::c3d7g::PermissionPlan& policy,
    const kernix::g2e::c3d7g::ApplyWitness& applied,
    const uint8_t* exactOriginalELFSourceBytes,
    size_t exactOriginalELFBytes,
    bool sourceTriadOriginalSHAAndRuntimeStageAuthenticated,
    bool sourceGNUInterpreterOriginalX86SyscallOpcodeMatched,
    bool actualOriginalMainPageAlreadySealedInSameFEXProcess,
    bool precedingOriginalGNUZeroIRELATIVEStoreSourceProvenInSeparateHardwareTrace,
    std::string(*rightsAt)(uint64_t)) noexcept {
  Witness r{};
  if(!rightsAt || !sourceTriadOriginalSHAAndRuntimeStageAuthenticated ||
     !sourceGNUInterpreterOriginalX86SyscallOpcodeMatched ||
     !actualOriginalMainPageAlreadySealedInSameFEXProcess ||
     !precedingOriginalGNUZeroIRELATIVEStoreSourceProvenInSeparateHardwareTrace ||
     ::sysconf(_SC_PAGESIZE)!=4096 ||
     call.guestNumber!=kernix::g2e::c1::kMprotect ||
     call.args[0]!=kPage || call.args[1]!=kLength ||
     call.args[2]!=uint64_t(PROT_READ) ||
     !call.trapBoundaryAuthenticated || !call.sourceRegisterMappingChecked ||
     call.hostSyscallDispatched || call.guestMemoryDereferenced ||
     owner.WindowsHeld()!=4 || !owner.LaunchPlan() ||
     !owner.Module(1) || !policy.sourceShaVerified ||
     !policy.nativeGuestVAIdentityOwned ||
     !applied.originalPinnedSourceValidated ||
     !applied.nativeNoWritableExecutablePage ||
     !applied.nativeNonPTLoadHolesDenied ||
     owner.Module(1)->chosenImageStart!=kBase ||
     owner.Module(1)->loadBias!=kBase ||
     !OriginalSourceRELROExactlyTwoPages(exactOriginalELFSourceBytes,exactOriginalELFBytes) ||
     !owner.GuestReadOnlyBytes(1,kPage,kLength) ||
     !owner.GuestReadOnlyBytes(1,kSlot,8) ||
     rightsAt(kPage)!="rw-p" || rightsAt(kPage+4096)!="rw-p" ||
     rightsAt(0x800003000ULL)!="r--p")
    return r;
  r.genuineGuestSourceSyscall10StageAuthenticated=true;
  r.originalLdsoSourceELF64PTGNURELROExactlyTwoPages=true;
  r.sourceOwnedTwoNativePages=true;
  const auto before=rightsAt(kPage-4096);
  const auto after=rightsAt(kPage+kLength);
  if(before=="unmapped" || after=="unmapped")return r;
  uint64_t qword=UINT64_MAX;
  const auto* old=owner.GuestReadOnlyBytes(1,kSlot,8);
  if(!old)return r;
  std::memcpy(&qword,old,8);
  if(qword!=0)return r;
  r.sameValueZeroSlotBeforeAndAfter=true;
  errno=0;
  if(::mprotect(reinterpret_cast<void*>(static_cast<uintptr_t>(kPage)),
                kLength,PROT_READ)!=0){
    r.guestReturn=-errno;
    return r;
  }
  r.realNativeMprotectTwoPagesSucceeded=true;
  if(rightsAt(kPage)!="r--p" || rightsAt(kPage+4096)!="r--p")
    return r;
  r.bothOriginalLdsoPagesReadOnly=true;
  if(rightsAt(kPage-4096)!=before || rightsAt(kPage+kLength)!=after)
    return r;
  r.precedingAndFollowingOutsidePagesUnchanged=true;
  std::memcpy(&qword,old,8);
  if(qword!=0)return r;
  // A child probes the actual same live FEX-owned original GNU loader
  // two protected pages without risking the parent/guest context.
  const auto proveDenial=[](uint64_t addr) noexcept {
    pid_t child=::fork();
    if(child<0)return false;
    if(child==0){
      struct sigaction a{};
      a.sa_handler=SIG_DFL;
      ::sigemptyset(&a.sa_mask);
      a.sa_flags=0;
      if(::sigaction(SIGSEGV,&a,nullptr)!=0)_exit(90);
      struct rlimit lim{0,0};
      (void)::setrlimit(RLIMIT_CORE,&lim);
      ::alarm(3);
      volatile uint8_t* target=reinterpret_cast<volatile uint8_t*>(static_cast<uintptr_t>(addr));
      target[0]=uint8_t(target[0]^1U);
      _exit(91);
    }
    int code=0;pid_t finish=-1;
    do {finish=::waitpid(child,&code,0);} while(finish<0 && errno==EINTR);
    return finish==child && WIFSIGNALED(code) && WTERMSIG(code)==SIGSEGV;
  };
  if(!proveDenial(kPage+0x360) || !proveDenial(kPage+4096+0x20))return r;
  r.twoRealChildWriteDenialsSIGSEGV=true;
  if(rightsAt(kPage)!="r--p" || rightsAt(kPage+4096)!="r--p" ||
     rightsAt(kPage-4096)!=before || rightsAt(kPage+kLength)!=after)
    return r;
  r.guestReturn=0;
  return r;
}
}  // namespace kernix::g0::originalldsoself
