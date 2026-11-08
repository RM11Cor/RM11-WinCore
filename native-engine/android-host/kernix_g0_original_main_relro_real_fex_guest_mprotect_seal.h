// SPDX-License-Identifier: MIT
#pragma once
// EXPERIMENTAL Linux AArch64 pinned-FEX diagnostic only.
// Called at one authentic GNU ld-linux x86 syscall(10) trap for source MAIN.
// No generic guest mprotect dispatcher. Never run on native 16KiB host pages.
// Never reuse for Android, Wine, arbitrary guest addresses or a game VMA.
//
// A genuine native 4KiB memory-page transition and a child write-denial trap
// are required before reporting guest Linux RAX=0. The source x86 loader's
// own late self-IRELATIVE remains a separate, subsequent proof.
#include "kernix_g0_original_main_relro_post_libc_source_audit.h"
#include <array>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <csignal>
#include <string>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

namespace kernix::g0::originalmainnative {
struct NativeWitness {
  int64_t guestReturn=-ENOSYS;
  bool authenticOriginalGNUTrapAndSourcePage=false;
  bool eightSourceMainRelocationQwordsExactNow=false;
  bool actualHostKernelMprotectSucceeded=false;
  bool nativeOwnedOriginalMainPageReadOnly=false;
  bool adjacentOriginalMainDataPageStillWritable=false;
  bool realChildAttemptedWriteWasDeniedBySIGSEGV=false;
  bool originalLdsoSelfIRELATIVEExecuted=false;
  bool AndroidBionicOrWineGameProven=false;
};

struct ExactSourceMainSlot {
  uint64_t relativePageOffset;
  uint64_t expectedGuestValue;
};

// Exact immutable source original main SHA256 9fb072db2732c7c6...
// and original pinned GNU ld-linux/libc. Revalidate all eight native guest
// qwords, including a zero-to-zero weak relocation, *before* any change.
// These expected values alone do NOT prove GNU ld-linux original writer RIPs.
// The original writer provenance remains a separate GDB source-trace gate.
constexpr std::array<ExactSourceMainSlot,8> kEightSourceMainSlots{{
  {0x0db8ULL,0x800001160ULL}, // original RELATIVE#0
  {0x0dc0ULL,0x800001120ULL}, // original RELATIVE#1
  {0x0fd0ULL,0x804087bc0ULL}, // puts JUMP_SLOT
  {0x0fd8ULL,0x80402a200ULL}, // __libc_start_main GLOB_DAT
  {0x0fe0ULL,0},              // weak _ITM_deregisterTMCloneTable
  {0x0fe8ULL,0},              // weak __gmon_start__
  {0x0ff0ULL,0},              // weak _ITM_registerTMCloneTable
  {0x0ff8ULL,0x8040472a0ULL} // weak __cxa_finalize resolved nonzero
}};

inline NativeWitness SealExactlyOneOwnedOriginalMainPage(
  const kernix::g2e::c1::TrapClassification& syscall,
  const kernix::g2e::c3d7b::NativeChosenPIEGuestLayout& owned,
  const kernix::g2e::c3d7g::PermissionPlan& policy,
  const kernix::g2e::c3d7g::ApplyWitness& nativePolicy,
  bool originalThreeELFSHAsPinnedAndIdentical,
  bool liveSourceGNUOpcodeAndGuestRIPAuthenticated,
  bool originalLibcRELROAlreadySuccessfullySealed,
  bool originalMainEightRecordsReadOnlySourceAuditPass,
  std::string(*rightsAt)(uint64_t)) noexcept {
  NativeWitness out{};
  constexpr uint64_t page=0x800003000ULL;
  constexpr uint64_t neighbor=page+0x1000ULL;
  if (!rightsAt || !originalThreeELFSHAsPinnedAndIdentical ||
      !liveSourceGNUOpcodeAndGuestRIPAuthenticated ||
      !originalLibcRELROAlreadySuccessfullySealed ||
      !originalMainEightRecordsReadOnlySourceAuditPass ||
      ::sysconf(_SC_PAGESIZE)!=4096 ||
      syscall.guestNumber!=kernix::g2e::c1::kMprotect ||
      syscall.args[0]!=page || syscall.args[1]!=4096 ||
      syscall.args[2]!=uint64_t(PROT_READ) ||
      !syscall.trapBoundaryAuthenticated ||
      !syscall.sourceRegisterMappingChecked ||
      syscall.hostSyscallDispatched || syscall.guestMemoryDereferenced ||
      !policy.sourceShaVerified ||
      !policy.nativeGuestVAIdentityOwned ||
      !nativePolicy.originalPinnedSourceValidated ||
      !nativePolicy.nativeNoWritableExecutablePage ||
      !nativePolicy.nativeNonPTLoadHolesDenied ||
      owned.WindowsHeld()!=4 || !owned.LaunchPlan() ||
      !owned.Module(0) || owned.Module(0)->chosenImageStart!=0x800000000ULL ||
      owned.Module(0)->loadBias!=0x800000000ULL ||
      !owned.GuestReadOnlyBytes(0,page,4096) ||
      !owned.GuestReadOnlyBytes(0,neighbor,8) ||
      rightsAt(page)!="rw-p" || rightsAt(neighbor)!="rw-p")
    return out;

  const auto original=kernix::g0::mainrelroaudit::ObserveNextOriginalMainRELRO(
    syscall,owned,policy,nativePolicy,page,true);
  if (!original.authenticatedGuestMprotect10 ||
      !original.sourceOwnedOriginalMainRWPage ||
      !original.originalSourceELF64PTGNURelroFullPage ||
      original.realDynamicRelocationClosureAttested ||
      !original.noGuestVMRightsModified ||
      original.start!=page || original.end!=neighbor)
    return out;

  out.authenticOriginalGNUTrapAndSourcePage=true;
  const auto* data=owned.GuestReadOnlyBytes(0,page,4096);
  if (!data)return out;
  for(const auto& slot:kEightSourceMainSlots) {
    if (slot.relativePageOffset>4096-8)return out;
    uint64_t live=0;
    std::memcpy(&live,data+slot.relativePageOffset,sizeof(live));
    if(live!=slot.expectedGuestValue)return out;
  }
  out.eightSourceMainRelocationQwordsExactNow=true;

  // The original main guest range is an exclusive native identity-mapped
  // FEX owner-held PT_LOAD page on supported 4KiB native Linux hosts.
  // Only the exact original guest syscall page may be protected.
  errno=0;
  if(::mprotect(reinterpret_cast<void*>(static_cast<uintptr_t>(page)),
                4096,PROT_READ)!=0){
    out.guestReturn=-errno;
    return out;
  }
  out.actualHostKernelMprotectSucceeded=true;
  if(rightsAt(page)!="r--p" || rightsAt(neighbor)!="rw-p")return out;
  out.nativeOwnedOriginalMainPageReadOnly=true;
  out.adjacentOriginalMainDataPageStillWritable=true;
  for(const auto& slot:kEightSourceMainSlots){
    uint64_t live=0;
    std::memcpy(&live,data+slot.relativePageOffset,sizeof(live));
    if(live!=slot.expectedGuestValue)return out;
  }

  // Source FEX may own process-wide SIGSEGV handlers. Reset disposition
  // IN THE FORK CHILD ONLY, leaving the parent FEX signal chain untouched.
  // The test child touches exclusively the known original source page.
  // A genuine native protection fault (SIGSEGV) is mandatory before success.
  pid_t child=::fork();
  if(child<0)return out;
  if(child==0){
    struct sigaction action{};
    action.sa_handler=SIG_DFL;
    ::sigemptyset(&action.sa_mask);
    action.sa_flags=0;
    if(::sigaction(SIGSEGV,&action,nullptr)!=0)_exit(90);
    struct rlimit limits{0,0};
    (void)::setrlimit(RLIMIT_CORE,&limits);
    ::alarm(3);
    volatile uint8_t* exact=
      reinterpret_cast<volatile uint8_t*>(static_cast<uintptr_t>(page));
    exact[0x0db8]=uint8_t(exact[0x0db8]^1U);
    _exit(91); // unexpected write success: never return guest RAX=0
  }
  int code=0;
  pid_t finished=-1;
  do {finished=::waitpid(child,&code,0);} while(finished<0 && errno==EINTR);
  if(finished!=child || !WIFSIGNALED(code) || WTERMSIG(code)!=SIGSEGV)
    return out;
  out.realChildAttemptedWriteWasDeniedBySIGSEGV=true;
  if(rightsAt(page)!="r--p" || rightsAt(neighbor)!="rw-p")return out;

  out.guestReturn=0;
  return out;
}
} // namespace kernix::g0::originalmainnative
