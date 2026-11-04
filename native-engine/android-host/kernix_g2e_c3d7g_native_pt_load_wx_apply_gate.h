#pragma once
// SPDX-License-Identifier: MIT
// KERNIX G2-E/C3-D7G runtime page-permission APPLICATION after original
// SHA-locked x86 PT_LOAD page policy passed. Linux native 4K only.
// All windows are owned by C3D7B, bounded, with no MAP_FIXED and no
// anonymous executable guest instructions. This is NOT ld-linux execution.
// On failure, unmap every window fail-closed, including injected faults.
#include "kernix_g2e_c3d7g_original_elf_pt_load_page_policy.h"
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <sys/mman.h>
namespace kernix::g2e::c3d7g {
struct ApplyWitness {
  Reject planningReject=Reject::None;
  int failureErrno=0;
  size_t nativeMprotectOperations=0;
  size_t originalModulesProtected=0;
  size_t ownedWindowsReleasedOnFailure=0;
  size_t executablePages=0;
  size_t writablePages=0;
  size_t nonePages=0;
  bool originalPinnedSourceValidated=false;
  bool eachPTLoadFlagTranslatedToNative=false;
  bool nativeNoWritableExecutablePage=false;
  bool nativeNonPTLoadHolesDenied=false;
  bool nativeStackGuardDenied=false;
  bool nativeLinuxStackWritableNonExecutable=false;
  bool allOriginalEntryBytesStillReadOnlyOrExecutable=false;
  bool originalLdsoExecuted=false;
  bool fexEntered=false;
  bool androidDeviceTested=false;
};
// Note: 'OriginalEntryBytesStillReadOnlyOrExecutable' records the plan:
// the actual complete source byte reread and /proc/self/maps examination
// belong to the Linux regression, not to this header.
inline bool ApplyOwnedOriginalPTLoadPagePermissions(
    c3d7b::NativeChosenPIEGuestLayout& owned,
    const GuestPreflight& source,
    ApplyWitness& result,
    size_t injectFailureAfterMprotect=
      std::numeric_limits<size_t>::max()) noexcept {
  result={};
  PermissionPlan plan;
  if(!BuildVerifiedOriginalPermissionPlan(
        source,owned,plan,result.planningReject)) {
    result.failureErrno=EINVAL;
    return false; // NEVER mprotect if source/policy validation failed
  }
  result.originalPinnedSourceValidated=true;
  const auto failClosed=[&](int nativeErr) noexcept {
    result.failureErrno=nativeErr;
    const size_t held=owned.WindowsHeld();
    if(owned.Release() && owned.WindowsHeld()==0)
      result.ownedWindowsReleasedOnFailure=held;
    else result.failureErrno=EBUSY;
    return false;
  };
  const auto guardedMprotect=[&](void* at,size_t bytes,
                                 int prot) noexcept -> bool {
    if(result.nativeMprotectOperations>=injectFailureAfterMprotect) {
      errno=ECANCELED;
      return false;
    }
    if(::mprotect(at,bytes,prot)!=0)return false;
    ++result.nativeMprotectOperations;
    return true;
  };
  // The *entire* image was source-verified in C3D7B. Remove even read
  // access from all unmapped holes before selectively granting the PT_LOAD
  // page rights. On partial failure, munmap rather than restoring a possibly
  // incorrect ELF state. No user game data or host system mappings touched.
  for(size_t i=0;i<3;++i) {
    const auto* mod=owned.Module(i);
    if(!mod || mod->chosenImageStart!=
         plan.modules[i].nativeOwnedStart)
      return failClosed(ERANGE);
    if(!guardedMprotect(
        reinterpret_cast<void*>(
          static_cast<uintptr_t>(mod->chosenImageStart)),
        c3d7b::kImageCapacity,PROT_NONE))
      return failClosed(errno);
    const auto& flags=plan.modules[i].rights;
    size_t at=0;
    while(at<kModulePages) {
      if(flags[at]==0) {
        ++at;
        continue;
      }
      const uint8_t rights=flags[at];
      if((rights&(kWrite|kExecute))==(kWrite|kExecute))
        return failClosed(EACCES);
      size_t end=at+1;
      while(end<kModulePages && flags[end]==rights)++end;
      int native=PROT_NONE;
      if(rights&kRead)native|=PROT_READ;
      if(rights&kWrite)native|=PROT_WRITE;
      if(rights&kExecute)native|=PROT_EXEC;
      void* first=reinterpret_cast<void*>(
        static_cast<uintptr_t>(mod->chosenImageStart)+
          at*c3d7b::kPagesize);
      if(!guardedMprotect(first,(end-at)*4096,native))
        return failClosed(errno);
      at=end;
    }
    result.executablePages+=plan.modules[i].executablePages;
    result.writablePages+=plan.modules[i].writablePages;
    result.nonePages+=plan.modules[i].inaccessiblePages;
    ++result.originalModulesProtected;
  }
  const auto base=static_cast<uintptr_t>(plan.stackBottom);
  if(plan.guardBytes!=4096 ||
     plan.stackBytes!=c3d7b::kStackCapacity ||
     !guardedMprotect(reinterpret_cast<void*>(base),
                      plan.stackBytes,PROT_NONE))
    return failClosed(errno ? errno : EINVAL);
  if(!guardedMprotect(
        reinterpret_cast<void*>(base+4096),
        plan.stackBytes-4096,PROT_READ|PROT_WRITE))
    return failClosed(errno);
  result.eachPTLoadFlagTranslatedToNative=true;
  result.nativeNoWritableExecutablePage=true;
  result.nativeNonPTLoadHolesDenied=true;
  result.nativeStackGuardDenied=true;
  result.nativeLinuxStackWritableNonExecutable=true;
  result.allOriginalEntryBytesStillReadOnlyOrExecutable=true;
  return true;
}
} // namespace kernix::g2e::c3d7g
