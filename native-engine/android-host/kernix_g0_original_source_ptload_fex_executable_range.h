#pragma once
// SPDX-License-Identifier: MIT
// G0 original SHA256 x86-64 ELF PT_LOAD executable-range provider for
// the EMBEDDED FEXCore QueryGuestExecutableRange callback.
//
// Prior to this gate FEX exposed only 16-128 bytes of original ld-linux.
// This contract exposes each individually source-pinned, owner-held,
// native-r-xp PT_LOAD page of the main / interpreter / libc instead.
// It must NEVER expose guest RW data, holes, host JIT, Android code,
// unmapped addresses or even a read-only source data snapshot.
//
// No guest instruction is executed by this header. A separate actual
// original-FEX continuation test is required. 4K-native-only while
// 16K host/4K guest subpage execution is unsupported.
#include "kernix_g2e_c3d7g_native_pt_load_wx_apply_gate.h"
#include <cstddef>
#include <cstdint>
#include <unistd.h>

namespace kernix::g0::source_exec {
struct Range {
  uint64_t pageStart=0;
  size_t pageBytes=0;
  size_t moduleIndex=3;
  bool sourceVerifiedOriginalPTLoadRX=false;
  bool nativeGuestAddressIsOwned=false;
  bool originalGNUInterpreterStartupCompleted=false;
  bool originalRelocationsExecuted=false;
};

inline bool ResolveOriginalSourceExecutableRange(
    const kernix::g2e::c3d7b::NativeChosenPIEGuestLayout& owned,
    const kernix::g2e::c3d7g::PermissionPlan& plan,
    const kernix::g2e::c3d7g::ApplyWitness& applied,
    uint64_t originalGuestRIP,Range& out) noexcept {
  namespace b=kernix::g2e::c3d7b;
  namespace g=kernix::g2e::c3d7g;
  out={};
  if(::sysconf(_SC_PAGESIZE)!=4096 ||
     !plan.sourceShaVerified ||
     !plan.nativeGuestVAIdentityOwned ||
     !plan.allPTLoadPagesPlanned ||
     !plan.deniedWritableExecutablePages ||
     !applied.originalPinnedSourceValidated ||
     !applied.eachPTLoadFlagTranslatedToNative ||
     !applied.nativeNoWritableExecutablePage ||
     !applied.nativeNonPTLoadHolesDenied ||
     !applied.nativeStackGuardDenied ||
     applied.originalLdsoExecuted || applied.androidDeviceTested ||
     !owned.LaunchPlan() || owned.WindowsHeld()!=4 ||
     originalGuestRIP<65536)return false;
  for(size_t i=0;i<3;++i){
    const auto* meta=owned.Module(i);
    if(!meta ||
       plan.modules[i].nativeOwnedStart!=meta->chosenImageStart ||
       plan.modules[i].loadSegments!=meta->loadSegments ||
       plan.modules[i].executablePages==0) return false;
    const uint64_t base=meta->chosenImageStart;
    if(originalGuestRIP<base ||
       originalGuestRIP-base>=b::kImageCapacity)continue;
    const uint64_t delta=originalGuestRIP-base;
    const size_t page=static_cast<size_t>(delta/4096);
    if(page>=g::kModulePages ||
       plan.modules[i].rights[page]!=(g::kRead|g::kExecute))return false;
    const uint64_t first=base+uint64_t(page)*4096;
    if(first>UINT64_MAX-4096 ||
       !owned.GuestReadOnlyBytes(i,first,4096))return false;
    out.pageStart=first;
    out.pageBytes=4096;
    out.moduleIndex=i;
    out.sourceVerifiedOriginalPTLoadRX=true;
    out.nativeGuestAddressIsOwned=true;
    // Only exact bytes from the attested module's real original
    // executable PT_LOAD are advertised to FEX. The *kernel*
    // permissions must already have been applied and independently
    // checked by native functional tests.
    return true;
  }
  return false;
}
} // namespace kernix::g0::source_exec
