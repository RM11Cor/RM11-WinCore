#pragma once
// SPDX-License-Identifier: MIT
// Linux x86_64 guest brk(12) mapped into the existing SHA-pinned
// original main ELF's OS-chosen 8 MiB native-owned PT_LOAD reservation.
// NEVER calls ::brk/sbrk or forwards a guest pointer to host memory.
//
// Main original PT_LOAD pages are already protected per source PHDR.
// New heap RW pages may only replace original PROT_NONE *holes after*
// the last original PT_LOAD page and before the final 4K reservation
// guard; no guest RWX and never an executable PT_LOAD page.
// Native 16K pages fail closed until a real guest subpage model exists.
#include "kernix_g2e_c3d7g_native_pt_load_wx_apply_gate.h"
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <sys/mman.h>
#include <unistd.h>

namespace kernix::g0::guestbrk {
struct Result {
  uint64_t guestReturn=0;
  bool authenticatedGuestBrk=false;
  bool originalMainOwnerRangeUsed=false;
  bool nativeGuestHeapPermissionsChanged=false;
  bool queriedOnly=false;
  bool growthDeniedWithoutNativeMemoryChange=false;
  bool nativeHostBrkOrSbrkCalled=false;
  bool originalPTLoadRightsModified=false;
};
class OriginalGuestMainProgramBreak final {
  uint64_t minimum_=0,current_=0,limit_=0,mainStart_=0;
  const kernix::g2e::c3d7b::NativeChosenPIEGuestLayout* owner_=nullptr;
  bool ready_=false;
  static constexpr uint64_t kPage=4096;
  static constexpr uint64_t kMaxGrow=1024*1024;
  static uint64_t Round(uint64_t x) noexcept {
    return (x+kPage-1)&~uint64_t(kPage-1);
  }
 public:
  bool Install(const kernix::g2e::c3d7b::NativeChosenPIEGuestLayout& owned,
               const kernix::g2e::c3d7g::PermissionPlan& p,
               const kernix::g2e::c3d7g::ApplyWitness& w) noexcept {
    namespace b=kernix::g2e::c3d7b;
    namespace g=kernix::g2e::c3d7g;
    minimum_=current_=limit_=mainStart_=0;owner_=nullptr;ready_=false;
    const auto* m=owned.Module(0);
    if(::sysconf(_SC_PAGESIZE)!=4096 || !m ||
       owned.WindowsHeld()!=4 || !owned.LaunchPlan() ||
       !p.sourceShaVerified || !p.nativeGuestVAIdentityOwned ||
       !p.allPTLoadPagesPlanned || !p.deniedWritableExecutablePages ||
       !w.originalPinnedSourceValidated ||
       !w.eachPTLoadFlagTranslatedToNative ||
       !w.nativeNoWritableExecutablePage ||
       !w.nativeNonPTLoadHolesDenied ||
       !w.nativeStackGuardDenied ||
       w.originalLdsoExecuted || w.androidDeviceTested ||
       p.modules[0].nativeOwnedStart!=m->chosenImageStart ||
       m->loadBias>UINT64_MAX-m->highestAlignedELFVA)
      return false;
    const uint64_t base=m->loadBias+m->highestAlignedELFVA;
    if(base<m->chosenImageStart ||
       base-m->chosenImageStart>b::kImageCapacity-kPage ||
       (base&(kPage-1))!=0 ||
       base>UINT64_MAX-kMaxGrow)return false;
    const uint64_t reserveLimit=m->chosenImageStart+
                                b::kImageCapacity-kPage;
    const uint64_t limit=base+kMaxGrow<reserveLimit?
                             base+kMaxGrow:reserveLimit;
    if(limit<=base || limit-base<kPage ||
       ((limit-base)&(kPage-1))!=0)return false;
    const size_t first=static_cast<size_t>(
       (base-m->chosenImageStart)/kPage);
    const size_t last=static_cast<size_t>(
       (limit-m->chosenImageStart)/kPage);
    if(first>=g::kModulePages || last>=g::kModulePages ||
       first>=last)return false;
    for(size_t pg=first;pg<=last;++pg)
      if(p.modules[0].rights[pg]!=0)return false;
    if(!kernix::g2e::c1::GuestRange(base,limit-base))return false;
    // Main original guest ELF end is the Linux guest's initial brk.
    // Do not mprotect anything on brk(0); holes remain PROT_NONE.
    minimum_=current_=base;limit_=limit;
    mainStart_=m->chosenImageStart;owner_=&owned;
    ready_=true;return true;
  }
  uint64_t Minimum() const noexcept {return minimum_;}
  uint64_t Current() const noexcept {return current_;}
  uint64_t Limit() const noexcept {return limit_;}
  bool Ready() const noexcept {return ready_;}
  Result Dispatch(const kernix::g2e::c1::TrapClassification& t) noexcept {
    namespace c1=kernix::g2e::c1;
    Result v{};
    if(!ready_ || !owner_ || owner_->WindowsHeld()!=4 ||
       !owner_->Module(0) ||
       owner_->Module(0)->chosenImageStart!=mainStart_ ||
       !t.trapBoundaryAuthenticated ||
       !t.sourceRegisterMappingChecked || t.hostSyscallDispatched ||
       t.guestMemoryDereferenced || t.guestNumber!=c1::kBrk ||
       t.category!=c1::CallCategory::NeedsGuestKernel)
       return v;
    v.authenticatedGuestBrk=true;
    v.originalMainOwnerRangeUsed=true;
    const uint64_t requested=t.args[0];
    v.guestReturn=current_;
    if(requested==0 || requested==current_){
      v.queriedOnly=true;return v;
    }
    if(requested<minimum_ || requested>limit_ ||
       requested>UINT64_MAX-kPage){
      v.growthDeniedWithoutNativeMemoryChange=true;return v;
    }
    const uint64_t before=Round(current_);
    const uint64_t after=Round(requested);
    if(after>before){
      if(::mprotect(reinterpret_cast<void*>(
            static_cast<uintptr_t>(before)),
           static_cast<size_t>(after-before),
           PROT_READ|PROT_WRITE)!=0){
        v.growthDeniedWithoutNativeMemoryChange=true;return v;
      }
      v.nativeGuestHeapPermissionsChanged=true;
    }else if(after<before){
      // Discard released pages while they are still guest-owned RW,
      // THEN remove native access. Never change the reported program
      // break if any kernel operation fails.
      if(::madvise(reinterpret_cast<void*>(
            static_cast<uintptr_t>(after)),
           static_cast<size_t>(before-after),MADV_DONTNEED)!=0 ||
         ::mprotect(reinterpret_cast<void*>(
            static_cast<uintptr_t>(after)),
           static_cast<size_t>(before-after),PROT_NONE)!=0){
        v.growthDeniedWithoutNativeMemoryChange=true;return v;
      }
      v.nativeGuestHeapPermissionsChanged=true;
    }
    current_=requested;v.guestReturn=requested;return v;
  }
};
} // namespace kernix::g0::guestbrk
