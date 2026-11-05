#pragma once
// SPDX-License-Identifier: MIT
// C3-D7K: verify the *actual source-pinned FEXCore CPUState* x86_64
// fs_cached/gs_cached ABI against the authenticated original libc TLS
// source model. This is a non-executing, non-attaching ABI audit.
// DO NOT attach the host-only C3D7J TLS buffer as a real guest FS base.
// No real glibc TCB/DTV, guest arch_prctl, FEX ExecuteThread, original
// ld-linux execution, Wine or Android device claim.
#include "kernix_g2e_c3d7j_original_x86_static_tls_variant2_order_gate.h"
#include <FEXCore/Core/CoreState.h>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <type_traits>

namespace kernix::g2e::c3d7k {
using FEXX86CPU=FEXCore::Core::CPUState;
static_assert(std::is_standard_layout_v<FEXX86CPU>);
static_assert(alignof(FEXX86CPU)==64);
static_assert(sizeof(((FEXX86CPU*)nullptr)->fs_cached)==sizeof(uint64_t));
static_assert(sizeof(((FEXX86CPU*)nullptr)->gs_cached)==sizeof(uint64_t));
static_assert(offsetof(FEXX86CPU,fs_cached)>offsetof(FEXX86CPU,fs_idx));
static_assert(offsetof(FEXX86CPU,gs_cached)>offsetof(FEXX86CPU,gs_idx));
static_assert(offsetof(FEXX86CPU,fs_cached)!=offsetof(FEXX86CPU,gs_cached));

enum class Reject : uint8_t {
  None, OriginalTLSUnverified, IFUNCAndRelocationsNotReady,
  UnexpectedInitialGuestFSOrGS, NoValidatedTCBDTV,
  HostOnlyTLSNeverGuestFSBase
};

struct Witness {
  size_t sourceFSBaseFieldOffset=offsetof(FEXX86CPU,fs_cached);
  size_t sourceGSBaseFieldOffset=offsetof(FEXX86CPU,gs_cached);
  size_t sourceFSSelectorFieldOffset=offsetof(FEXX86CPU,fs_idx);
  size_t sourceGSSelectorFieldOffset=offsetof(FEXX86CPU,gs_idx);
  size_t actualOriginalLibcTLSBytes=0;
  size_t originalIFUNCResolversNotExecuted=0;
  bool exactFEXCpuStateLayoutCompiled=false;
  bool originalLibcTLSVerified=false;
  bool fsCachedAndGsCachedDistinct64BitFields=false;
  bool independentIsolatedFEXStateFSAndGSReadback=false;
  bool isolatedStateFSAndGSReturnedToZero=false;
  bool originalGuestCPUStateNotAttached=true;
  bool originalGuestFSBaseAssigned=false;
  bool originalGuestTCBOrDTVCreated=false;
  bool originalIFUNCResolversExecuted=false;
  bool originalLdsoExecuted=false;
  bool androidDeviceRuntimeTested=false;
};
// This test-only state is created and destroyed in-process. It is
// never a live FEX thread frame; no guest FS/GS modification occurs.
// Verify that both original ABI fields retain separate 64-bit values
// without touching host thread register bases or a real interpreter.
inline bool InspectSourcePinnedFEXGuestFSandGS(
    const c3d7j::TLSModel& sourceTLS,
    const c3d7j::DependencyGate& sourceDeps,
    Witness& result,Reject& reject) noexcept {
  result={};
  reject=Reject::OriginalTLSUnverified;
  if(!sourceTLS.sourceInitializerMatchesOriginalELF ||
     !sourceTLS.zeroFillMatchesOriginalPTTLSMemsz ||
     !sourceTLS.x86VariantIIModelOnly ||
     !sourceTLS.nativeHostFSGSRegistersUnchanged ||
     sourceTLS.realGuestTCBInitialized ||
     sourceTLS.realGuestDTVInitialized ||
     sourceTLS.realGuestFSBaseAssigned ||
     sourceTLS.originalLdsoExecuted ||
     !sourceDeps.authenticateThreeOriginalELFs ||
     !sourceDeps.linuxX86VariantIIInitializerModeled ||
     !sourceDeps.requiresRealGuestTCBAndDTV ||
     !sourceDeps.requiresActualGuestFSBase ||
     sourceDeps.guestFSBaseAssigned)
    return false;
  reject=Reject::IFUNCAndRelocationsNotReady;
  if(!sourceDeps.requiresRealIFUNCResolverGuestExecution ||
     !sourceDeps.requiresActualRelocationWrites ||
     !sourceDeps.requiresGuestSymbolVersionResolution ||
     !sourceDeps.requiresPostRelocationRELRO ||
     sourceDeps.sourceOriginalIRelativeResolvers==0 ||
     sourceDeps.sourceOriginalRelrTargets==0 ||
     sourceDeps.realRelocationWritePerformed ||
     sourceDeps.guestRelroApplied ||
     sourceDeps.anyOriginalX86InstructionExecuted)
    return false;
  FEXX86CPU isolated{};
  reject=Reject::UnexpectedInitialGuestFSOrGS;
  if(isolated.fs_cached!=0 || isolated.gs_cached!=0 ||
     isolated.fs_idx!=0 || isolated.gs_idx!=0)return false;
  // Separate synthetic 64-bit values are intentionally not real
  // guest VAs; do not let them escape this local test-only frame.
  constexpr uint64_t fakeFS=0x1111222233334444ULL;
  constexpr uint64_t fakeGS=0x5555666677778888ULL;
  isolated.fs_cached=fakeFS;
  isolated.gs_cached=fakeGS;
  isolated.fs_idx=0;
  isolated.gs_idx=0;
  if(isolated.fs_cached!=fakeFS || isolated.gs_cached!=fakeGS ||
     isolated.fs_cached==isolated.gs_cached)return false;
  isolated.fs_cached=0;
  isolated.gs_cached=0;
  if(isolated.fs_cached!=0 || isolated.gs_cached!=0)return false;
  result.actualOriginalLibcTLSBytes=sourceTLS.totalTLSMemoryBytes;
  result.originalIFUNCResolversNotExecuted=
    sourceDeps.sourceOriginalIRelativeResolvers;
  result.exactFEXCpuStateLayoutCompiled=true;
  result.originalLibcTLSVerified=true;
  result.fsCachedAndGsCachedDistinct64BitFields=true;
  result.independentIsolatedFEXStateFSAndGSReadback=true;
  result.isolatedStateFSAndGSReturnedToZero=true;
  reject=Reject::None;
  return true;
}

// The original C3D7J Variant II scratch's "TP" is one-past-array,
// and cannot be used as FS base. A *real* glibc TCB/DTV, verified
// FEX thread frame & syscalls are required by a future runtime.
// This denied transition is intentionally impossible in C3-D7K.
inline bool AuthorizeLiveOriginalGuestFSBase(
    const c3d7j::TLSModel& model,const Witness&,
    uint64_t proposedGuestBase,Reject& reject) noexcept {
  reject=Reject::NoValidatedTCBDTV;
  if(proposedGuestBase==static_cast<uint64_t>(
       model.modelThreadPointerIndex))
    reject=Reject::HostOnlyTLSNeverGuestFSBase;
  return false;
}
} // namespace kernix::g2e::c3d7k
