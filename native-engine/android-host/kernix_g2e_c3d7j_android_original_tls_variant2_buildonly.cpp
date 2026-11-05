// SPDX-License-Identifier: MIT
// C3-D7J Android/Bionic ARM64 SOURCE-ONLY compilation check.
// Does NOT attach to FEXCore or set host/guest FS/GS, TCB/DTV, TLS,
// RELRO, relocation writes, original ld-linux RIP or launch any EXE.
// Original Linux 3-module app-private immutable root fd required.
#include "kernix_g2e_c3d7j_original_x86_static_tls_variant2_order_gate.h"
#include <array>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <string>
#if !defined(__ANDROID__) || !defined(__aarch64__)
#error C3-D7J standalone Android Bionic ARM64 source compile only
#endif
extern "C" __attribute__((visibility("default")))
int kernix_c3d7j_authentic_x86_tls_and_irelative_SOURCE_ONLY(
    int originalAppPrivateRootFd,
    const uint8_t* exactly16BytesOfEntropy,
    uint32_t* outLibcOriginalTLSInitializerSize,
    uint32_t* outLibcOriginalTLSMemSize,
    uint32_t* outOriginalIFUNCResolversUnexecuted,
    uint32_t* outActualGuestFSBaseAssigned) noexcept {
  if(outLibcOriginalTLSInitializerSize)
    *outLibcOriginalTLSInitializerSize=0;
  if(outLibcOriginalTLSMemSize)
    *outLibcOriginalTLSMemSize=0;
  if(outOriginalIFUNCResolversUnexecuted)
    *outOriginalIFUNCResolversUnexecuted=0;
  if(outActualGuestFSBaseAssigned)
    *outActualGuestFSBaseAssigned=0;
  if(originalAppPrivateRootFd<0 ||
     !exactly16BytesOfEntropy ||
     !outLibcOriginalTLSInitializerSize ||
     !outLibcOriginalTLSMemSize ||
     !outOriginalIFUNCResolversUnexecuted ||
     !outActualGuestFSBaseAssigned)return -EINVAL;
  std::array<uint8_t,16> entropy{};
  std::memcpy(entropy.data(),exactly16BytesOfEntropy,entropy.size());
  kernix::g2e::GuestPreflight originals;
  std::string reason;
  if(!kernix::g2e::Validate(
       originalAppPrivateRootFd,originals,reason))
    return -ENOEXEC;
  kernix::g2e::c3d7b::NativeChosenPIEGuestLayout owned;
  kernix::g2e::c3d7b::Witness staged;
  if(!owned.Stage(originalAppPrivateRootFd,entropy,staged) ||
     !staged.pinnedOriginalELFSHA256Verified ||
     staged.originalLdsoExecuted || staged.originalELFCodeExecuted)
    return -ENOEXEC;
  kernix::g2e::c3d7g::PermissionPlan permissions;
  kernix::g2e::c3d7g::Reject pgReject;
  const bool pg=kernix::g2e::c3d7g::BuildVerifiedOriginalPermissionPlan(
      originals,owned,permissions,pgReject);
  kernix::g2e::c3d7h::Plan relro;
  kernix::g2e::c3d7h::Reject relroReject;
  const bool rp=pg &&
    kernix::g2e::c3d7h::BuildVerifiedOriginalThreeELFRelroPlan(
      originals,owned,permissions,relro,relroReject);
  kernix::g2e::c3d7i::Plan dynamic;
  kernix::g2e::c3d7i::Reject dynReject;
  const bool dp=rp &&
    kernix::g2e::c3d7i::InspectOriginalThreeModules(
      originals,owned,permissions,relro,dynamic,dynReject);
  kernix::g2e::c3d7j::TLSModel tls;
  kernix::g2e::c3d7j::DependencyGate deps;
  kernix::g2e::c3d7j::Reject tlsReject;
  const bool tp=dp &&
    kernix::g2e::c3d7j::BuildOriginalStaticTLSModel(
      originals,owned,dynamic,relro,tls,deps,tlsReject);
  kernix::g2e::c3d7j::Reject premature;
  const bool denied=!kernix::g2e::c3d7j::
    AuthorizeOriginalLdsoRelocationOrRelroFromMetadataOnly(
      deps,premature) &&
    premature==kernix::g2e::c3d7j::Reject::GuestRuntimeNotStarted;
  const bool ready=tp && denied &&
    tls.sourceInitializerMatchesOriginalELF &&
    tls.zeroFillMatchesOriginalPTTLSMemsz &&
    tls.negativeTPRelativeStart<0 &&
    deps.authenticateThreeOriginalELFs &&
    deps.sourceOriginalIRelativeResolvers>0 &&
    !deps.realRelocationWritePerformed &&
    !deps.guestFSBaseAssigned &&
    !deps.guestRelroApplied;
  const uint64_t init=tls.originalInitializerBytes;
  const uint64_t memory=tls.totalTLSMemoryBytes;
  const uint64_t ifunc=deps.sourceOriginalIRelativeResolvers;
  const bool released=owned.Release()&&owned.WindowsHeld()==0;
  if(!ready || !released || init>UINT32_MAX ||
     memory>UINT32_MAX || ifunc>UINT32_MAX)
    return -ENOEXEC;
  *outLibcOriginalTLSInitializerSize=static_cast<uint32_t>(init);
  *outLibcOriginalTLSMemSize=static_cast<uint32_t>(memory);
  *outOriginalIFUNCResolversUnexecuted=static_cast<uint32_t>(ifunc);
  return 0;
}
