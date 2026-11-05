// SPDX-License-Identifier: MIT
// C3-D7K Android/Bionic AArch64 ABI BUILD-ONLY: actual original
// source-pinned FEX CPUState fs_cached / gs_cached 64-bit offsets,
// authenticated Linux x86 libc TLS and fail-closed TCB/DTV barrier.
// NEVER attach a FEX thread, change Android host FS/GS, invoke
// arch_prctl, run guest ld-linux or claim any user APK runtime.
#include "kernix_g2e_c3d7k_source_pinned_fex_fs_gs_cpu_state_abi_gate.h"
#include <array>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <string>
#if !defined(__ANDROID__) || !defined(__aarch64__)
#error C3-D7K Bionic ARM64 compilation gate only
#endif
extern "C" __attribute__((visibility("default")))
int kernix_c3d7k_pinned_fex_fsgs_original_libc_tls_BUILDONLY(
    int shaPinnedAppPrivateOriginalELFsFd,
    const uint8_t* sixteenBytesRandom,
    uint32_t* outFEXOriginalFSFieldOffset,
    uint32_t* outFEXOriginalGSFieldOffset,
    uint32_t* outOriginalLibcTLSSize,
    uint32_t* outRealGuestFSAssigned) noexcept {
  if(outFEXOriginalFSFieldOffset)*outFEXOriginalFSFieldOffset=0;
  if(outFEXOriginalGSFieldOffset)*outFEXOriginalGSFieldOffset=0;
  if(outOriginalLibcTLSSize)*outOriginalLibcTLSSize=0;
  if(outRealGuestFSAssigned)*outRealGuestFSAssigned=0;
  if(shaPinnedAppPrivateOriginalELFsFd<0 || !sixteenBytesRandom ||
     !outFEXOriginalFSFieldOffset || !outFEXOriginalGSFieldOffset ||
     !outOriginalLibcTLSSize || !outRealGuestFSAssigned)return -EINVAL;
  std::array<uint8_t,16> entropy{};
  std::memcpy(entropy.data(),sixteenBytesRandom,entropy.size());
  kernix::g2e::GuestPreflight original;
  std::string why;
  if(!kernix::g2e::Validate(
       shaPinnedAppPrivateOriginalELFsFd,original,why))
    return -ENOEXEC;
  kernix::g2e::c3d7b::NativeChosenPIEGuestLayout guest;
  kernix::g2e::c3d7b::Witness stage;
  if(!guest.Stage(shaPinnedAppPrivateOriginalELFsFd,entropy,stage) ||
     !stage.pinnedOriginalELFSHA256Verified ||
     stage.originalELFCodeExecuted || stage.originalLdsoExecuted)
    return -ENOEXEC;
  kernix::g2e::c3d7g::PermissionPlan rights;
  kernix::g2e::c3d7g::Reject rightsError;
  const bool pages=kernix::g2e::c3d7g::
     BuildVerifiedOriginalPermissionPlan(
       original,guest,rights,rightsError);
  kernix::g2e::c3d7h::Plan relro;
  kernix::g2e::c3d7h::Reject relroError;
  const bool relroOK=pages && kernix::g2e::c3d7h::
     BuildVerifiedOriginalThreeELFRelroPlan(
       original,guest,rights,relro,relroError);
  kernix::g2e::c3d7i::Plan dyn;
  kernix::g2e::c3d7i::Reject dynError;
  const bool dynOK=relroOK && kernix::g2e::c3d7i::
     InspectOriginalThreeModules(
       original,guest,rights,relro,dyn,dynError);
  kernix::g2e::c3d7j::TLSModel tls;
  kernix::g2e::c3d7j::DependencyGate dep;
  kernix::g2e::c3d7j::Reject tlsError;
  const bool tlsOK=dynOK && kernix::g2e::c3d7j::
     BuildOriginalStaticTLSModel(
       original,guest,dyn,relro,tls,dep,tlsError);
  kernix::g2e::c3d7k::Witness witness;
  kernix::g2e::c3d7k::Reject reject;
  const bool verified=tlsOK && kernix::g2e::c3d7k::
     InspectSourcePinnedFEXGuestFSandGS(
       tls,dep,witness,reject);
  const bool denied=!kernix::g2e::c3d7k::
     AuthorizeLiveOriginalGuestFSBase(
       tls,witness,tls.originalGuestTLSVirtualAddress,reject) &&
       reject==kernix::g2e::c3d7k::Reject::NoValidatedTCBDTV;
  const bool valid=verified && denied &&
      witness.originalLibcTLSVerified &&
      witness.fsCachedAndGsCachedDistinct64BitFields &&
      witness.independentIsolatedFEXStateFSAndGSReadback &&
      !witness.originalGuestFSBaseAssigned &&
      !witness.originalGuestTCBOrDTVCreated &&
      !witness.originalLdsoExecuted &&
      witness.sourceFSBaseFieldOffset<=UINT32_MAX &&
      witness.sourceGSBaseFieldOffset<=UINT32_MAX &&
      tls.totalTLSMemoryBytes<=UINT32_MAX;
  const size_t fsOffset=witness.sourceFSBaseFieldOffset;
  const size_t gsOffset=witness.sourceGSBaseFieldOffset;
  const size_t memory=tls.totalTLSMemoryBytes;
  const bool released=guest.Release()&&guest.WindowsHeld()==0;
  if(!valid || !released)return -ENOEXEC;
  *outFEXOriginalFSFieldOffset=static_cast<uint32_t>(fsOffset);
  *outFEXOriginalGSFieldOffset=static_cast<uint32_t>(gsOffset);
  *outOriginalLibcTLSSize=static_cast<uint32_t>(memory);
  return 0;
}
