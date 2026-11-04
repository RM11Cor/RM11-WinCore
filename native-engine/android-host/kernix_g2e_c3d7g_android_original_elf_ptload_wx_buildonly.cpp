// SPDX-License-Identifier: MIT
// C3-D7G Android/Bionic AArch64 ABI build-only. No APK and no phone
// runtime attested by this adapter. Requires an explicit trusted
// app-private root FD with source-pinned immutable three x86 ELF files.
// Enforces original PT_LOAD W^X and isolated Linux stack guard, then
// releases every owned native memory region. Never enters FEX/ld-linux.
#include "kernix_g2e_c3d7g_native_pt_load_wx_apply_gate.h"
#include <array>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <string>
#if !defined(__ANDROID__) || !defined(__aarch64__)
#error This adapter compiles only for Android/Bionic ARM64.
#endif
extern "C" __attribute__((visibility("default")))
int kernix_g2ec3d7g_native_original_elf_wx_BUILDONLY(
    int verifiedAppPrivateRootFd,
    const uint8_t* exactly16BytesEntropy,
    uint32_t* outThreeVerifiedOriginalModules,
    uint32_t* outGuardedNativeGuestStack,
    uint32_t* outFEXOriginalGuestExecuted) noexcept {
  if(outThreeVerifiedOriginalModules)
    *outThreeVerifiedOriginalModules=0;
  if(outGuardedNativeGuestStack)
    *outGuardedNativeGuestStack=0;
  if(outFEXOriginalGuestExecuted)
    *outFEXOriginalGuestExecuted=0;
  if(verifiedAppPrivateRootFd<0 || !exactly16BytesEntropy ||
     !outThreeVerifiedOriginalModules ||
     !outGuardedNativeGuestStack ||
     !outFEXOriginalGuestExecuted)
    return -EINVAL;
  std::array<uint8_t,16> entropy{};
  std::memcpy(entropy.data(),exactly16BytesEntropy,entropy.size());
  kernix::g2e::GuestPreflight originals;
  std::string reason;
  if(!kernix::g2e::Validate(
       verifiedAppPrivateRootFd,originals,reason))
    return -ENOEXEC;
  kernix::g2e::c3d7b::NativeChosenPIEGuestLayout owned;
  kernix::g2e::c3d7b::Witness staged;
  if(!owned.Stage(verifiedAppPrivateRootFd,entropy,staged) ||
     staged.phase!=kernix::g2e::c3d7b::Phase::Complete ||
     !staged.pinnedOriginalELFSHA256Verified ||
     !staged.originalBytesCopiedReadOnly ||
     staged.originalLdsoExecuted || staged.originalELFCodeExecuted ||
     staged.originalFEXGuestMemoryAttached) {
    (void)owned.Release();
    return -ENOEXEC;
  }
  kernix::g2e::c3d7g::ApplyWitness rights;
  const bool applied=
    kernix::g2e::c3d7g::ApplyOwnedOriginalPTLoadPagePermissions(
       owned,originals,rights);
  const bool correct=applied && rights.originalModulesProtected==3 &&
    rights.nativeNoWritableExecutablePage &&
    rights.nativeNonPTLoadHolesDenied &&
    rights.nativeStackGuardDenied &&
    rights.nativeLinuxStackWritableNonExecutable &&
    !rights.originalLdsoExecuted && !rights.fexEntered;
  const bool released=owned.Release() && owned.WindowsHeld()==0;
  if(!correct || !released)return -ENOEXEC;
  *outThreeVerifiedOriginalModules=3;
  *outGuardedNativeGuestStack=1;
  return 0;
}
