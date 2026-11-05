// SPDX-License-Identifier: MIT
// C3-D7H Android/Bionic ARM64 source compilation only; no new APK,
// dynamic linker, FEX guest RIP or real PT_GNU_RELRO mprotect.
// Only accepts 3 original SHA-pinned app-private Linux x86_64 ELFs.
#include "kernix_g2e_c3d7h_original_elf_relro_after_relocation_policy.h"
#include <array>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <string>
#if !defined(__ANDROID__) || !defined(__aarch64__)
#error C3-D7H source-only Android ARM64 Bionic gate
#endif
extern "C" __attribute__((visibility("default")))
int kernix_c3d7h_original_relro_AFTER_RELOCATION_PLAN_BUILDONLY(
  int originalAppPrivateRootFd,
  const uint8_t* exactly16BytesRandom,
  uint32_t* outValidatedAuthenticRelroPages,
  uint32_t* outOriginalRelocationsApplied) noexcept {
  if(outValidatedAuthenticRelroPages)
    *outValidatedAuthenticRelroPages=0;
  if(outOriginalRelocationsApplied)
    *outOriginalRelocationsApplied=0;
  if(originalAppPrivateRootFd<0 || !exactly16BytesRandom ||
     !outValidatedAuthenticRelroPages ||
     !outOriginalRelocationsApplied)
    return -EINVAL;
  std::array<uint8_t,16> random{};
  std::memcpy(random.data(),exactly16BytesRandom,random.size());
  kernix::g2e::GuestPreflight source;
  std::string why;
  if(!kernix::g2e::Validate(
        originalAppPrivateRootFd,source,why))
    return -ENOEXEC;
  kernix::g2e::c3d7b::NativeChosenPIEGuestLayout guest;
  kernix::g2e::c3d7b::Witness original;
  if(!guest.Stage(originalAppPrivateRootFd,random,original) ||
     !original.pinnedOriginalELFSHA256Verified ||
     original.originalLdsoExecuted ||
     original.originalELFCodeExecuted)
    return -ENOEXEC;
  kernix::g2e::c3d7g::PermissionPlan permission;
  kernix::g2e::c3d7g::Reject pageReject;
  const bool pageValid=
    kernix::g2e::c3d7g::BuildVerifiedOriginalPermissionPlan(
      source,guest,permission,pageReject);
  kernix::g2e::c3d7h::Plan relro;
  kernix::g2e::c3d7h::Reject policyReject;
  const bool planned=pageValid &&
    kernix::g2e::c3d7h::BuildVerifiedOriginalThreeELFRelroPlan(
      source,guest,permission,relro,policyReject);
  kernix::g2e::c3d7h::Reject earlySeal;
  const bool prematurelySealed=planned &&
    kernix::g2e::c3d7h::SealOriginalRelroBeforeVerifiedRealRelocations(
      relro,earlySeal);
  const size_t pages=relro.totalFullPages;
  const bool valid=planned && pages>0 &&
    relro.totalInitiallyWritablePages>0 &&
    relro.exactOriginalSHA256Sources &&
    relro.glibcBothEndpointsRoundedDown &&
    relro.noNativeMprotectApplied &&
    relro.noGuestELFRelocationsApplied &&
    !prematurelySealed &&
    earlySeal==kernix::g2e::c3d7h::Reject::NoRelocationProof;
  const bool released=guest.Release() &&
    guest.WindowsHeld()==0;
  if(!valid || !released || pages>UINT32_MAX)
    return -ENOEXEC;
  *outValidatedAuthenticRelroPages=
    static_cast<uint32_t>(pages);
  return 0;
}
