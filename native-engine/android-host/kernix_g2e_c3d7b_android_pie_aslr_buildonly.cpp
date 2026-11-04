// SPDX-License-Identifier: MIT
// C3-D7B Android AArch64 Bionic compilation gate, NOT distributed in APK.
// May validate host-selected original x86 ET_DYN main/ldso/libc VA/auxv
// data staging if a trusted app-private root FD is explicitly supplied;
// no FEX, guest RIP, executable memory, syscalls or game runtime.
#include "kernix_g2e_c3d7b_kernel_selected_pie_guest_vas.h"
#include <array>
#include <cerrno>
#include <cstdint>
#include <cstring>
#if !defined(__ANDROID__) || !defined(__aarch64__)
#error C3-D7B native Bionic ARM64 only
#endif
extern "C" __attribute__((visibility("default")))
int kernix_g2ec3d7b_android_pie_rebase_BUILDONLY(
    int pinnedPrivateGuestRootFd,
    const uint8_t* exactlySixteenRandomBytes,
    uint32_t* outOriginalPIEModulesVerified,
    uint32_t* outRebasedInitialStackValidated,
    uint32_t* outActualFEXGuestExecuted) noexcept {
  if(outOriginalPIEModulesVerified)*outOriginalPIEModulesVerified=0;
  if(outRebasedInitialStackValidated)*outRebasedInitialStackValidated=0;
  if(outActualFEXGuestExecuted)*outActualFEXGuestExecuted=0;
  if(pinnedPrivateGuestRootFd<0 || !exactlySixteenRandomBytes ||
     !outOriginalPIEModulesVerified ||
     !outRebasedInitialStackValidated ||
     !outActualFEXGuestExecuted)
    return -EINVAL;
  std::array<uint8_t,16> seed{};
  std::memcpy(seed.data(),exactlySixteenRandomBytes,seed.size());
  kernix::g2e::c3d7b::NativeChosenPIEGuestLayout guest;
  kernix::g2e::c3d7b::Witness w;
  const bool staged=guest.Stage(pinnedPrivateGuestRootFd,seed,w);
  const bool qualified=staged &&
      w.phase==kernix::g2e::c3d7b::Phase::Complete &&
      w.imagesVerified==3 && w.windowsReserved==4 &&
      w.pinnedOriginalELFSHA256Verified &&
      w.actualNativeKernel4K &&
      w.guestAddressEqualsOwnedHostPage &&
      w.linuxAuxvRebased &&
      w.originalBytesCopiedReadOnly &&
      !w.originalELFCodeExecuted &&
      !w.originalLdsoExecuted &&
      !w.originalFEXGuestMemoryAttached &&
      !w.nativeExecutablePageGranted &&
      guest.WindowsHeld()==4;
  const bool released=guest.Release() && guest.WindowsHeld()==0;
  if(!qualified || !released)return -ENOEXEC;
  *outOriginalPIEModulesVerified=3;
  *outRebasedInitialStackValidated=1;
  return 0;
}
