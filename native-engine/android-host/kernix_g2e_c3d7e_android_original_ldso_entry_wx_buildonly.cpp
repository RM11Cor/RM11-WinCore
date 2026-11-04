// SPDX-License-Identifier: MIT
// Build-only Android AArch64 C3-D7E adapter: verifies exact original
// x86 ld-linux and main file-backed entry *bytes* and an owned
// kernel-chosen temporary RX/RO page gate. NEVER jumps to guest code,
// provides no FEX context, and is NOT packaged in a signed APK.
#include "kernix_g2e_c3d7e_original_ldso_entry_rx_ownership.h"
#include <array>
#include <cerrno>
#include <cstdint>
#include <cstring>
#if !defined(__ANDROID__) || !defined(__aarch64__)
#error C3-D7E Bionic ARM64 build-only ABI gate
#endif
extern "C" __attribute__((visibility("default")))
int kernix_c3d7e_original_guest_main_ldso_entry_rx_BUILDONLY(
    int originalGuestPrivateRootFd,
    const uint8_t* entropyExactly16Bytes,
    uint32_t* outOriginalEntryBytesMatched,
    uint32_t* outGuestOriginalLdsoExecuted) noexcept {
  if(outOriginalEntryBytesMatched)*outOriginalEntryBytesMatched=0;
  if(outGuestOriginalLdsoExecuted)*outGuestOriginalLdsoExecuted=0;
  if(originalGuestPrivateRootFd<0 || !entropyExactly16Bytes ||
     !outOriginalEntryBytesMatched || !outGuestOriginalLdsoExecuted)
    return -EINVAL;
  std::array<uint8_t,16> entropy{};
  std::memcpy(entropy.data(),entropyExactly16Bytes,entropy.size());
  kernix::g2e::GuestPreflight original;
  std::string why;
  if(!kernix::g2e::Validate(originalGuestPrivateRootFd,original,why))
    return -ENOEXEC;
  kernix::g2e::c3d7b::NativeChosenPIEGuestLayout guest;
  kernix::g2e::c3d7b::Witness staged;
  if(!guest.Stage(originalGuestPrivateRootFd,entropy,staged) ||
     staged.phase!=kernix::g2e::c3d7b::Phase::Complete ||
     !staged.pinnedOriginalELFSHA256Verified ||
     staged.originalELFCodeExecuted || staged.originalLdsoExecuted ||
     staged.originalFEXGuestMemoryAttached)
    return -ENOEXEC;
  kernix::g2e::c3d7e::EntryProof main{};
  kernix::g2e::c3d7e::EntryProof ldso{};
  const bool proof=
    kernix::g2e::c3d7e::VerifyOriginalGuestEntryAndTemporaryHostRX(
      guest,original,0,main) &&
    kernix::g2e::c3d7e::VerifyOriginalGuestEntryAndTemporaryHostRX(
      guest,original,1,ldso) &&
    main.entryIsInsideOriginalFileBackedRXSegment &&
    ldso.entryIsInsideOriginalFileBackedRXSegment &&
    main.instructionBytesMatchOriginalSource &&
    ldso.instructionBytesMatchOriginalSource &&
    main.kernelNativeRXTemporarilyEstablished &&
    ldso.kernelNativeRXTemporarilyEstablished &&
    main.nativeRORestored && ldso.nativeRORestored &&
    !main.originalGuestInstructionsExecuted &&
    !ldso.originalGuestInstructionsExecuted;
  const bool allReleased=guest.Release() && guest.WindowsHeld()==0;
  if(!proof || !allReleased)return -ENOEXEC;
  *outOriginalEntryBytesMatched=32;
  return 0;
}
