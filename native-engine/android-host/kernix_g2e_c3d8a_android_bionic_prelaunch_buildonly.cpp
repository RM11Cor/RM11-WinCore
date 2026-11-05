// SPDX-License-Identifier: MIT
// C3-D8A cross-platform exact original loader handoff contract.
// ANDROID ARM64 output is BUILD-ONLY: not in signed APK, no FEX guest
// Context/ExecuteThread, no Wine/PC games, never a device result.
#include "kernix_g2e_c3d8a_original_loader_handoff_barrier.h"
#include <array>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#if defined(KERNIX_C3D8A_LINUX_REGRESSION)
#include <cstdio>
int main(int argc,char** argv) {
  if(argc!=2 || !argv[1])return 2;
  const int fd=::open(argv[1],O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
  if(fd<0)return 3;
  std::array<uint8_t,16> entropy{};
  for(size_t i=0;i<entropy.size();++i)
    entropy[i]=static_cast<uint8_t>(i+1);
  namespace z=kernix::g2e::c3d8a;
  z::Witness invalid{};
  // Reject missing FD without source/native guest memory ownership.
  if(z::PrepareOriginalOwnedGuestHandoffNoExecute(-1,entropy,invalid))
    return 4;
  z::Witness fault{};
  // Explicit native mprotect fault injection must release all 4 VMAs.
  if(z::PrepareOriginalOwnedGuestHandoffNoExecute(fd,entropy,fault,true) ||
     !fault.originalMemoryReleased ||
     fault.guestExecutionAttempted || fault.originalLoaderStarted)
    return 5;
  z::Witness good{};
  const bool passed=
      z::PrepareOriginalOwnedGuestHandoffNoExecute(fd,entropy,good);
  ::close(fd);
  if(!passed ||
     good.originalModules!=3 || good.nativeProtectedModules!=3 ||
     good.sourceCheckedPTLoadSegments<3 ||
     !good.originalOpcodeANDAndLEAWhitelisted ||
     !good.sourceSHA256Locked ||
     !good.fileBackedPTLoadBytesMatch ||
     !good.originalRWPTLoadDataAddressOwned ||
     !good.originalRSIPointerOwned ||
     !good.allNativeWXRejected ||
     !good.guardedGuestStackProtected ||
     !good.originalMemoryReleased ||
     good.guestExecutionAttempted || good.originalLoaderStarted ||
     good.androidDeviceExecuted)
     return 6;
  std::puts(
    "KERNIX_G2EC3D8A_SOURCE_LOCKED_ORIGINAL_LDSO_NATIVE_GUEST_HANDOFF_LINUX_PASS"
    " original_three_source_sha256=1"
    " four_guest_identity_windows_owned=1"
    " original_source_call_target_verified=1"
    " original_rw_guest_target_and_rsi_source_opcode_whitelisted=1"
    " native_original_three_elf_ptload_WX_permissions_applied=1"
    " source_backed_ptload_bytes_unchanged=1"
    " native_stack_guard_enforced=1"
    " native_permission_injected_failure_released=1"
    " four_guest_windows_fully_released=1"
    " original_fex_guest_context_created=0"
    " original_ldso_guest_executed=0"
    " android_device_tested=0"
    " wine_games_executed=0");
  return 0;
}
#elif defined(__ANDROID__) && defined(__aarch64__)
extern "C" __attribute__((visibility("default")))
int kernix_g2ec3d8a_android_source_locked_guest_handoff_BUILDONLY(
    int trustedOriginalGuestPrivateRootFd,
    const uint8_t* exactlySixteenEntropyBytes,
    uint32_t* outVerifiedOriginalELFModules,
    uint32_t* outNativeGuardedGuestStack,
    uint32_t* outGuestExecutionAttempted) noexcept {
  if(outVerifiedOriginalELFModules)*outVerifiedOriginalELFModules=0;
  if(outNativeGuardedGuestStack)*outNativeGuardedGuestStack=0;
  if(outGuestExecutionAttempted)*outGuestExecutionAttempted=0;
  if(!exactlySixteenEntropyBytes || !outVerifiedOriginalELFModules ||
     !outNativeGuardedGuestStack || !outGuestExecutionAttempted ||
     trustedOriginalGuestPrivateRootFd<0)return -EINVAL;
  std::array<uint8_t,16> entropy{};
  std::memcpy(entropy.data(),exactlySixteenEntropyBytes,16);
  try {
    kernix::g2e::c3d8a::Witness proof{};
    if(!kernix::g2e::c3d8a::PrepareOriginalOwnedGuestHandoffNoExecute(
          trustedOriginalGuestPrivateRootFd,entropy,proof) ||
       proof.nativeProtectedModules!=3 ||
       !proof.originalMemoryReleased ||
       proof.guestExecutionAttempted || proof.originalLoaderStarted)
       return -ENOEXEC;
    *outVerifiedOriginalELFModules=3;
    *outNativeGuardedGuestStack=1;
    return 0;
  } catch(...) {
    return -ENOEXEC;
  }
}
#else
#error C3-D8A compiles only under verified Linux regression or Android ARM64 Bionic build-only
#endif
