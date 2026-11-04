// SPDX-License-Identifier: MIT
// G2-E/C3-D4 Android AArch64 Bionic *BUILD ONLY*.
// This ABI is not part of any signed Android APK. It has not run on device.
// Requires original SHA-locked main/ld-linux/libc in a caller-owned root FD.
// Native 4KiB only. No FEX, no PT_INTERP entry, no host executable pages.
#include "kernix_g2e_c3d4_native_4k_original_elf_readonly_lease.h"
#include <array>
#include <cerrno>
#include <cstdint>
#include <cstring>
#if !defined(__ANDROID__) || !defined(__aarch64__)
#error G2-E/C3-D4 requires real Android/Bionic ARM64 NDK ABI
#endif

extern "C" __attribute__((visibility("default")))
int kernix_g2ec3d4_android_bionic_original_elf_native_4k_RO_BUILDONLY(
    int appPrivateOriginalGuestRootFd,
    const uint8_t* callerEntropy16,
    uint64_t* outRuntimeNativeKernelPageBytes,
    uint32_t* outVerifiedReadOnlyGuest4KPages,
    uint32_t* outFexGuestExecuted) noexcept {
    if(outRuntimeNativeKernelPageBytes)
        *outRuntimeNativeKernelPageBytes=0;
    if(outVerifiedReadOnlyGuest4KPages)
        *outVerifiedReadOnlyGuest4KPages=0;
    if(outFexGuestExecuted)
        *outFexGuestExecuted=0;
    if(appPrivateOriginalGuestRootFd<0 || !callerEntropy16 ||
       !outRuntimeNativeKernelPageBytes ||
       !outVerifiedReadOnlyGuest4KPages || !outFexGuestExecuted)
        return -EINVAL;
    std::array<uint8_t,16> entropy{};
    std::memcpy(entropy.data(),callerEntropy16,entropy.size());
    kernix::g2e::c3d4::OriginalGuestNative4KReadOnlyLease lease;
    kernix::g2e::c3d4::NativeReadOnlyWitness evidence;
    const bool staged=lease.StageFromPinnedOriginals(
        appPrivateOriginalGuestRootFd,entropy,evidence);
    *outRuntimeNativeKernelPageBytes=evidence.actualNativeKernelPageBytes;
    const bool exactlyReadOnly=staged &&
        evidence.originalNative4KPagesByteCompared==609 &&
        evidence.exactNative4KPagesReserved==609 &&
        evidence.allOwnedMapsFinalReadOnly &&
        !evidence.originalFexGuestMemoryAttached &&
        !evidence.originalLinuxLdsoExecuted;
    const bool safelyReleased=lease.Release();
    if(!exactlyReadOnly || !safelyReleased)
        return -ENOEXEC;
    *outVerifiedReadOnlyGuest4KPages=609;
    // A build-only ABI must NEVER be counted as FEX guest execution.
    return 0;
}
