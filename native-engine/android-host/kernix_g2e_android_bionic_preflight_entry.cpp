// KERNIX G2-E/A: Android ARM64/Bionic source-link, DATA ONLY.
// It cannot launch ld-linux, host dlopen() glibc, call FEX, or run Wine.
// Caller supplies a stable, private, no-symlink rootfd and immutable files.
// SPDX-License-Identifier: MIT
#include "kernix_g2e_pinned_glibc_preflight.h"
#include <cerrno>
#include <cstdint>
#if !defined(__ANDROID__) || !defined(__aarch64__)
#error G2-E/A must be compiled with Android NDK aarch64-linux-android, not Linux host
#endif

extern "C" __attribute__((visibility("default")))
int kernix_g2e_android_attest_exact_linux_x86_guest_data_only(
    int app_owned_private_guest_rootfd,
    uint32_t* out_verified_objects) noexcept {
    if(out_verified_objects) *out_verified_objects=0;
    if(app_owned_private_guest_rootfd<0 || out_verified_objects==nullptr)
        return -EINVAL;
    try {
        kernix::g2e::GuestPreflight result;
        std::string reason;
        if(!kernix::g2e::Validate(
             app_owned_private_guest_rootfd,result,reason) ||
           !result.exactSha256Matched ||
           !result.readOnlyAnonymousSnapshots ||
           !result.exactInterpreterAndGlibcClosure ||
           result.guestCodeExecuted || result.dynamicLinkerExecuted ||
           result.fexAttached || result.wineExecuted)
            return -ENOEXEC;
        *out_verified_objects=3;
        // No anonymous snapshot, x86 address or FD leaves this process API.
        // The object releases its read-only allocations upon return.
        return 0;
    } catch (...) {
        return -EFAULT;
    }
}
