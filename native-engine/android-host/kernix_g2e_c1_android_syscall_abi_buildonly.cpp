// KERNIX G2-E/C1: Android/Bionic AArch64 cross-link audit, NOT an APK component.
// Copies a caller-provided synthetic register record and evaluates exactly
// the x86 Linux guest syscall boundary policy in host-only memory.
// It does not read FEXCore state, map pages, execute a guest or forward syscalls.
// SPDX-License-Identifier: MIT
#include "kernix_g2e_c1_x86_linux_syscall_boundary.h"
#include <cerrno>
#include <cstdint>
#include <cstring>
#if !defined(__ANDROID__) || !defined(__aarch64__)
#error Android G2-E/C1 build-only policy must cross-link against Bionic ARM64
#endif

extern "C" __attribute__((visibility("default")))
int kernix_g2e_c1_android_bionic_syscall_abi_build_only(
    const uint64_t* caller_provided_register_words,
    uint32_t word_count,
    uint64_t trusted_stack_begin,
    uint64_t trusted_stack_end,
    uint32_t trusted_fixed_test_fixture,
    uint64_t* out_guest_syscall_number,
    int64_t* out_guest_denial_result) noexcept {
    if(out_guest_syscall_number)*out_guest_syscall_number=UINT64_MAX;
    if(out_guest_denial_result)*out_guest_denial_result=-38;
    if(!caller_provided_register_words || word_count!=11 ||
       !out_guest_syscall_number || !out_guest_denial_result ||
       trusted_fixed_test_fixture!=1)
        return -EINVAL;
    // Only 11 copied register words, no guest pointers dereferenced.
    uint64_t r[11]{};
    std::memcpy(r,caller_provided_register_words,sizeof(r));
    const kernix::g2e::c1::X86LinuxSyscallTrap synthetic{
        r[0],r[1],r[2],r[3],r[4],r[5],r[6],
        r[7],r[8],r[9],r[10]
    };
    const kernix::g2e::c1::X86GuestStackBoundary fakeStack{
        trusted_stack_begin,trusted_stack_end,true
    };
    kernix::g2e::c1::TrapClassification decoded;
    if(!kernix::g2e::c1::ClassifyVerifiedTrap(synthetic,fakeStack,decoded))
        return -ENOEXEC;
    // All recognized and unrecognized Linux syscalls are denied with
    // -ENOSYS. Even exit_group cannot call the Android process exit.
    const auto denied=kernix::g2e::c1::PlanHostlessGuestDispatch(decoded);
    if(denied.hostSyscallInvoked || denied.guestMemoryTouched ||
       denied.hostProcessExited || decoded.fexGuestExecuted)
        return -EPERM;
    *out_guest_syscall_number=decoded.guestNumber;
    *out_guest_denial_result=denied.safeGuestReturn;
    return 0;
}
