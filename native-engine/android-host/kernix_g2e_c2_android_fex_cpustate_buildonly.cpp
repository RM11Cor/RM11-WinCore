// KERNIX G2-E/C2 ARM64 Android-Bionic upstream FEXCore ABI source proof.
// This symbol is compiled into a BUILD-ONLY unshipped ELF for ABI checking.
// No Android device execution, no FEX thread creation, no ld-linux, no syscalls.
// SPDX-License-Identifier: MIT
#include "kernix_g2e_c2_original_fex_cpu_state_adapter.h"
#include <cstdint>
#if !defined(__ANDROID__) || !defined(__aarch64__)
#error This build-only adapter must target native Android/Bionic AArch64
#endif

extern "C" __attribute__((visibility("default")))
int kernix_g2ec2_bionic_fex_original_cpustate_frame_buildonly(
    const FEXCore::Core::CpuStateFrame* caller_frame,
    uint64_t trusted_stack_begin,
    uint64_t trusted_stack_past_last,
    uint32_t trusted_source_attestation_only,
    uint64_t* out_x86_guest_syscall,
    uint64_t* out_x86_guest_fourth_argument,
    int64_t* out_fail_closed_linux_return) noexcept {
    if(out_x86_guest_syscall)*out_x86_guest_syscall=UINT64_MAX;
    if(out_x86_guest_fourth_argument)*out_x86_guest_fourth_argument=0;
    if(out_fail_closed_linux_return)*out_fail_closed_linux_return=-38;
    if(!caller_frame || trusted_source_attestation_only!=1 ||
       !out_x86_guest_syscall || !out_x86_guest_fourth_argument ||
       !out_fail_closed_linux_return)return -22;
    const kernix::g2e::c1::X86GuestStackBoundary declared{
        trusted_stack_begin,trusted_stack_past_last,true
    };
    kernix::g2e::c2::ActualFexTrapWitness witness;
    if(!kernix::g2e::c2::DecodePinnedFexCpuState(
         caller_frame,declared,witness) ||
       !witness.originalFexCpuStateFrameRead ||
       witness.guestSyscallExecuted ||
       witness.guestKernelDispatched ||
       witness.guestMemoryDereferenced ||
       witness.guestDynamicLinkerEntered)return -8;
    const auto& dec=witness.decoded;
    *out_x86_guest_syscall=dec.guestNumber;
    *out_x86_guest_fourth_argument=dec.args[3];
    *out_fail_closed_linux_return=
        kernix::g2e::c2::NoHostDispatchLinuxEnosys();
    return 0;
}
