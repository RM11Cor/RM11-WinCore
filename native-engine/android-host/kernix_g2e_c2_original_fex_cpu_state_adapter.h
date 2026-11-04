#pragma once
// KERNIX G2-E/C2: true original FEXCore CpuStateFrame -> Linux x86-64 ABI.
// This is a PINNED UPSTREAM SOURCE ADAPTER, not a guest kernel implementation.
// It never dereferences guest pointers or forwards syscalls to Android/Linux.
// SPDX-License-Identifier: MIT
#include "kernix_g2e_c1_x86_linux_syscall_boundary.h"
#include <FEXCore/Core/CoreState.h>
#include <FEXCore/Core/X86Enums.h>
#include <cstdint>

namespace kernix::g2e::c2 {
struct ActualFexTrapWitness {
    kernix::g2e::c1::TrapClassification decoded{};
    bool originalFexCpuStateFrameRead=false;
    bool guestSyscallExecuted=false;    // set ONLY by actual FEX host callback
    bool guestKernelDispatched=false;
    bool guestMemoryDereferenced=false;
    bool guestDynamicLinkerEntered=false;
};
inline bool DecodePinnedFexCpuState(
    const FEXCore::Core::CpuStateFrame* frame,
    const kernix::g2e::c1::X86GuestStackBoundary& trustedStack,
    ActualFexTrapWitness& out) noexcept {
    out={};
    if(!frame)return false;
    const auto& cpu=frame->State;
    // Preserve genuine x86 Linux kernel syscall order, not AMD64 C ABI.
    // In FEX host callback RAX=guest syscall number, RCX=RIP after 0F05,
    // R11=guest RFLAGS, and R10=arg 4 (RCX is never arg 4).
    const kernix::g2e::c1::X86LinuxSyscallTrap record{
        cpu.gregs[FEXCore::X86State::REG_RAX],
        cpu.gregs[FEXCore::X86State::REG_RDI],
        cpu.gregs[FEXCore::X86State::REG_RSI],
        cpu.gregs[FEXCore::X86State::REG_RDX],
        cpu.gregs[FEXCore::X86State::REG_R10],
        cpu.gregs[FEXCore::X86State::REG_R8],
        cpu.gregs[FEXCore::X86State::REG_R9],
        cpu.rip,
        cpu.gregs[FEXCore::X86State::REG_RCX],
        cpu.gregs[FEXCore::X86State::REG_R11],
        cpu.gregs[FEXCore::X86State::REG_RSP]
    };
    if(!kernix::g2e::c1::ClassifyVerifiedTrap(
        record,trustedStack,out.decoded))return false;
    // This flag proves only that the pointed-to upstream FEX frame was read.
    // The caller must independently prove actual FEX guest trap execution.
    out.originalFexCpuStateFrameRead=true;
    return true;
}
inline constexpr int64_t NoHostDispatchLinuxEnosys() noexcept {
    return -38; // x86_64 Linux -ENOSYS, never a Bionic/ARM64 host syscall
}
} // namespace kernix::g2e::c2
