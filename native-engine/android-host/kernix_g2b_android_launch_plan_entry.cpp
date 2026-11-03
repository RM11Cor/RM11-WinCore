// KERNIX G2-B Android/Bionic C ABI for *planning only* the first dynamic
// Linux x86_64 guest startup. No FEX entry, no mapping, no Wine execution.
// SPDX-License-Identifier: MIT
#include "kernix_g2b_guest_launch_plan.h"
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <unistd.h>

#if !defined(__ANDROID__) || !defined(__aarch64__)
#error Expected real Android ARM64/Bionic NDK
#endif

extern "C" __attribute__((visibility("default")))
int kernix_g2b_android_audit_dynamic_launch_plan_only(
    int app_owned_immutable_rootfd, const char* fixed_guest_executable,
    uint64_t main_image_start, uint64_t interpreter_image_start,
    uint64_t guest_stack_bottom, uint64_t guest_stack_bytes,
    uint64_t guest_page_bytes, const uint8_t* external_random16,
    uint64_t* out_loader_entry, uint64_t* out_initial_stack_rsp,
    uint32_t* out_verified_elf_count) noexcept {
    if (out_loader_entry) *out_loader_entry=0;
    if (out_initial_stack_rsp) *out_initial_stack_rsp=0;
    if (out_verified_elf_count) *out_verified_elf_count=0;
    if (app_owned_immutable_rootfd<0 || !fixed_guest_executable ||
        !external_random16 || !out_loader_entry ||
        !out_initial_stack_rsp || !out_verified_elf_count)
        return -EINVAL;
    const size_t n=strnlen(fixed_guest_executable,
                           kernix::g2b::kMaxSymlinkGuestPath+1);
    if (n<2 || n>kernix::g2b::kMaxSymlinkGuestPath ||
        fixed_guest_executable[0]!='/') return -EINVAL;
    try {
        kernix::g2b::X86GuestProcessAddresses in{};
        in.mainImageStart=main_image_start;
        in.interpreterImageStart=interpreter_image_start;
        in.stackBottom=guest_stack_bottom;
        in.stackBytes=guest_stack_bytes;
        in.guestPageBytes=guest_page_bytes;
        in.uid=static_cast<uint32_t>(getuid());
        in.euid=static_cast<uint32_t>(geteuid());
        in.gid=static_cast<uint32_t>(getgid());
        in.egid=static_cast<uint32_t>(getegid());
        std::memcpy(in.randomBytes.data(),external_random16,16);
        in.argv.emplace_back(fixed_guest_executable,n);
        in.environment={"LANG=C"};
        kernix::g2b::X86GuestProcessLaunchPlan plan;
        std::string failure;
        if (!kernix::g2b::PrepareX86DynamicGuestLaunchPlan(
                app_owned_immutable_rootfd,
                std::string_view(fixed_guest_executable,n),
                in,plan,failure) ||
            !plan.guestVirtualAddressesValidated ||
            !plan.stackAndAuxvConsistent ||
            plan.guestAddressSpaceReserved ||
            plan.guestMemoryMapped || plan.fexEntryPointAssigned ||
            plan.dynamicLinkerExecuted || plan.guestCodeExecuted ||
            plan.androidWineTested || !plan.guestInterpreterEntry ||
            !plan.stack.guestRSP || plan.dependencyObjectsChecked==0)
            return -ENOEXEC;
        *out_loader_entry=plan.guestInterpreterEntry;
        *out_initial_stack_rsp=plan.stack.guestRSP;
        *out_verified_elf_count=static_cast<uint32_t>(
            plan.dependencyObjectsChecked);
        // IMPORTANT: No guest memory exists at these numbers! Returning
        // addresses is a layout test, not authorization to enter FEX.
        return 0;
    } catch (...) {
        return -EFAULT;
    }
}
