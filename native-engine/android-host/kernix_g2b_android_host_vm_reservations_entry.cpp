// KERNIX G2-B Android ARM64 cross-link gate for NO-ACCESS host VM windows.
// Build-only: NOT packaged, NOT invoked on a phone and NOT a FEX guest VA
// allocator. No MAP_FIXED, root, PROT_EXEC, PT_LOAD installation or Wine.
// SPDX-License-Identifier: MIT
#include "kernix_g2b_guest_host_reservations.h"
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <string>
#include <unistd.h>

#if !defined(__ANDROID__) || !defined(__aarch64__)
#error This build-only probe must target actual Android ARM64/Bionic
#endif

extern "C" __attribute__((visibility("default")))
int kernix_g2b_android_host_prot_none_reservation_preflight(
    int trusted_app_rootfd, const char* fixed_guest_path,
    uint64_t guest_page_bytes, const uint8_t* caller_random16,
    uint64_t* main_guest_window, uint64_t* loader_guest_window,
    uint64_t* stack_guest_window, uint32_t* elf_objects) noexcept {
    if (main_guest_window) *main_guest_window=0;
    if (loader_guest_window) *loader_guest_window=0;
    if (stack_guest_window) *stack_guest_window=0;
    if (elf_objects) *elf_objects=0;
    if (trusted_app_rootfd<0 || !fixed_guest_path || !caller_random16 ||
        !main_guest_window || !loader_guest_window ||
        !stack_guest_window || !elf_objects)
        return -EINVAL;
    const size_t n=strnlen(fixed_guest_path,
                            kernix::g2b::kMaxSymlinkGuestPath+1);
    if (n<2 || n>kernix::g2b::kMaxSymlinkGuestPath ||
        fixed_guest_path[0]!='/') return -EINVAL;
    try {
        std::array<uint8_t,16> random{};
        std::memcpy(random.data(),caller_random16,16);
        kernix::g2b::X86HostReservedGuestLaunch reservation;
        std::string why;
        if (!kernix::g2b::ReserveAndValidateX86HostGuestWindows(
            trusted_app_rootfd,
            std::string_view(fixed_guest_path,n),
            guest_page_bytes,65536,random,
            {std::string(fixed_guest_path,n)},
            {"LANG=C"},reservation,why) ||
            !reservation.hostVAsReservedPROT_NONE ||
            reservation.guestVAsInstalledInFEX ||
            reservation.executableGuestPagesMapped ||
            reservation.guestCodeExecuted ||
            reservation.androidWineTested)
            return -ENOEXEC;
        // These addresses become invalid IMMEDIATELY after return as the
        // RAII object unmaps all host windows. Only an instrumented in-scope
        // caller may use them for transient diagnostics, never for execution.
        // To prevent false capability claims, export only object count.
        *elf_objects=static_cast<uint32_t>(
            reservation.plan.dependencyObjectsChecked);
        *main_guest_window=0;
        *loader_guest_window=0;
        *stack_guest_window=0;
        return 0;
    } catch (...) {
        return -EFAULT;
    }
}
