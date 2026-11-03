// KERNIX G2-B narrow Android Bionic C ABI for Linux x86-64 initial stack.
 // Build-only. Does not map guest memory, initialize FEX or run Wine.
#include "kernix_guest_linux_x86_initial_stack.h"
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <unistd.h>
#if !defined(__ANDROID__) || !defined(__aarch64__)
#error KERNIX G2-B stack must cross-link with real Android ARM64 NDK
#endif

extern "C" __attribute__((visibility("default")))
int kernix_g2b_android_plan_guest_linux_x86_stack_readonly(
    uint64_t stack_bottom, uint64_t stack_bytes, uint64_t guest_page_bytes,
    uint64_t verified_guest_phdr, uint64_t verified_main_entry,
    uint64_t verified_interpreter_base, uint16_t verified_phnum,
    const uint8_t* supplied_random16, const char* verified_guest_argv0,
    uint64_t* out_rsp, uint64_t* out_execfn,
    uint32_t* out_aux_entries) noexcept {
    if (out_rsp) *out_rsp=0;
    if (out_execfn) *out_execfn=0;
    if (out_aux_entries) *out_aux_entries=0;
    if (!out_rsp || !out_execfn || !out_aux_entries ||
        !supplied_random16 || !verified_guest_argv0)
        return -EINVAL;
    // argv0 is a caller-owned, bounded NUL-terminated string.
    const size_t n=strnlen(verified_guest_argv0,2049);
    if (!n || n>2048) return -EINVAL;
    try {
        kernix::g2b::LinuxX86StackInput plan;
        plan.guestStackBottom=stack_bottom;
        plan.guestStackBytes=stack_bytes;
        plan.guestPageBytes=guest_page_bytes;
        plan.guestMainProgramHeaders=verified_guest_phdr;
        plan.guestMainEntry=verified_main_entry;
        plan.guestInterpreterBase=verified_interpreter_base;
        plan.programHeaderCount=verified_phnum;
        plan.uid=static_cast<uint32_t>(getuid());
        plan.euid=static_cast<uint32_t>(geteuid());
        plan.gid=static_cast<uint32_t>(getgid());
        plan.egid=static_cast<uint32_t>(getegid());
        memcpy(plan.randomBytes.data(),supplied_random16,16);
        plan.args.emplace_back(verified_guest_argv0,n);
        plan.environment={"LANG=C"};
        kernix::g2b::LinuxX86StackImage prepared;
        std::string error;
        if (!kernix::g2b::PrepareLinuxX86InitialStack(
                plan,prepared,error) ||
            !prepared.initialStackLayoutValidated ||
            prepared.guestMemoryMapped || prepared.guestCodeExecuted ||
            prepared.androidWineTested || !prepared.guestRSP ||
            !prepared.guestExecFnPointer) return -ENOEXEC;
        *out_rsp=prepared.guestRSP;
        *out_execfn=prepared.guestExecFnPointer;
        *out_aux_entries=static_cast<uint32_t>(prepared.auxEntryCount);
        // Prepared bytes are discarded here. This is ONLY an ABI layout
        // preflight, not a valid installed guest RSP for FEX execution.
        return 0;
    } catch (...) {
        return -EFAULT;
    }
}
