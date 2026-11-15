// SPDX-License-Identifier: MIT
// R3D27: bounded SOURCE-VERIFIED x86 guest readlink(89) for /proc/self/exe.
//
// Phone R3D26 verified 23 prior Linux syscall responses, and the 24th
// original libc x86 syscall = readlink(89) from the real verified libc
// executable mapping. x86 args: path 0x6FFFFFF0A0,
// destination 0x6FFFFFF8C0, capacity 1023. The path contents are NOT
// present in R3D26 report. Verify them live from the owned guest stack
// before selecting any result. No guest pointer forwarded to host readlink.
//
// R3C23's SHA-source-verified ELF launch contract explicitly installs
// /usr/lib/wine/wine64 as the guest Wine executable. ONLY the exact
// /proc/self/exe guest procfs symlink is exposed as this pathname.
// All other paths fail closed with a bounded diagnostic path witness.
// Follows Linux readlink semantics: bytes copied, NO trailing NUL.
// This is a guest-only diagnostic procfs overlay, NOT general VFS.
#pragma once
#include <cstdint>
#include <cstddef>
#include <algorithm>
#include <cstring>
namespace carx_r3d27 {
constexpr uint64_t kLinuxX86Readlink=89;
inline constexpr char kGuestProcSelfExe[]="/proc/self/exe";
inline constexpr char kGuestWineExec[]="/usr/lib/wine/wine64";
constexpr uint64_t kMaxReadlinkBytes=4096;
enum class Status : uint8_t {
 Success, NotVerifiedGuestProcSelfExe, InvalidDestination,
 InvalidCount, VerificationFailed
};
struct Result {Status code{Status::NotVerifiedGuestProcSelfExe};uint64_t bytes{0};};
inline bool owned_stack_target(uint64_t addr,uint64_t count,
                               uint64_t low,uint64_t high)noexcept{
 return low>0 && low<high && high-low==65536 &&
        addr>=low && addr<high &&
        count>0 && count<=kMaxReadlinkBytes &&
        count<=high-addr;
}
inline Result write_source_bound_proc_self_exe(
    const char* capturedReadlinkPath,uint64_t guestBuffer,uint64_t capacity,
    uint64_t stackBase,uint64_t stackTop)noexcept{
 if(!capturedReadlinkPath ||
    std::strcmp(capturedReadlinkPath,kGuestProcSelfExe)!=0)
   return {Status::NotVerifiedGuestProcSelfExe,0};
 if(!capacity || capacity>kMaxReadlinkBytes)
   return {Status::InvalidCount,0};
 if(!owned_stack_target(guestBuffer,capacity,stackBase,stackTop))
   return {Status::InvalidDestination,0};
 constexpr size_t kPathLen=sizeof(kGuestWineExec)-1;
 const size_t n=static_cast<size_t>(std::min<uint64_t>(capacity,kPathLen));
 auto* ptr=reinterpret_cast<char*>(static_cast<uintptr_t>(guestBuffer));
 std::memcpy(ptr,kGuestWineExec,n);
 if(std::memcmp(ptr,kGuestWineExec,n)!=0)
   return {Status::VerificationFailed,0};
 return {Status::Success,n};
}
} // namespace carx_r3d27
