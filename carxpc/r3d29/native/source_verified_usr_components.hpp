// SPDX-License-Identifier: MIT
// R3D29: narrowly source-authenticated guest rootfs directory readlink.
//
// R3D28 phone trace proved authenticated libc source x86_64 syscall #28
// readlink(89) on exact path "/usr", after 27 bounded Linux guest responses.
// Correct Linux readlink(non-symlink directory) = -EINVAL; no buffer write.
// Source: the already SHA-validated Wine guest launch contract /usr/lib/wine/wine64
// plus installed verified guest rootfs. This is NOT an Android host path.
// Treat only the *directory components* of that same verified Wine path as
// non-links; any other path retains the original fail-closed source trace.
// In particular, NEVER assume /lib is a directory (may be an actual symlink).
// Preserve R3D28 procfs symlink and directory handling as a separate case.
// No syscalls forwarded to host; no arbitrary host stat/readlink calls.
#pragma once
#include "carxpc/r3d27/native/verified_guest_readlink.hpp"
#include <cerrno>
#include <cstdint>
#include <cstring>
namespace carx_r3d29 {
enum class Kind : uint8_t { Unknown=0, VerifiedNonSymlinkDirectory=1, BadOutputRegion=2, MissingOriginalWineEvidence=3 };
struct Result {
 Kind kind{Kind::Unknown};
 int64_t guestReturn{0};
};
inline Kind known_wine_guest_directory(const char* path) noexcept {
 if(!path)return Kind::Unknown;
 // The prefix chain is derived from the authenticated guest Wine ELF
 // execfn /usr/lib/wine/wine64, not from the Android process filesystem.
 if(std::strcmp(path,"/")==0 ||
    std::strcmp(path,"/usr")==0 ||
    std::strcmp(path,"/usr/")==0 ||
    std::strcmp(path,"/usr/lib")==0 ||
    std::strcmp(path,"/usr/lib/")==0 ||
    std::strcmp(path,"/usr/lib/wine")==0 ||
    std::strcmp(path,"/usr/lib/wine/")==0)
   return Kind::VerifiedNonSymlinkDirectory;
 return Kind::Unknown;
}
inline Result query_readlink_non_symlink(
 const char* sourceVerifiedGuestPath,uint64_t guestOutput,uint64_t capacity,
 uint64_t stackLow,uint64_t stackTop,bool originalWineELFVerified) noexcept {
 const auto kind=known_wine_guest_directory(sourceVerifiedGuestPath);
 if(kind==Kind::Unknown)return {};
 if(!originalWineELFVerified)return {Kind::MissingOriginalWineEvidence,0};
 if(!carx_r3d27::owned_stack_target(
        guestOutput,capacity,stackLow,stackTop))
   return {Kind::BadOutputRegion,-EFAULT};
 // Linux readlink never succeeds for these already-known actual directories,
 // and must NEVER modify the supplied guest output bytes in this case.
 return {Kind::VerifiedNonSymlinkDirectory,-EINVAL};
}
} // namespace carx_r3d29
