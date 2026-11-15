// SPDX-License-Identifier: MIT
// R3D28: source-bounded guest procfs readlink path components for Wine bootstrap.
//
// R3D27 device reported the EXACT original x86 libc readlink(89) path /proc
// (guest-owned stack, size 1023) after 23 source-verified Linux ABI responses.
// /proc is a DIRECTORY, NOT a symlink: Linux returns -EINVAL, *not* a
// fabricated /proc/self/exe value. glibc realpath may then inspect /proc/self
// (a symlink to its PID), /proc/<pid> (directory), and /proc/<pid>/exe (link).
//
// This narrow guest procfs view reflects the one isolated app-worker PID,
// already used as the identity of the guest Wine process. NEVER invoke host
// readlink on untrusted guest paths, never expose Android /proc/self/exe.
// The destination is solely the already-verified writable 64 KiB x86 stack.
// The caller preserves R3D27's standalone /proc/self/exe path case. Any
// unknown path still fails closed and captures a bounded original hex prefix.
#pragma once
#include "carxpc/r3d27/native/verified_guest_readlink.hpp"
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <algorithm>
namespace carx_r3d28 {
enum class Kind : uint8_t {
 Unknown, DirectoryNotSymlink, SelfPidSymlink, ProcessExeSymlink,
 InvalidGuestDestination
};
struct Result {
 Kind kind{Kind::Unknown};
 int64_t guestReturn{0};
};
inline Result resolve_known_procfs_component(
    const char* guestPath,uint64_t guestOutput,uint64_t capacity,
    uint64_t ownedStackStart,uint64_t ownedStackEnd,
    uint64_t guestWorkerPid) noexcept {
 if(!guestPath || !*guestPath || !guestWorkerPid ||
    guestWorkerPid>INT32_MAX)return {};
 if(std::strcmp(guestPath,carx_r3d27::kGuestProcSelfExe)==0)
   return {}; // keep earlier original R3D27 authenticated Wine ELF target
 char procPid[56]{},procPidExe[64]{},pidOnly[24]{};
 const int n=std::snprintf(pidOnly,sizeof(pidOnly),"%llu",
              static_cast<unsigned long long>(guestWorkerPid));
 if(n<=0 || static_cast<size_t>(n)>=sizeof(pidOnly))return {};
 const int dir=std::snprintf(procPid,sizeof(procPid),"/proc/%s",pidOnly);
 const int exe=std::snprintf(procPidExe,sizeof(procPidExe),"%s/exe",procPid);
 if(dir<=0 || exe<=0 || static_cast<size_t>(dir)>=sizeof(procPid) ||
    static_cast<size_t>(exe)>=sizeof(procPidExe))return {};
 const bool knownDirectory=
     std::strcmp(guestPath,"/proc")==0 ||
     std::strcmp(guestPath,"/proc/")==0 ||
     std::strcmp(guestPath,procPid)==0;
 const bool selfPid=std::strcmp(guestPath,"/proc/self")==0;
 const bool processExe=std::strcmp(guestPath,procPidExe)==0;
 if(!knownDirectory && !selfPid && !processExe)return {};
 // Readlink errors must not write to the output, but we still require a
 // source-owned valid writable guest target so we cannot accidentally
 // accept an invalid pointer with a fabricated -EINVAL.
 if(!carx_r3d27::owned_stack_target(
         guestOutput,capacity,ownedStackStart,ownedStackEnd))
   return {Kind::InvalidGuestDestination,-EFAULT};
 if(knownDirectory)return {Kind::DirectoryNotSymlink,-EINVAL};
 const char* target=selfPid?pidOnly:carx_r3d27::kGuestWineExec;
 const size_t len=std::strlen(target);
 const size_t copy=static_cast<size_t>(std::min<uint64_t>(capacity,len));
 void* dest=reinterpret_cast<void*>(static_cast<uintptr_t>(guestOutput));
 std::memcpy(dest,target,copy);
 if(std::memcmp(dest,target,copy)!=0)
   return {Kind::InvalidGuestDestination,-EFAULT};
 // POSIX readlink returns number of copied bytes and does not append NUL.
 return {selfPid?Kind::SelfPidSymlink:Kind::ProcessExeSymlink,
         static_cast<int64_t>(copy)};
}
} // namespace carx_r3d28
