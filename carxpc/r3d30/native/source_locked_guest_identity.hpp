// SPDX-License-Identifier: MIT
// Only source-authenticated x86 syscall callbacks may reach this classifier.
// No guest pointer forwarded; identity based on isolated Android worker.
// x86_64 Linux: getpid=39, getuid=102, getgid=104, geteuid=107,
// getegid=108, gettid=186. Return the SAME UID/GID used on guest stack.
#pragma once
#include <cstdint>
namespace carx_r3d30 {
struct GuestIdentity{
 uint64_t pid{},tid{},uid{},gid{};
};
struct IdentityResult {bool handled{};uint64_t value{};};
inline IdentityResult handle_identity(uint64_t nr,GuestIdentity id)noexcept {
 if(!id.pid||!id.tid)return {};
 switch(nr) {
 case 39:return {true,id.pid};
 case 102:return {true,id.uid};
 case 104:return {true,id.gid};
 case 107:return {true,id.uid};
 case 108:return {true,id.gid};
 case 186:return {true,id.tid};
 default:return {};
 }
}
} // namespace carx_r3d30
