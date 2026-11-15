// SPDX-License-Identifier: MIT
// R3D26 source-locked x86_64 prlimit64(302) for the current Wine guest worker.
//
// The R3D25 real-device syscall is from ORIGINAL rootfs libc x86 RX code:
// pid=0, resource=3 (RLIMIT_STACK), new=NULL, old=0x6FFFFFFA80.
// Only a read-only query is supported; caller's output MUST be inside the
// already-installed, writable 64 KiB source-owned x86 guest Linux ABI stack.
// We never forward guest pointers to Android/Linux prlimit64, and never
// alter the actual Android host process's resource limits.
//
// Because the diagnostic guest stack cannot autogrow, report an effective
// guest limit capped by the installed stack span AND host's existing limits.
// These are documented diagnostic guest limits, not full Linux ABI semantics.
#pragma once
#include <algorithm>
#include <cstdint>
#include <cstddef>
#include <cerrno>
#include <cstring>
#include <sys/resource.h>
#include <limits>
namespace carx_r3d26 {
constexpr uint64_t kX86_64Prlimit64 = 302;
constexpr uint64_t kLinuxRLIMIT_STACK = 3;
struct LinuxRlimit64 {uint64_t cur{}, max{};};
static_assert(sizeof(LinuxRlimit64)==16,"x86_64 prlimit64 ABI is 16 bytes");
enum class StackLimitCode : uint8_t {
 Success, UnsupportedShape, InvalidStackRegion, OutsideWritableGuestStack,
 HostReadFailed
};
struct StackLimitResult {
 StackLimitCode code{StackLimitCode::UnsupportedShape};
 LinuxRlimit64 reported{};
};
inline bool can_write_guest_stack(uint64_t guestPointer,uint64_t bytes,
                       uint64_t stackBase,uint64_t stackEnd)noexcept {
 return guestPointer && bytes &&
        stackBase<stackEnd &&
        guestPointer>=stackBase &&
        guestPointer<stackEnd &&
        bytes<=stackEnd-guestPointer;
}
inline StackLimitResult query_guest_stack_prlimit64(
    uint64_t pid,uint64_t resource,uint64_t newLimit,
    uint64_t oldLimit,uint64_t stackBase,uint64_t stackEnd)noexcept {
 StackLimitResult out{};
 if(pid!=0 || resource!=kLinuxRLIMIT_STACK || newLimit!=0 || oldLimit==0)
   return out;
 if(!stackBase || stackBase>=stackEnd ||
    (stackBase&4095) || (stackEnd&4095) ||
    stackEnd-stackBase>1024*1024) {
   out.code=StackLimitCode::InvalidStackRegion;return out;
 }
 if((oldLimit&7) ||
    !can_write_guest_stack(oldLimit,sizeof(LinuxRlimit64),
                           stackBase,stackEnd)) {
   out.code=StackLimitCode::OutsideWritableGuestStack;return out;
 }
 struct rlimit current{};
 if(::getrlimit(RLIMIT_STACK,&current)!=0) {
   out.code=StackLimitCode::HostReadFailed;return out;
 }
 const uint64_t capacity=stackEnd-stackBase;
 const auto effective=[&](rlim_t native)->uint64_t {
   if(native==RLIM_INFINITY)return capacity;
   return std::min<uint64_t>(static_cast<uint64_t>(native),capacity);
 };
 out.reported={effective(current.rlim_cur),effective(current.rlim_max)};
 // Never make the guest's soft stack limit exceed its hard one.
 out.reported.cur=std::min(out.reported.cur,out.reported.max);
 void* dst=reinterpret_cast<void*>(static_cast<uintptr_t>(oldLimit));
 std::memcpy(dst,&out.reported,sizeof(out.reported));
 if(std::memcmp(dst,&out.reported,sizeof(out.reported))!=0){
   out.code=StackLimitCode::OutsideWritableGuestStack;return out;
 }
 out.code=StackLimitCode::Success;
 return out;
}
} // namespace carx_r3d26
