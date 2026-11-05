#pragma once
// SPDX-License-Identifier: MIT
// G0: restricted guest x86 Linux -> Bionic/POSIX syscall bridge.
// The supplied VmInterval must correspond to a *current owner-held* guest map.
// No raw guest syscall numbers forwarded to Android/ARM64.
#include "kernix_g2e_c1_x86_linux_syscall_boundary.h"
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <unistd.h>
namespace kernix::g0 {
namespace abi=kernix::g2e::c1;
constexpr uint64_t kMaxSingleWrite=4096;
enum class Event : uint8_t {Denied,WroteGuestData,ReturnedRealPid,ExitRequested};
struct Result {
 Event event=Event::Denied;
 int64_t guestReturn=-38;
 bool guestBytesValidated=false;
 bool hostWriteCalled=false;
 bool hostProcessExited=false;
 bool guestExitRequested=false;
 uint8_t guestExitCode=0;
};
// Only guest fd 1 is allowed and mapped to a host-selected output FD.
// No host stdout redirect from a guest fd, unverified pointer or host exit.
inline Result DispatchVerifiedGuestTrap(
 const abi::TrapClassification& trap,
 const abi::GuestVmInterval& authenticMappedBytes,
 int trustedOutputFD) noexcept {
 Result out{};
 if(!trap.trapBoundaryAuthenticated ||
    !trap.sourceRegisterMappingChecked ||
    trap.hostSyscallDispatched || trap.guestMemoryDereferenced)return out;
 switch(trap.guestNumber) {
 case abi::kWrite: {
   const uint64_t fd=trap.args[0],ptr=trap.args[1],len=trap.args[2];
   if(fd!=1 || trustedOutputFD<0){out.guestReturn=-9;return out;}
   if(len>kMaxSingleWrite){out.guestReturn=-22;return out;}
   if(!len){out.guestReturn=0;return out;}
   if(!abi::PinnedGuestSpan(ptr,len,abi::GuestDataAccess::Read,
                            authenticMappedBytes)){out.guestReturn=-14;return out;}
   out.guestBytesValidated=true;
   const ssize_t n=::write(trustedOutputFD,reinterpret_cast<const void*>(ptr),
                           static_cast<size_t>(len));
   out.hostWriteCalled=true;
   if(n<0) {
     switch(errno) {
     case EINTR:out.guestReturn=-4;break;
     case EAGAIN:out.guestReturn=-11;break;
     case EBADF:out.guestReturn=-9;break;
     case EFAULT:out.guestReturn=-14;break;
     case EPIPE:out.guestReturn=-32;break;
     default:out.guestReturn=-5;break;
     }
     return out;
   }
   out.event=Event::WroteGuestData;
   out.guestReturn=n;
   return out;
 }
 case abi::kGetpid: {
   const pid_t p=::getpid();
   if(p<=0){out.guestReturn=-5;return out;}
   out.event=Event::ReturnedRealPid;
   out.guestReturn=p;return out;
 }
 case abi::kExit: case abi::kExitGroup:
   out.event=Event::ExitRequested;
   out.guestExitRequested=true;
   out.guestExitCode=static_cast<uint8_t>(trap.args[0]&0xff);
   out.guestReturn=0; // Must stop guest thread, NOT resume nor exit host.
   return out;
 default:return out; // Linux -ENOSYS until explicitly implemented.
 }
}
} // namespace kernix::g0
