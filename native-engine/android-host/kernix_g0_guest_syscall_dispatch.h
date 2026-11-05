#pragma once
// SPDX-License-Identifier: MIT
// G0: restricted guest x86 Linux -> Bionic/POSIX syscall bridge.
// The supplied VmInterval must correspond to a *current owner-held* guest map.
// No raw guest syscall numbers forwarded to Android/ARM64.
#include "kernix_g2e_c1_x86_linux_syscall_boundary.h"
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <fcntl.h>
#include <limits>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
namespace kernix::g0 {
namespace abi=kernix::g2e::c1;
constexpr uint64_t kMaxSingleWrite=4096;
constexpr uint64_t kMaxSinglePinnedPread=4096;
constexpr uint64_t kMaxAttestedGuestFileBytes=32*1024*1024ULL;
// The host *itself* opened, SHA256-checked and kept this exact regular file
// under its owned, no-symlink private guest root. No arbitrary guest path,
// descriptor or openat() is exposed by this narrow early runtime bridge.
struct PinnedReadOnlyGuestFile {
 uint64_t guestFd=3;
 int hostFd=-1;
 uint64_t exactVerifiedSize=0;
 bool sourceSha256Verified=false;
 bool ownerHeldNoFollowFd=false;
};
enum class Event : uint8_t {Denied,WroteGuestData,ReadPinnedGuestFile,ReturnedRealPid,ExitRequested};
struct Result {
 Event event=Event::Denied;
 int64_t guestReturn=-38;
 bool guestBytesValidated=false;
 bool hostWriteCalled=false;
 bool hostPreadCalled=false;
 bool hostProcessExited=false;
 bool guestExitRequested=false;
 uint8_t guestExitCode=0;
};
// Only guest fd 1 is allowed and mapped to a host-selected output FD.
// No host stdout redirect from a guest fd, unverified pointer or host exit.
inline Result DispatchVerifiedGuestTrap(
 const abi::TrapClassification& trap,
 const abi::GuestVmInterval& authenticMappedBytes,
 int trustedOutputFD,
 const PinnedReadOnlyGuestFile& allowedFile={}) noexcept {
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
 case abi::kPread64: {
   const uint64_t fd=trap.args[0],ptr=trap.args[1],
                  bytes=trap.args[2],offset=trap.args[3]; // guest R10
   if(fd!=3 || allowedFile.guestFd!=3 || allowedFile.hostFd<0 ||
      !allowedFile.sourceSha256Verified || !allowedFile.ownerHeldNoFollowFd ||
      allowedFile.exactVerifiedSize==0 ||
      allowedFile.exactVerifiedSize>kMaxAttestedGuestFileBytes) {
     out.guestReturn=-9;return out;
   }
   if(bytes>kMaxSinglePinnedPread ||
      offset>static_cast<uint64_t>(std::numeric_limits<int64_t>::max())) {
     out.guestReturn=-22;return out;
   }
   // Detect revoked/opened-wrong file descriptors before touching guest VM.
   struct stat st{};
   if(::fstat(allowedFile.hostFd,&st)!=0 || !S_ISREG(st.st_mode) ||
      st.st_uid!=::getuid() || (st.st_mode&(S_IWGRP|S_IWOTH)) ||
      st.st_size<0 ||
      static_cast<uint64_t>(st.st_size)!=allowedFile.exactVerifiedSize ||
      ::fcntl(allowedFile.hostFd,F_GETFL)<0 ||
      (::fcntl(allowedFile.hostFd,F_GETFL)&O_ACCMODE)!=O_RDONLY) {
     out.guestReturn=-9;return out;
   }
   if(bytes==0 || offset>=allowedFile.exactVerifiedSize) {
     out.guestReturn=0;return out;
   }
   if(!abi::PinnedGuestSpan(ptr,bytes,abi::GuestDataAccess::Write,
                            authenticMappedBytes)) {
     out.guestReturn=-14;return out;
   }
   out.guestBytesValidated=true;
   const uint64_t remaining=allowedFile.exactVerifiedSize-offset;
   const size_t cap=static_cast<size_t>(remaining<bytes?remaining:bytes);
   const ssize_t n=::pread(allowedFile.hostFd,
                           reinterpret_cast<void*>(ptr),cap,
                           static_cast<off_t>(offset));
   out.hostPreadCalled=true;
   if(n<0) {
     switch(errno) {
       case EINTR:out.guestReturn=-4;break;
       case EAGAIN:out.guestReturn=-11;break;
       case EBADF:out.guestReturn=-9;break;
       case EFAULT:out.guestReturn=-14;break;
       case EINVAL:out.guestReturn=-22;break;
       default:out.guestReturn=-5;break;
     }
     return out;
   }
   out.event=Event::ReadPinnedGuestFile;
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
