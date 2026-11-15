// SPDX-License-Identifier: MIT
// CarX R3D43 - Real AF_UNIX stream sockets owned by the isolated native
// worker, exposed to the original FEX guest through virtual FDs 117..124.
// No guest syscall number, host socket FD, sockaddr, guest pointer or path is
// forwarded blindly. Only Linux x86_64 socket(41), AF_UNIX, SOCK_STREAM,
// optional SOCK_NONBLOCK|SOCK_CLOEXEC and protocol=0 are accepted.
// No connect/listen/SCM_RIGHTS support yet; no Wine server is spoofed.
#pragma once
#include <array>
#include <cerrno>
#include <cstdint>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>

namespace carx_r3d43 {
constexpr uint64_t kX86Socket=41;
constexpr uint64_t kX86Close=3;
constexpr uint64_t kAfUnix=1;
constexpr uint64_t kSockStream=1;
constexpr uint64_t kSockNonblock=0x800;
constexpr uint64_t kSockCloexec=0x80000;
constexpr int kFirstGuestFd=117;
constexpr int kGuestCapacity=8;
enum class Reason:uint8_t {
  Accepted, UnsupportedSyscall, InvalidFamily, InvalidType,
  InvalidProtocol, NoSlot, InvalidGuestFd, NativeError
};
struct Reply {bool handled{false};int64_t value{-ENOSYS};
              Reason reason{Reason::UnsupportedSyscall};};
class OwnedUnixSockets {
  struct Slot {int hostFd{-1};};
  std::array<Slot,kGuestCapacity> sockets{};
  int index(uint64_t fd)const noexcept {
    if(fd<kFirstGuestFd || fd>=kFirstGuestFd+kGuestCapacity)return -1;
    return static_cast<int>(fd-kFirstGuestFd);
  }
 public:
  OwnedUnixSockets()=default;
  OwnedUnixSockets(const OwnedUnixSockets&)=delete;
  OwnedUnixSockets& operator=(const OwnedUnixSockets&)=delete;
  ~OwnedUnixSockets(){for(auto &s:sockets)if(s.hostFd>=0)::close(s.hostFd);}
  bool owns(uint64_t fd)const noexcept {
    int i=index(fd);return i>=0 && sockets[i].hostFd>=0;
  }
  // Native FD is *never* exposed to the guest; test-only introspection.
  int native_fd_for_verification(uint64_t fd)const noexcept {
    int i=index(fd);return i>=0?sockets[i].hostFd:-1;
  }
  Reply dispatch(uint64_t number,uint64_t arg0,uint64_t arg1,
                 uint64_t arg2) noexcept {
    if(number==kX86Close){
      const int i=index(arg0);
      if(i<0 || sockets[i].hostFd<0)
        return {false,-ENOSYS,Reason::InvalidGuestFd};
      const int fd=sockets[i].hostFd;
      sockets[i].hostFd=-1;
      if(::close(fd)!=0)return {true,-errno,Reason::NativeError};
      return {true,0,Reason::Accepted};
    }
    if(number!=kX86Socket)
      return {false,-ENOSYS,Reason::UnsupportedSyscall};
    if(arg0!=kAfUnix)
      return {false,-EAFNOSUPPORT,Reason::InvalidFamily};
    if((arg1&~(kSockNonblock|kSockCloexec))!=kSockStream)
      return {false,-EINVAL,Reason::InvalidType};
    if(arg2!=0)
      return {false,-EPROTONOSUPPORT,Reason::InvalidProtocol};
    int slot=-1;
    for(int i=0;i<kGuestCapacity;i++) {
      if(sockets[i].hostFd<0){slot=i;break;}
    }
    if(slot<0)return {true,-EMFILE,Reason::NoSlot};
    int flags=SOCK_STREAM;
    if(arg1&kSockNonblock)flags|=SOCK_NONBLOCK;
    if(arg1&kSockCloexec)flags|=SOCK_CLOEXEC;
    const int hostFd=::socket(AF_UNIX,flags,0);
    if(hostFd<0)return {true,-errno,Reason::NativeError};
    // FEX has a separate 64-bit guest FD namespace; never expose hostFd.
    sockets[slot].hostFd=hostFd;
    return {true,kFirstGuestFd+slot,Reason::Accepted};
  }
};
} // namespace carx_r3d43
