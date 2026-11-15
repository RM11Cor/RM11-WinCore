// SPDX-License-Identifier: MIT
// R3D44: inspect genuine x86_64 connect(42) to NSCD, not Wine server.
// Phone R3D43 saw socket(41,AF_UNIX,0x80801,0)->virtual fd117 then
// connect(42,117, guest stack 0x6FFFFFF680, sizeof(sockaddr_un)=110).
// glibc nscd_helper.c calls this same sequence against
// /var/run/nscd/socket. No guest pointer, socket name or host fd is passed
// to the Android socket syscall; verified rootfd checks an absent endpoint.
// No generic socket connect support or Wine server emulation is claimed.
#pragma once
#include "carxpc/r3d41/native/confined_symlink_walker.hpp"
#include "carxpc/r3d43/native/source_locked_afunix_socket_vfd.hpp"
#include <cerrno>
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cstdio>

namespace carx_r3d44 {
constexpr uint64_t kX86Connect=42;
constexpr size_t kGuestSockAddrMax=110;
constexpr size_t kSunPathMax=108;
enum class Reason:uint8_t {
  HandledNscdAbsent=0, NotConnect=1,UnknownGuestSocket=2,InvalidSize=3,
  UnownedGuestMemory=4,NotUnixFamily=5,AbstractSocket=6,
  UnterminatedPath=7,UnsafePathBytes=8,UnexpectedPath=9,
  RootfsPathPresent=10,UnsafeRootfs=11,UnexpectedRootfsError=12
};
struct Result {
 bool handled{false};
 int64_t value{-ENOSYS};
 Reason reason{Reason::NotConnect};
 char guestPath[kSunPathMax+1]{};
 size_t pathLength{0};
 uint8_t symlinkHops{0};
};
template<class Readable>
inline Result source_verified_nscd_connect(
  uint64_t number,uint64_t guestSocketFd,uint64_t guestAddress,
  uint64_t guestLength,int guestRootFd,
  const carx_r3d43::OwnedUnixSockets& sockets,
  Readable sourceOwnedGuestReadable) noexcept {
 Result r{};
 if(number!=kX86Connect)return r;
 r.reason=Reason::UnknownGuestSocket;
 if(!sockets.owns(guestSocketFd))return r;
 r.reason=Reason::InvalidSize;
 if(guestLength<3 || guestLength>kGuestSockAddrMax ||
    guestAddress==0 || guestAddress>UINT64_MAX-guestLength)
   return r;
 r.reason=Reason::UnownedGuestMemory;
 if(!sourceOwnedGuestReadable(guestAddress,guestLength))return r;
 unsigned char bytes[kGuestSockAddrMax]{};
 // Only copy from proven guest-owned readable address, never host pointer
 // passthrough, no reads outside the validated user-provided length.
 std::memcpy(bytes,reinterpret_cast<const void*>(
    static_cast<uintptr_t>(guestAddress)),size_t(guestLength));
 r.reason=Reason::NotUnixFamily;
 if(bytes[0]!=1 || bytes[1]!=0)return r;
 r.reason=Reason::AbstractSocket;
 if(bytes[2]==0)return r;
 r.reason=Reason::UnterminatedPath;
 const size_t n=size_t(guestLength)-2;
 size_t len=0;
 for(;len<n;++len)if(bytes[2+len]==0)break;
 if(len==n || len==0 || len>kSunPathMax)return r;
 r.reason=Reason::UnsafePathBytes;
 for(size_t i=0;i<len;i++) {
   const unsigned char b=bytes[2+i];
   if(b<0x21||b>0x7e)return r;
   r.guestPath[i]=static_cast<char>(b);
 }
 r.guestPath[len]='\0';r.pathLength=len;
 r.reason=Reason::UnexpectedPath;
 // Exactly two ABI-valid glibc NSCD endpoint spellings are allowed.
 if(std::strcmp(r.guestPath,"/var/run/nscd/socket")!=0 &&
    std::strcmp(r.guestPath,"/run/nscd/socket")!=0)return r;
 // Consult only app-private source-authenticated guest rootfd, with
 // jailed symlink traversal and a metadata-only lookup. We only
 // return ENOENT after actual negative lookup, never from assumption.
 const auto lookup=carx_r3d41::open_guest_readonly(
     guestRootFd,r.guestPath,true);
 r.symlinkHops=lookup.symlinks;
 if(lookup.status==carx_r3d41::Status::Opened &&
    lookup.negativeErrno==-ENOENT) {
   r.handled=true;r.value=-ENOENT;
   r.reason=Reason::HandledNscdAbsent;return r;
 }
 r.reason=lookup.status==carx_r3d41::Status::Exists?
     Reason::RootfsPathPresent:Reason::UnsafeRootfs;
 if(lookup.status==carx_r3d41::Status::Opened &&
    lookup.negativeErrno==-ENOTDIR) {
    r.handled=true;r.value=-ENOTDIR;
    r.reason=Reason::HandledNscdAbsent;return r;
 }
 if(lookup.status==carx_r3d41::Status::Opened)
   r.reason=Reason::UnexpectedRootfsError;
 return r;
}
inline void path_hex_marker(const Result& result,
                            char (&out)[190]) noexcept {
 std::memset(out,0,sizeof(out));
 const int prefix=std::snprintf(out,sizeof(out),
   "N71_R3D44_SOCKADDR_GUEST_PATH_HEX_");
 if(prefix<0 || size_t(prefix)>=sizeof(out))return;
 constexpr char hex[]="0123456789ABCDEF";
 size_t at=size_t(prefix);
 const size_t lim=result.pathLength<70?result.pathLength:70;
 for(size_t i=0;i<lim && at+2<sizeof(out);++i) {
   const unsigned char b=static_cast<unsigned char>(result.guestPath[i]);
   out[at++]=hex[b>>4];out[at++]=hex[b&15];
 }
 out[at]='\0';
}
} // namespace carx_r3d44
