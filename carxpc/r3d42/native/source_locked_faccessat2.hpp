// SPDX-License-Identifier: MIT
// R3D42: source-locked original GNU libc x86_64 syscall 439 faccessat2,
// first observed on phone R3D41 at index66, args:
// dirfd=AT_FDCWD(-100), path=owned guest stack, mode=F_OK,
// flags=AT_EACCESS(0x200). Guest paths never forwarded to the host kernel.
// Only F_OK of a rooted ABSOLUTE guest pathname is currently supported.
// Unknown flags/modes/relative CWD deliberately remain UNHANDLED.
#pragma once
#include "carxpc/r3d33/native/owned_guest_path_and_vfs.hpp"
#include "carxpc/r3d41/native/confined_symlink_walker.hpp"
#include <cstdint>
#include <cerrno>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <fcntl.h>

namespace carx_r3d42 {
constexpr uint64_t kX64Faccessat2=439;
constexpr uint64_t kAtEaccess=0x200;
constexpr int32_t kGuestAtFdcwd=-100;
enum class Reason:uint8_t {
  Ok=0,NoFile=1,InvalidSource=2,UnknownMode=3,UnknownFlags=4,
  UnknownDirfd=5,RelativeCwdUnproven=6,UnsafePath=7,
  SymlinkLoop=8,SourceRootInvalid=9,OtherLookupError=10
};
struct Result {
 bool handled{false};
 int64_t value{-ENOSYS};
 Reason reason{Reason::InvalidSource};
 carx_r3d33::PathCapture path{};
 uint8_t hops{0};
};
template<class GuestReadable>
inline Result source_verified_faccessat2(
    uint64_t number,uint64_t dirfd,uint64_t guestPathPointer,
    uint64_t mode,uint64_t flags,int verifiedGuestRootFd,
    GuestReadable guestReadable) noexcept {
 Result r{};
 if(number!=kX64Faccessat2)return r;
 if(mode!=0){r.reason=Reason::UnknownMode;return r;}
 if(flags!=0 && flags!=kAtEaccess){
   r.reason=Reason::UnknownFlags;return r;
 }
 if(int32_t(uint32_t(dirfd))!=kGuestAtFdcwd){
   r.reason=Reason::UnknownDirfd;return r;
 }
 r.path=carx_r3d33::capture_guest_owned_path(
      guestPathPointer,guestReadable);
 if(r.path.status!=carx_r3d33::PathStatus::Okay) {
   r.reason=Reason::InvalidSource;return r;
 }
 if(r.path.path[0]!='/'){
   r.reason=Reason::RelativeCwdUnproven;return r;
 }
 const auto result=carx_r3d41::open_guest_readonly(
      verifiedGuestRootFd,r.path.path,true);
 r.hops=result.symlinks;
 switch(result.status) {
   case carx_r3d41::Status::Exists:
     r.handled=true;r.value=0;r.reason=Reason::Ok;return r;
   case carx_r3d41::Status::Opened:
     // negative errno from source-verified jailed fstatat/openat walk;
     // notably ENOENT and ENOTDIR are valid Linux F_OK results.
     if(result.negativeErrno>=0) {
       r.reason=Reason::OtherLookupError;return r;
     }
     r.handled=true;
     r.value=result.negativeErrno;
     r.reason=(r.value==-ENOENT)?Reason::NoFile:Reason::OtherLookupError;
     return r;
   case carx_r3d41::Status::UnresolvedSymlink:
     r.reason=Reason::SymlinkLoop;return r;
   case carx_r3d41::Status::Unsafe:
     r.reason=Reason::UnsafePath;return r;
   case carx_r3d41::Status::HostError:
   case carx_r3d41::Status::NotRegular:
     r.reason=Reason::SourceRootInvalid;return r;
 }
 return r;
}
// Only source-owned printable ASCII is hex-encoded. No host paths, no guest
// dereference, no raw memory content beyond the proven 48 path bytes.
inline void path_hex_marker(const carx_r3d33::PathCapture& path,
                            char (&out)[144]) noexcept {
 std::memset(out,0,sizeof(out));
 const int prefix=std::snprintf(out,sizeof(out),
      "N65_R3D42_FACCESSAT2_GUEST_PATH_HEX_");
 if(prefix<0||size_t(prefix)>=sizeof(out))return;
 const size_t limit=path.size<48?path.size:48;
 constexpr char hex[]="0123456789ABCDEF";
 size_t pos=size_t(prefix);
 for(size_t i=0;i<limit && pos+2<sizeof(out);++i) {
   const unsigned char b=static_cast<unsigned char>(path.path[i]);
   out[pos++]=hex[b>>4];out[pos++]=hex[b&15];
 }
 out[pos]='\0';
}
} // namespace carx_r3d42
