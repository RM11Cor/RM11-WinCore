// SPDX-License-Identifier: MIT
// R3D45 source-locked glibc x86_64 newfstatat(262) via app-owned guest
// rootfs. Original R3D44 phone callback index86:
//   dirfd=0xFFFFFF9C, pathname=0x73505BCD92 (guest libc-mapped),
//   statbuf=0x6FFFFFF780 (guest stack), flags=0.
// Never hand guest pointers, host-absolute paths, or raw host directory
// descriptors to syscalls. Validated guest memory and jailed symlink walker
// only; host metadata is converted to the x86_64 144-byte Linux ABI.
// Diagnostic scope: absolute paths, AT_FDCWD, flags=0. No relative CWD,
// AT_SYMLINK_NOFOLLOW or AT_EMPTY_PATH emulation without an owned witness.
#pragma once
#include "carxpc/r3d19/native/unified_guest_libc_abi.hpp"
#include "carxpc/r3d33/native/owned_guest_path_and_vfs.hpp"
#include "carxpc/r3d41/native/confined_symlink_walker.hpp"
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <sys/stat.h>
#include <unistd.h>

namespace carx_r3d45 {
constexpr uint64_t kNewfstatat=262;
constexpr uint64_t kAtFdcwdZeroExtended=0x00000000FFFFFF9CULL;
constexpr uint64_t kAtFdcwdSignExtended=0xFFFFFFFFFFFFFF9CULL;
enum class Reason:uint8_t {
  Success=0, NotNewfstatat=1, UnsupportedDirfd=2, UnsupportedFlags=3,
  UnownedOrInvalidGuestPath=4, RelativeGuestPath=5, UntrustedRoot=6,
  UnownedGuestStatDestination=7, UnsafeRootfs=8, HostMetadataError=9,
  GuestFileNotFound=10
};
struct Result {
 bool handled{false};
 int64_t value{-ENOSYS};
 Reason reason{Reason::NotNewfstatat};
 carx_r3d33::PathCapture guestPath{};
 uint8_t symlinkHops{0};
};
inline carx_r3d19::LinuxX64Stat as_x86_64_stat(
 const struct stat& st) noexcept {
 carx_r3d19::LinuxX64Stat x{};
 x.dev=uint64_t(st.st_dev);
 x.ino=uint64_t(st.st_ino);
 x.nlink=uint64_t(st.st_nlink);
 x.mode=uint32_t(st.st_mode);
 x.uid=uint32_t(st.st_uid);
 x.gid=uint32_t(st.st_gid);
 x.rdev=uint64_t(st.st_rdev);
 x.size=int64_t(st.st_size);
 x.blksize=int64_t(st.st_blksize);
 x.blocks=int64_t(st.st_blocks);
 x.atime_sec=int64_t(st.st_atim.tv_sec);
 x.atime_nsec=int64_t(st.st_atim.tv_nsec);
 x.mtime_sec=int64_t(st.st_mtim.tv_sec);
 x.mtime_nsec=int64_t(st.st_mtim.tv_nsec);
 x.ctime_sec=int64_t(st.st_ctim.tv_sec);
 x.ctime_nsec=int64_t(st.st_ctim.tv_nsec);
 return x;
}
template<class Readable,class Writable>
inline Result source_verified_newfstatat(
 uint64_t number,uint64_t guestDirFd,uint64_t guestPathAddr,
 uint64_t guestStatBuf,uint64_t guestFlags,int trustedGuestRootFd,
 Readable sourceOwnedGuestReadable,
 Writable sourceOwnedGuestWritable) noexcept {
 Result r{};
 if(number!=kNewfstatat)return r;
 r.reason=Reason::UnsupportedDirfd;
 if(guestDirFd!=kAtFdcwdZeroExtended &&
    guestDirFd!=kAtFdcwdSignExtended)return r;
 r.reason=Reason::UnsupportedFlags;
 if(guestFlags!=0)return r;
 r.guestPath=carx_r3d33::capture_guest_owned_path(
   guestPathAddr,sourceOwnedGuestReadable);
 r.reason=Reason::UnownedOrInvalidGuestPath;
 if(r.guestPath.status!=carx_r3d33::PathStatus::Okay)return r;
 r.reason=Reason::RelativeGuestPath;
 if(r.guestPath.path[0]!='/')return r;
 r.reason=Reason::UntrustedRoot;
 struct stat rootst{};
 if(trustedGuestRootFd<0 || ::fstat(trustedGuestRootFd,&rootst)!=0 ||
    !S_ISDIR(rootst.st_mode))return r;
 int fd=-1;
 if(std::strcmp(r.guestPath.path,"/")==0) {
   fd=::fcntl(trustedGuestRootFd,F_DUPFD_CLOEXEC,3);
   if(fd<0){r.reason=Reason::HostMetadataError;return r;}
 } else {
   const auto lookup=carx_r3d41::open_guest_readonly(
      trustedGuestRootFd,r.guestPath.path);
   r.symlinkHops=lookup.symlinks;
   if(lookup.fd<0){
     // ENOENT/ENOTDIR from the jailed rootfd lookup is a genuine guest
     // result; a forbidden escape/symlink cycle is never treated as absence.
     if(lookup.status==carx_r3d41::Status::Opened &&
        (lookup.negativeErrno==-ENOENT ||
         lookup.negativeErrno==-ENOTDIR)) {
       r.handled=true;
       r.value=lookup.negativeErrno;
       r.reason=Reason::GuestFileNotFound;
     } else {
       r.reason=Reason::UnsafeRootfs;
     }
     return r;
   }
   fd=lookup.fd;
 }
 struct stat metadata{};
 const int statRc=::fstat(fd,&metadata);
 const int statError=statRc<0?errno:0;
 ::close(fd);
 if(statRc!=0){r.reason=Reason::HostMetadataError;return r;}
 r.reason=Reason::UnownedGuestStatDestination;
 if(!sourceOwnedGuestWritable(guestStatBuf,
      sizeof(carx_r3d19::LinuxX64Stat)))return r;
 const auto abi=as_x86_64_stat(metadata);
 std::memcpy(reinterpret_cast<void*>(
    static_cast<uintptr_t>(guestStatBuf)),&abi,sizeof(abi));
 (void)statError;
 r.handled=true;r.value=0;r.reason=Reason::Success;
 return r;
}
inline void path_hex_marker(const carx_r3d33::PathCapture& p,
                            char (&out)[166]) noexcept {
 std::memset(out,0,sizeof(out));
 const int offset=::snprintf(out,sizeof(out),
   "N74_R3D45_GUEST_FSTATAT_PATH_HEX_");
 if(offset<0 || size_t(offset)>=sizeof(out))return;
 constexpr char hex[]="0123456789ABCDEF";
 size_t at=size_t(offset);
 const size_t count=p.size<54?p.size:54;
 for(size_t i=0;i<count && at+2<sizeof(out);i++) {
   unsigned char b=static_cast<unsigned char>(p.path[i]);
   out[at++]=hex[b>>4];out[at++]=hex[b&15];
 }
 out[at]=0;
}
} // namespace carx_r3d45
