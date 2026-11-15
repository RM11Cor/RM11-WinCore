// SPDX-License-Identifier: MIT
// R3D30: source-owned Wine rootfs guest readlink VFS, not a host path bridge.
// RootfsFD is an app-private verified ROOTFS directory preopened by Java,
// and ALL resolution uses no-follow openat/fstatat relative to that fd.
// Never forward an unbounded guest pointer or path to Android host syscalls.
// Reject intermediate symlinks until a confined safe resolver is implemented.
#pragma once
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cerrno>
#include <algorithm>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
namespace carx_r3d30 {
constexpr uint64_t kMaxGuestReadlink=4096;
enum class Status : uint8_t {Resolved,UntrustedRoot,InvalidGuestPath,
    InvalidGuestOutput,IntermediateSymlink,HostIOError};
struct Result {Status status{Status::InvalidGuestPath};int64_t value{0};};
inline bool guest_writable(uint64_t addr,uint64_t count,
                            uint64_t low,uint64_t high)noexcept {
 return low&&high>low&&high-low==65536&&count>0&&
        count<=kMaxGuestReadlink&&addr>=low&&addr<high&&count<=high-addr;
}
inline bool parse_absolute_path(const char* path,size_t& length)noexcept {
 if(!path||path[0]!='/')return false;
 length=::strnlen(path,4097);
 if(length==0||length>4096)return false;
 for(size_t i=1;i<length;++i) {
   if(static_cast<unsigned char>(path[i])<32 ||
      static_cast<unsigned char>(path[i])>126)return false;
   if(path[i]=='/'&&path[i-1]=='/')return false;
 }
 return true;
}
inline Result resolve_readlink(int rootfd,const char* path,
 uint64_t guestDestination,uint64_t capacity,
 uint64_t stackLow,uint64_t stackHigh)noexcept {
 if(!guest_writable(guestDestination,capacity,stackLow,stackHigh))
   return {Status::InvalidGuestOutput,-EFAULT};
 size_t pathlen=0;
 if(!parse_absolute_path(path,pathlen))
   return {Status::InvalidGuestPath,0};
 struct stat rootstat{};
 if(rootfd<0||::fstat(rootfd,&rootstat)!=0||!S_ISDIR(rootstat.st_mode))
   return {Status::UntrustedRoot,0};
 if(pathlen==1)return {Status::Resolved,-EINVAL};
 int current=::fcntl(rootfd,F_DUPFD_CLOEXEC,3);
 if(current<0)return {Status::HostIOError,0};
 char component[256]{};
 size_t from=1;
 auto finish=[&](Status status,int64_t value)->Result{
   ::close(current);return {status,value};
 };
 while(from<pathlen){
   size_t until=from;
   while(until<pathlen&&path[until]!='/')++until;
   const size_t n=until-from;
   if(n==0){if(until==pathlen-1)break;
     return finish(Status::InvalidGuestPath,0);}
   if(n>=sizeof(component))return finish(Status::InvalidGuestPath,0);
   std::memcpy(component,path+from,n);component[n]='\0';
   if(std::strcmp(component,".")==0||
      std::strcmp(component,"..")==0)
     return finish(Status::InvalidGuestPath,0);
   const bool final=until>=pathlen-1;
   if(!final){
     struct stat file{};
     if(::fstatat(current,component,&file,AT_SYMLINK_NOFOLLOW)!=0){
       const int e=errno;
       return finish(Status::Resolved,e==ENOENT?-ENOENT:-ENOTDIR);
     }
     if(S_ISLNK(file.st_mode))return finish(Status::IntermediateSymlink,0);
     if(!S_ISDIR(file.st_mode))
       return finish(Status::Resolved,-ENOTDIR);
     const int next=::openat(current,component,
          O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
     if(next<0)return finish(Status::HostIOError,0);
     ::close(current);current=next;from=until+1;continue;
   }
   struct stat file{};
   if(::fstatat(current,component,&file,AT_SYMLINK_NOFOLLOW)!=0){
     const int e=errno;
     return finish(Status::Resolved,e==ENOENT?-ENOENT:-ENOTDIR);
   }
   if(!S_ISLNK(file.st_mode))
     return finish(Status::Resolved,-EINVAL);
   char target[kMaxGuestReadlink]{};
   const ssize_t nread=::readlinkat(current,component,target,sizeof(target));
   if(nread<0||nread>=static_cast<ssize_t>(sizeof(target)))
     return finish(Status::HostIOError,0);
   const size_t copied=static_cast<size_t>(
       std::min<uint64_t>(static_cast<uint64_t>(nread),capacity));
   auto* dst=reinterpret_cast<char*>(static_cast<uintptr_t>(guestDestination));
   std::memcpy(dst,target,copied); // Linux readlink does NOT append NUL.
   if(std::memcmp(dst,target,copied)!=0)
     return finish(Status::HostIOError,0);
   return finish(Status::Resolved,static_cast<int64_t>(copied));
 }
 return finish(Status::Resolved,-EINVAL);
}
} // namespace carx_r3d30
