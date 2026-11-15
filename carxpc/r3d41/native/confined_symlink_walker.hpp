// SPDX-License-Identifier: MIT
// R3D41: bounded guest symlink resolution via app-private guest rootfd.
// Never use host absolute paths or follow a symlink with openat.
// Each component is fstatat(AT_SYMLINK_NOFOLLOW), opened O_NOFOLLOW.
// Relative/absolute guest symlink targets restart through the jailed walker.
// ".." may pop frames but can NEVER cross the preopened guest root.
#pragma once
#include <array>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace carx_r3d41 {
constexpr size_t kMaxSymlinkExpansions=16;
constexpr size_t kMaxExpandedPath=4096;
enum class Status:uint8_t {Opened, Unsafe, UnresolvedSymlink, NotRegular, HostError};
struct Result {
 int fd{-1};
 Status status{Status::Unsafe};
 int negativeErrno{-EINVAL};
 uint8_t reason{0};
 uint8_t symlinks{0};
};
struct Frames {
 std::array<int,64> fds{};
 size_t count{0};
 Frames()=default;
 Frames(const Frames&)=delete;
 Frames& operator=(const Frames&)=delete;
 ~Frames(){while(count) ::close(fds[--count]);}
 bool push(int fd) noexcept {
   if(count>=fds.size())return false;
   fds[count++]=fd;return true;
 }
 bool pop() noexcept {
   if(count<=1)return false;
   ::close(fds[--count]);return true;
 }
 void reset_to_root() noexcept {while(count>1)::close(fds[--count]);}
 int top()const noexcept {return fds[count-1];}
};
inline Result open_guest_readonly(int trustedRootFd,const char* guestPath) noexcept {
 if(!guestPath || guestPath[0]!='/')return {-1,Status::Unsafe,-EINVAL,1,0};
 const size_t guestLen=::strnlen(guestPath,257);
 if(!guestLen || guestLen>255)
   return {-1,Status::Unsafe,-ENAMETOOLONG,2,0};
 struct stat rst{};
 if(trustedRootFd<0 || ::fstat(trustedRootFd,&rst)!=0 ||
    !S_ISDIR(rst.st_mode))
   return {-1,Status::HostError,-EBADF,3,0};
 const int rootCopy=::fcntl(trustedRootFd,F_DUPFD_CLOEXEC,3);
 if(rootCopy<0)return {-1,Status::HostError,-errno,4,0};
 Frames frames{};
 if(!frames.push(rootCopy)){
   ::close(rootCopy);return {-1,Status::Unsafe,-E2BIG,5,0};
 }
 std::array<char,kMaxExpandedPath+1> pending{};
 std::memcpy(pending.data(),guestPath,guestLen+1);
 size_t len=guestLen,pos=0;
 uint8_t hops=0;
 while(pos<len){
   while(pos<len && pending[pos]=='/')++pos;
   if(pos>=len)break;
   size_t end=pos;
   while(end<len && pending[end]!='/')++end;
   const size_t sz=end-pos;
   if(sz==0 || sz>255)
     return {-1,Status::Unsafe,-ENAMETOOLONG,6,hops};
   char component[256]{};
   std::memcpy(component,pending.data()+pos,sz);
   size_t continuation=end;
   while(continuation<len && pending[continuation]=='/')++continuation;
   const bool last=(continuation>=len);
   if(std::strcmp(component,".")==0){pos=continuation;continue;}
   if(std::strcmp(component,"..")==0){
     if(!frames.pop())return {-1,Status::Unsafe,-EPERM,7,hops};
     pos=continuation;continue;
   }
   struct stat st{};
   if(::fstatat(frames.top(),component,&st,AT_SYMLINK_NOFOLLOW)!=0)
     return {-1,Status::Opened,-errno,0,hops};
   if(S_ISLNK(st.st_mode)){
     if(hops>=kMaxSymlinkExpansions)
       return {-1,Status::UnresolvedSymlink,-ELOOP,8,hops};
     char target[kMaxExpandedPath+1]{};
     const ssize_t n=::readlinkat(frames.top(),component,target,
                                  kMaxExpandedPath);
     if(n<=0 || size_t(n)>=kMaxExpandedPath)
       return {-1,Status::Unsafe,n<0?-errno:-ENAMETOOLONG,9,hops};
     ++hops;
     const bool absolute=target[0]=='/';
     const size_t remaining=len-continuation;
     const size_t tlen=size_t(n);
     const bool slash=(remaining>0 && target[tlen-1]!='/');
     const size_t wanted=tlen+(slash?1:0)+remaining;
     if(wanted>kMaxExpandedPath)
       return {-1,Status::Unsafe,-ENAMETOOLONG,10,hops};
     std::array<char,kMaxExpandedPath+1> next{};
     std::memcpy(next.data(),target,tlen);
     if(slash)next[tlen]='/';
     if(remaining)
       std::memcpy(next.data()+tlen+(slash?1:0),
                   pending.data()+continuation,remaining);
     pending=next;len=wanted;pos=0;
     if(absolute)frames.reset_to_root();
     continue;
   }
   if(!last){
     if(!S_ISDIR(st.st_mode))
       return {-1,Status::Opened,-ENOTDIR,0,hops};
     const int dir=::openat(frames.top(),component,
         O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK);
     if(dir<0)return {-1,Status::Opened,-errno,0,hops};
     if(!frames.push(dir)){
       ::close(dir);return {-1,Status::Unsafe,-E2BIG,11,hops};
     }
     pos=continuation;continue;
   }
   if(!S_ISREG(st.st_mode) && !S_ISDIR(st.st_mode))
     return {-1,Status::NotRegular,-EACCES,12,hops};
   if(st.st_size<0 || (S_ISREG(st.st_mode) &&
      uint64_t(st.st_size)>256ULL*1024*1024))
     return {-1,Status::NotRegular,-EFBIG,13,hops};
   const int fd=::openat(frames.top(),component,
      O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK);
   if(fd<0)return {-1,Status::Opened,-errno,0,hops};
   struct stat actual{};
   if(::fstat(fd,&actual)!=0){
     const int error=errno;::close(fd);
     return {-1,Status::HostError,-error,14,hops};
   }
   if((!S_ISREG(actual.st_mode) && !S_ISDIR(actual.st_mode)) ||
      actual.st_size<0 || (S_ISREG(actual.st_mode) &&
      uint64_t(actual.st_size)>256ULL*1024*1024)){
     ::close(fd);return {-1,Status::NotRegular,-EACCES,15,hops};
   }
   return {fd,Status::Opened,0,0,hops};
 }
 return {-1,Status::NotRegular,-EISDIR,16,hops};
}
} // namespace carx_r3d41
