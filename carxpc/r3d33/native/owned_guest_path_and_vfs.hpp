// SPDX-License-Identifier: MIT
// R3D33: source-authenticated x86 guest openat path from owned guest VM.
//
// Real R3D32 phone: 80 preflight successes, getrandom(318) accepted,
// brk(12) created writable x86 guest heap, then original GNU ld.so
// openat(257) path pointer 0x7382E00310 (guest brk heap, NOT guest stack).
// This reads ONLY explicitly proved owned/readable guest stack, source-owned
// mmap pages, or committed brk data. NO arbitrary host memory probing,
// process_vm_readv, /proc/self/mem, or Android absolute path forwarding.
// The rootfs files are opened ONLY via pre-opened app-private rootfd with
// O_NOFOLLOW on every component. Unknown symlinks fail closed for now.
// Generic read-only guest VFS FD 101..116 supports openat/read/pread64,
// fstat(144 bytes)/lseek/close while real executable mmap provenance stays
// strictly unimplemented for new fd sources (never synthesize ELF proof).
#pragma once
#include "carxpc/r3d19/native/unified_guest_libc_abi.hpp"
#include <array>
#include <cstdint>
#include <cstddef>
#include <climits>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
namespace carx_r3d33 {
constexpr size_t kMaxPath=255;
enum class PathStatus:uint8_t {Okay,Unowned,InvalidAscii,TooLong};
struct PathCapture {
 PathStatus status{PathStatus::Unowned};
 char path[kMaxPath+1]{};
 size_t size{0};
};
template<class Readable>
inline PathCapture capture_guest_owned_path(uint64_t addr,Readable readable)
noexcept{
 PathCapture v{};
 if(!addr || addr>UINT64_MAX-kMaxPath)return v;
 for(size_t i=0;i<=kMaxPath;++i){
   if(!readable(addr+i,1))return v;
   char c=0;
   std::memcpy(&c,
      reinterpret_cast<const void*>(static_cast<uintptr_t>(addr+i)),1);
   if(c=='\0'){
     if(i==0){v.status=PathStatus::InvalidAscii;return v;}
     v.size=i;v.status=PathStatus::Okay;return v;
   }
   if(static_cast<unsigned char>(c)<0x20 ||
      static_cast<unsigned char>(c)>0x7e){
       v.status=PathStatus::InvalidAscii;return v;
   }
   if(i==kMaxPath){v.status=PathStatus::TooLong;return v;}
   v.path[i]=c;
 }
 v.status=PathStatus::TooLong;return v;
}
inline bool brk_readable(uint64_t ptr,uint64_t bytes,
         uint64_t base,uint64_t current)noexcept{
 return bytes && base && current>base && ptr>=base &&
    ptr<current && bytes<=current-ptr;
}
enum class OpenState:uint8_t {
 Resolved,UntrustedRoot,UnsafePath,UnresolvedSymlink,NotRegular,TableFull,HostError
};
struct OpenResult {
 OpenState state{OpenState::UnsafePath};
 int64_t value{0};
};
class ReadOnlyFiles final {
 struct File {
  int nativeFd{-1};
  uint64_t position{0};
 };
 std::array<File,16> files{};
 static constexpr int kFirstGuestFd=101;
 int findFd(uint64_t fd)const noexcept{
   if(fd<kFirstGuestFd || fd>=kFirstGuestFd+files.size())return -1;
   const int slot=static_cast<int>(fd-kFirstGuestFd);
   return files[slot].nativeFd>=0 ? slot : -1;
 }
 public:
  ReadOnlyFiles()=default;
  ReadOnlyFiles(const ReadOnlyFiles&)=delete;
  ReadOnlyFiles& operator=(const ReadOnlyFiles&)=delete;
  ~ReadOnlyFiles(){
   for(auto& f:files)if(f.nativeFd>=0)::close(f.nativeFd);
  }
  bool owns(uint64_t fd)const noexcept {return findFd(fd)>=0;}
  // The rootfd is separately opened by Android from a source-verified,
  // app-private rootfs and passed into this isolated guest-worker JNI.
  OpenResult open_guest_file(int rootfd,const char* path)noexcept {
   if(!path||path[0]!='/')return {OpenState::UnsafePath,0};
   // Preserve the original source-diagnostic guest cacheless policy:
   // /etc/ld.so.cache physically exists in Android app rootfs but must
   // NEVER be exposed to original GNU ld.so for this isolated boot probe.
   if(std::strcmp(path,"/etc/ld.so.cache")==0)
     return {OpenState::Resolved,-ENOENT};
   const size_t len=::strnlen(path,kMaxPath+2);
   if(len==0||len>kMaxPath)return {OpenState::UnsafePath,0};
   struct stat rootstat{};
   if(rootfd<0||::fstat(rootfd,&rootstat)!=0||!S_ISDIR(rootstat.st_mode))
     return {OpenState::UntrustedRoot,0};
   if(len==1)return {OpenState::NotRegular,0};
   int dir=::fcntl(rootfd,F_DUPFD_CLOEXEC,3);
   if(dir<0)return {OpenState::HostError,0};
   size_t start=1;
   while(start<len){
     size_t end=start;
     while(end<len&&path[end]!='/')++end;
     const auto count=end-start;
     if(count==0||count>255){
       ::close(dir);return {OpenState::UnsafePath,0};
     }
     char component[256]{};
     std::memcpy(component,path+start,count);
     if(std::strcmp(component,".")==0||
        std::strcmp(component,"..")==0){
       ::close(dir);return {OpenState::UnsafePath,0};
     }
     const bool final=end==len;
     struct stat st{};
     if(::fstatat(dir,component,&st,AT_SYMLINK_NOFOLLOW)!=0){
       const int e=errno;::close(dir);
       return {OpenState::Resolved,-int64_t(e)};
     }
     if(S_ISLNK(st.st_mode)){
       ::close(dir);return {OpenState::UnresolvedSymlink,0};
     }
     if(!final){
       if(!S_ISDIR(st.st_mode)){
         ::close(dir);return {OpenState::Resolved,-ENOTDIR};
       }
       int next=::openat(dir,component,
            O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
       if(next<0){
         const int e=errno;::close(dir);
         return {OpenState::Resolved,-int64_t(e)};
       }
       ::close(dir);dir=next;start=end+1;continue;
     }
     if(!S_ISREG(st.st_mode)&&!S_ISDIR(st.st_mode)){
       ::close(dir);return {OpenState::NotRegular,0};
     }
     if(st.st_size<0||
        (S_ISREG(st.st_mode)&&uint64_t(st.st_size) >
             carx_r3d19::kMaxTotalMapBytes)){
        ::close(dir);return {OpenState::NotRegular,0};
     }
     const int nativeFd=::openat(dir,component,
         O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
     const int savedErr=errno;
     ::close(dir);
     if(nativeFd<0)return {OpenState::Resolved,-int64_t(savedErr)};
     struct stat after{};
     if(::fstat(nativeFd,&after)!=0 ||
        (S_ISREG(st.st_mode)&&!S_ISREG(after.st_mode)) ||
        (S_ISDIR(st.st_mode)&&!S_ISDIR(after.st_mode)) ||
        st.st_dev!=after.st_dev||st.st_ino!=after.st_ino){
       ::close(nativeFd);return {OpenState::HostError,0};
     }
     for(size_t slot=0;slot<files.size();++slot)
       if(files[slot].nativeFd<0){
         files[slot].nativeFd=nativeFd;files[slot].position=0;
         return {OpenState::Resolved,
                     int64_t(kFirstGuestFd+static_cast<int>(slot))};
       }
     ::close(nativeFd);return {OpenState::TableFull,0};
   }
   ::close(dir);return {OpenState::UnsafePath,0};
  }
  int64_t close_guest(uint64_t fd) noexcept {
   int slot=findFd(fd);if(slot<0)return -EBADF;
   const int n=files[slot].nativeFd;
   files[slot]={};files[slot].nativeFd=-1;
   return ::close(n)==0?0:-int64_t(errno);
  }
  template<class Writable>
  int64_t pread_guest(uint64_t fd,uint64_t dst,uint64_t length,
                uint64_t offset,Writable canWrite) noexcept {
   int slot=findFd(fd);if(slot<0)return -EBADF;
   if(length>4096||offset>INT64_MAX)return -EINVAL;
   if(length==0)return 0;
   if(!canWrite(dst,length))return -EFAULT;
   unsigned char local[4096]{};
   const ssize_t n=::pread(files[slot].nativeFd,local,
                       static_cast<size_t>(length),
                       static_cast<off_t>(offset));
   if(n<0)return -int64_t(errno);
   if(n>0)std::memcpy(
       reinterpret_cast<void*>(static_cast<uintptr_t>(dst)),
       local,static_cast<size_t>(n));
   return int64_t(n);
  }
  template<class Writable>
  int64_t read_guest(uint64_t fd,uint64_t dst,uint64_t length,
                     Writable canWrite) noexcept {
   int slot=findFd(fd);if(slot<0)return -EBADF;
   const int64_t n=pread_guest(fd,dst,length,files[slot].position,canWrite);
   if(n>0)files[slot].position+=uint64_t(n);
   return n;
  }
  int64_t lseek_guest(uint64_t fd,uint64_t offset,uint64_t whence)noexcept{
   int slot=findFd(fd);if(slot<0)return -EBADF;
   int64_t base=0;
   if(whence==1)base=static_cast<int64_t>(files[slot].position);
   else if(whence==2){
     struct stat st{};
     if(::fstat(files[slot].nativeFd,&st)!=0)return -int64_t(errno);
     if(st.st_size<0)return -EINVAL;
     base=static_cast<int64_t>(st.st_size);
   }else if(whence!=0)return -EINVAL;
   const int64_t signedOff=static_cast<int64_t>(offset);
   if((signedOff>0&&base>INT64_MAX-signedOff)||
      (signedOff<0&&base<INT64_MIN-signedOff))return -EINVAL;
   const int64_t next=base+signedOff;
   if(next<0)return -EINVAL;
   files[slot].position=uint64_t(next);
   return next;
  }
  template<class Writable>
  int64_t fstat_guest(uint64_t fd,uint64_t dst,Writable canWrite)noexcept{
   int slot=findFd(fd);if(slot<0)return -EBADF;
   if(!canWrite(dst,sizeof(carx_r3d19::LinuxX64Stat)))return -EFAULT;
   struct stat st{};
   if(::fstat(files[slot].nativeFd,&st)!=0)return -int64_t(errno);
   carx_r3d19::LinuxX64Stat x{};
   x.dev=uint64_t(st.st_dev);x.ino=uint64_t(st.st_ino);
   x.nlink=uint64_t(st.st_nlink);x.mode=uint32_t(st.st_mode);
   x.uid=uint32_t(st.st_uid);x.gid=uint32_t(st.st_gid);
   x.rdev=uint64_t(st.st_rdev);x.size=int64_t(st.st_size);
   x.blksize=int64_t(st.st_blksize);x.blocks=int64_t(st.st_blocks);
   x.atime_sec=st.st_atim.tv_sec;x.atime_nsec=st.st_atim.tv_nsec;
   x.mtime_sec=st.st_mtim.tv_sec;x.mtime_nsec=st.st_mtim.tv_nsec;
   x.ctime_sec=st.st_ctim.tv_sec;x.ctime_nsec=st.st_ctim.tv_nsec;
   std::memcpy(reinterpret_cast<void*>(static_cast<uintptr_t>(dst)),&x,sizeof(x));
   return 0;
  }
};
} // namespace carx_r3d33
