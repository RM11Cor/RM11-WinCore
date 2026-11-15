// SPDX-License-Identifier: MIT
// R3D19 unified, *bounded* source-witnessed GNU ld.so Linux ABI bootstrap.
//
// This is a guest-only ABI adapter, not a general syscall pass-through or
// completed Wine/Windows runtime. Dynamic mappings are owned in a private
// Android probe process, not allowed to clobber arbitrary host addresses.
// All Linux guest FD=100 reads use the real app-rootfs libc regular file.
// File-backed executable mappings are private anonymous copies with W^X.
#pragma once
#include "carxpc/r3d18/native/bounded_libc_guest_read.hpp"
#include <sys/mman.h>
#include <sys/stat.h>
#include <cerrno>
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <climits>
#include <array>
#include <memory>
#include <new>
#include <algorithm>
#include <fcntl.h>
#include <unistd.h>

namespace carx_r3d19 {
constexpr uint64_t kPage=4096;
constexpr uint64_t kMaxMapBytes=128ULL*1024ULL*1024ULL;
constexpr uint64_t kMaxTotalMapBytes=256ULL*1024ULL*1024ULL;
constexpr uint64_t kMaxLibcFile=carx_r3d17::kMaxLibcLength;
constexpr size_t kMapSlots=96;
constexpr uint64_t kLinuxMapPrivate=0x02, kLinuxMapFixed=0x10;
constexpr uint64_t kLinuxMapAnonymous=0x20, kLinuxMapDenyWrite=0x800;
constexpr uint64_t kLinuxMapNoReserve=0x4000, kLinuxMapFixedNoReplace=0x100000;
constexpr uint64_t kAllowedFlags=kLinuxMapPrivate|kLinuxMapFixed|
    kLinuxMapAnonymous|kLinuxMapDenyWrite|kLinuxMapNoReserve|
    kLinuxMapFixedNoReplace;

inline bool checked_round_page(uint64_t size,uint64_t &rounded) noexcept {
  if(!size || size>kMaxMapBytes || size>UINT64_MAX-(kPage-1))return false;
  rounded=(size+(kPage-1))&~(kPage-1);
  return rounded<=kMaxMapBytes;
}

struct LinuxX64Stat {
  uint64_t dev, ino, nlink;
  uint32_t mode, uid, gid, pad0;
  uint64_t rdev;
  int64_t size, blksize, blocks;
  int64_t atime_sec, atime_nsec;
  int64_t mtime_sec, mtime_nsec;
  int64_t ctime_sec, ctime_nsec;
  int64_t reserved[3];
};
static_assert(sizeof(LinuxX64Stat)==144,"Linux x86_64 stat ABI must be 144B");
static_assert(offsetof(LinuxX64Stat,size)==48,"x64 stat st_size offset");
static_assert(offsetof(LinuxX64Stat,mtime_sec)==88,"x64 stat mtime offset");

// Unlike read(), Linux pread64 uses the explicit 64-bit R10 offset and MUST
// NOT modify the guest read() file cursor.
inline carx_r3d18::Result pread64_verified_libc_stack(
    int hostfd,uint64_t guestfd,uint64_t dst,uint64_t len,
    uint64_t positionalOffset) noexcept {
  if(positionalOffset>kMaxLibcFile)return {};
  uint64_t independentCursor=positionalOffset;
  return carx_r3d18::read_libc_to_owned_guest_stack(
      hostfd,guestfd,dst,len,independentCursor);
}

inline bool fstat_verified_libc_to_guest_stack(
    int hostfd,uint64_t guestfd,uint64_t dst) noexcept {
  if(guestfd!=uint64_t(carx_r3d17::kGuestLibcFd) ||
     !carx_r3d18::owned_stack_write_bounds(dst,sizeof(LinuxX64Stat)) ||
     !carx_r3d17::verified_readonly_libc_fd(hostfd))return false;
  struct stat st{};
  if(::fstat(hostfd,&st)!=0)return false;
  LinuxX64Stat value{};
  value.dev=uint64_t(st.st_dev);
  value.ino=uint64_t(st.st_ino);
  value.nlink=uint64_t(st.st_nlink);
  value.mode=uint32_t(st.st_mode);
  value.uid=uint32_t(st.st_uid);
  value.gid=uint32_t(st.st_gid);
  value.rdev=uint64_t(st.st_rdev);
  value.size=int64_t(st.st_size);
  value.blksize=int64_t(st.st_blksize);
  value.blocks=int64_t(st.st_blocks);
  value.atime_sec=int64_t(st.st_atim.tv_sec);
  value.atime_nsec=int64_t(st.st_atim.tv_nsec);
  value.mtime_sec=int64_t(st.st_mtim.tv_sec);
  value.mtime_nsec=int64_t(st.st_mtim.tv_nsec);
  value.ctime_sec=int64_t(st.st_ctim.tv_sec);
  value.ctime_nsec=int64_t(st.st_ctim.tv_nsec);
  std::memcpy(reinterpret_cast<void*>(static_cast<uintptr_t>(dst)),
              &value,sizeof(value));
  return std::memcmp(reinterpret_cast<const void*>(static_cast<uintptr_t>(dst)),
                     &value,sizeof(value))==0;
}

// Verify every changed mapping belongs to our isolated guest address space.
// No host MAP_FIXED on an address not previously allocated by this manager.
class GuestMappings final {
 // Per-4KiB guest-page write permissions within the original owned host
 // reservation. Source-verified MAP_FIXED overlays and mprotect may change
 // *part* of a larger read-only reservation: a single region bool is wrong.
 // A per-page 1-byte bitmap costs at most 64 KiB at the 256 MiB cap.
 struct Region {
   uint64_t base{0},length{0};
   bool used{false};
   std::unique_ptr<uint8_t[]> pageWritable{};
 };
 std::array<Region,kMapSlots> regions{};
 uint64_t total{0};
 bool owns(uint64_t addr,uint64_t len)const noexcept {
   if(!len || addr>UINT64_MAX-len)return false;
   for(const auto &r:regions)
     if(r.used && addr>=r.base && addr-r.base<=r.length &&
        len<=r.length-(addr-r.base))return true;
   return false;
 }
 bool add(uint64_t addr,uint64_t len,bool writable) noexcept {
   if(len>kMaxTotalMapBytes-total || len%kPage!=0)return false;
   const auto count=static_cast<size_t>(len/kPage);
   auto bits=std::unique_ptr<uint8_t[]>(new(std::nothrow) uint8_t[count]);
   if(!bits)return false;
   std::memset(bits.get(),writable?1:0,count);
   for(auto &r:regions)if(!r.used){
     r.base=addr;r.length=len;r.used=true;
     r.pageWritable=std::move(bits);total+=len;return true;
   }
   return false;
 }
 // For a verified page-aligned fixed mmap or mprotect, set rights only for
 // the covered pages. The untouched pages retain their real guest rights.
 bool update_writable_pages(uint64_t addr,uint64_t rounded,bool write) noexcept{
   if(!rounded || (addr%kPage) || (rounded%kPage))return false;
   for(auto& r:regions)if(r.used && r.pageWritable &&
      addr>=r.base && addr-r.base<=r.length &&
      rounded<=r.length-(addr-r.base)){
      const auto first=static_cast<size_t>((addr-r.base)/kPage);
      const auto count=static_cast<size_t>(rounded/kPage);
      std::memset(r.pageWritable.get()+first,write?1:0,count);
      return true;
   }
   return false;
 }
public:
 bool owned_range(uint64_t addr,uint64_t len)const noexcept {
   return owns(addr,len);
 }
 // Authorize only when EVERY touched guest 4KiB page is tracked writable
 // by our original source-created host-mapping registry. Cross-page writes,
 // partial fixed overlays and read-only mprotect are all accounted for.
 bool owned_writable_range(uint64_t addr,uint64_t len)const noexcept {
   if(!len||addr>UINT64_MAX-len)return false;
   for(const auto& r:regions)if(r.used&&r.pageWritable&&
       addr>=r.base&&addr-r.base<=r.length&&
       len<=r.length-(addr-r.base)){
     const auto first=static_cast<size_t>((addr-r.base)/kPage);
     const auto last=static_cast<size_t>((addr-r.base+len-1)/kPage);
     for(auto p=first;p<=last;++p)if(r.pageWritable[p]==0)return false;
     return true;
   }
   return false;
 }
 // Real source-backed memory. Returns mmap address or negative *Linux* errno.
 int64_t map(int hostfd,bool fdOpen,uint64_t hint,uint64_t length,
             uint64_t protection,uint64_t guestFlags,uint64_t guestFd,
             uint64_t offset) noexcept {
   uint64_t rounded=0;
   if(!checked_round_page(length,rounded) || (offset&(kPage-1)))return -EINVAL;
   if((protection&~uint64_t(PROT_READ|PROT_WRITE|PROT_EXEC))!=0 ||
      ((protection&PROT_EXEC)&&(protection&PROT_WRITE)))return -EACCES;
   if((guestFlags&~kAllowedFlags)!=0 ||
      (guestFlags&kLinuxMapPrivate)==0)return -EINVAL;
   const bool fixed=(guestFlags&kLinuxMapFixed)!=0;
   const bool noReplace=(guestFlags&kLinuxMapFixedNoReplace)!=0;
   if(fixed&&noReplace)return -EINVAL;
   if((fixed||noReplace) && ((hint&(kPage-1))!=0 || !hint))return -EINVAL;
   if(fixed && !owns(hint,rounded))return -EACCES;
   const bool anonymous=(guestFlags&kLinuxMapAnonymous)!=0;
   if(!anonymous &&
      (!fdOpen || guestFd!=uint64_t(carx_r3d17::kGuestLibcFd) ||
       !carx_r3d17::verified_readonly_libc_fd(hostfd)))return -EBADF;
   if(anonymous && offset!=0)return -EINVAL;
   if(!fixed && total>kMaxTotalMapBytes-rounded)return -ENOMEM;
   int hostFlags=MAP_PRIVATE|MAP_ANONYMOUS;
   if(fixed)hostFlags|=MAP_FIXED;
#ifdef MAP_FIXED_NOREPLACE
   if(noReplace)hostFlags|=MAP_FIXED_NOREPLACE;
#else
   if(noReplace)return -ENOSYS;
#endif
   void* request=(fixed||noReplace) ?
        reinterpret_cast<void*>(static_cast<uintptr_t>(hint)):nullptr;
   // Map RW for initial copy, then restore guest's real protections using
   // mprotect. This never exposes simultaneously writable+executable memory.
   void* result=::mmap(request,static_cast<size_t>(rounded),
                       PROT_READ|PROT_WRITE,hostFlags,-1,0);
   if(result==MAP_FAILED)return -errno;
   const uint64_t base=reinterpret_cast<uintptr_t>(result);
   if(fixed&&base!=hint)return -EFAULT;
   if(!anonymous){
     unsigned char buffer[16384]{};
     uint64_t done=0;
     struct stat st{};
     if(::fstat(hostfd,&st)!=0 || st.st_size<0){
       if(!fixed)::munmap(result,rounded);
       return -EIO;
     }
     while(done<rounded && offset+done<uint64_t(st.st_size)){
       if(offset>UINT64_MAX-done){
         if(!fixed)::munmap(result,rounded);
         return -EOVERFLOW;
       }
       uint64_t remain=uint64_t(st.st_size)-(offset+done);
       size_t ask=static_cast<size_t>(std::min<uint64_t>(
          sizeof(buffer),std::min<uint64_t>(remain,rounded-done)));
       ssize_t n=::pread(hostfd,buffer,ask,static_cast<off_t>(offset+done));
       if(n<=0) {
         if(!fixed)::munmap(result,rounded);
         return -EIO;
       }
       std::memcpy(reinterpret_cast<unsigned char*>(result)+done,
                   buffer,static_cast<size_t>(n));
       done+=uint64_t(n);
     }
   }
   if(::mprotect(result,rounded,int(protection))!=0){
     int e=errno;
     if(!fixed)::munmap(result,rounded);
     return -e;
   }
   if(!fixed && !add(base,rounded,(protection&PROT_WRITE)!=0)){
     ::munmap(result,rounded);
     return -ENOMEM;
   }
   if(fixed && !update_writable_pages(
        base,rounded,(protection&PROT_WRITE)!=0))return -EFAULT;
   return static_cast<int64_t>(base);
 }
 int64_t protect(uint64_t addr,uint64_t length,uint64_t prot) noexcept {
   uint64_t rounded=0;
   if(!checked_round_page(length,rounded) || (addr&(kPage-1)))return -EINVAL;
   if((prot&~uint64_t(PROT_READ|PROT_WRITE|PROT_EXEC))!=0 ||
      ((prot&PROT_EXEC)&&(prot&PROT_WRITE)))return -EACCES;
   if(!owns(addr,rounded))return -EACCES;
   if(::mprotect(reinterpret_cast<void*>(static_cast<uintptr_t>(addr)),
         rounded,int(prot))!=0)return -errno;
   return update_writable_pages(addr,rounded,(prot&PROT_WRITE)!=0)
      ? 0 : -EFAULT;
 }
 int64_t unmap(uint64_t addr,uint64_t length) noexcept {
   uint64_t rounded=0;
   if(!checked_round_page(length,rounded) || (addr&(kPage-1)))return -EINVAL;
   // Fail closed for partial unmaps until region splitting is source-tested.
   for(auto &r:regions)if(r.used && addr==r.base && rounded==r.length){
     if(::munmap(reinterpret_cast<void*>(static_cast<uintptr_t>(addr)),
                 rounded)!=0)return -errno;
     r.used=false;r.pageWritable.reset();
     r.base=0;r.length=0;total-=rounded;
     return 0;
   }
   return -EACCES;
 }
};

inline bool grow_guest_brk(uint64_t base,uint64_t requested,
                           uint64_t& current) noexcept {
  constexpr uint64_t reserve=8ULL*1024*1024;
  if(!base || requested<base || requested>=base+reserve ||
     (current && requested<current))return false;
  const uint64_t oldEnd=current>base?((current-base+4095)&~4095ULL):0;
  const uint64_t newEnd=(requested-base+4095)&~4095ULL;
  if(newEnd>oldEnd &&
     ::mprotect(reinterpret_cast<void*>(static_cast<uintptr_t>(base+oldEnd)),
                newEnd-oldEnd,PROT_READ|PROT_WRITE)!=0)return false;
  current=requested;
  return true;
}
} // namespace carx_r3d19
