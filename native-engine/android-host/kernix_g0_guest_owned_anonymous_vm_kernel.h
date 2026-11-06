#pragma once
// SPDX-License-Identifier: MIT
// KERNIX G0 guest Linux x86_64 mmap(9)/mprotect(10)/munmap(11), getrandom(318) for REAL owned
// non-executable anonymous guest pages. No raw syscall forwarding.
// Restricted functional guest memory allocator for FEX callback wiring;
// it is not a complete ELF/ld-linux mmap, brk, file-map, TLS or RELRO service.
// Guest getrandom fills ONLY authenticated writable owner VMAs via the
// constant trusted host /dev/urandom source; never guest filename/fd/ioctl.
// mprotect is whole-OWNED-ANONYMOUS mapping only, RO <-> RW, never executable.
#include "kernix_g2e_c1_x86_linux_syscall_boundary.h"
#include <array>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <sys/stat.h>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <sys/mman.h>
#include <unistd.h>

namespace kernix::g0 {
// Without an independently enforced 4K subpage permission model, a 4K
// guest mapping on a 16K Android host page exposes 12K extra native
// writable bytes. Such mismatched requests MUST fail closed.
inline constexpr bool NativePageGuestLengthSafe(
    uint64_t requested,uint64_t hostPage) noexcept {
  return (hostPage==4096 || hostPage==16384) &&
         requested!=0 && requested%hostPage==0;
}
class BoundedGuestAnonymousVM final {
public:
  static constexpr size_t kSlots=8;
  static constexpr uint64_t kMaxGuestRequest=2*1024*1024ULL;
  static constexpr uint64_t kTotalGuestQuota=8*1024*1024ULL;
  struct Result {
    int64_t guestReturn=-38; // Guest Linux -ENOSYS by default.
    bool guestSyscallAuthenticated=false;
    bool nativeAnonymousMapCalled=false;
    bool nativeOwnedMapReleased=false;
    bool nativeOwnedMapProtectionChanged=false;
    bool guestWritableDataMapped=false;
    bool nativeTrustedEntropySourceRead=false;
    bool guestOwnedWritableEntropyFilled=false;
    bool hostAnyUntrustedSyscallForwarded=false;
  };
  BoundedGuestAnonymousVM()=default;
  BoundedGuestAnonymousVM(const BoundedGuestAnonymousVM&)=delete;
  BoundedGuestAnonymousVM& operator=(const BoundedGuestAnonymousVM&)=delete;
  ~BoundedGuestAnonymousVM(){(void)Reset();}
  bool Reset() noexcept {
    bool ok=true;
    for(auto& slot:maps_){
      if(!slot.owner)continue;
      if(::munmap(slot.owner,slot.nativeBytes)==0)slot={};
      else ok=false;
    }
    return ok;
  }
  size_t Count() const noexcept {
    size_t n=0;
    for(const auto& slot:maps_)if(slot.owner)++n;
    return n;
  }
  uint64_t AllocatedRequestedBytes() const noexcept {
    uint64_t total=0;
    for(const auto& slot:maps_)if(slot.owner)total+=slot.guestBytes;
    return total;
  }
  kernix::g2e::c1::GuestVmInterval AuthenticatedRW(
        uint64_t guestPtr,uint64_t bytes) const noexcept {
    namespace c1=kernix::g2e::c1;
    for(const auto& slot:maps_){
      if(!slot.owner)continue;
      const uint64_t first=reinterpret_cast<uintptr_t>(slot.owner);
      if(guestPtr<first || guestPtr>=first+slot.guestBytes ||
         bytes==0 || bytes>first+slot.guestBytes-guestPtr)continue;
      return {first,first+slot.guestBytes,
              (slot.protection&PROT_READ)!=0,
              (slot.protection&PROT_WRITE)!=0,false,true};
    }
    return {};
  }
  Result Dispatch(const kernix::g2e::c1::TrapClassification& trap) noexcept {
    namespace c1=kernix::g2e::c1;
    Result result{};
    if(!trap.trapBoundaryAuthenticated ||
       !trap.sourceRegisterMappingChecked ||
       trap.hostSyscallDispatched || trap.guestMemoryDereferenced)
      return result;
    if(trap.guestNumber!=c1::kMmap &&
       trap.guestNumber!=c1::kMprotect &&
       trap.guestNumber!=c1::kMunmap &&
       trap.guestNumber!=c1::kGetrandom)return result;
    result.guestSyscallAuthenticated=true;
    if(trap.guestNumber==c1::kGetrandom){
      // Linux guest ABI: getrandom(buf,len,flags), x86 number 318.
      // No guest-controlled file names, file descriptors, syscall IDs,
      // unowned addresses or host TLS are ever accepted. The host reads
      // a hardcoded kernel entropy device into native scratch and
      // commits bytes to guest ONLY after a complete successful read.
      const uint64_t dst=trap.args[0];
      const uint64_t bytes=trap.args[1];
      const uint64_t flags=trap.args[2];
      if(!bytes || bytes>256 || flags!=0){
        result.guestReturn=-22;return result;
      }
      const auto span=AuthenticatedRW(dst,bytes);
      if(!span.attested || !span.guestRead || !span.guestWrite ||
         span.guestExecute){
        result.guestReturn=-14;return result; // guest Linux EFAULT
      }
      const int fd=::open("/dev/urandom",O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
      if(fd<0){result.guestReturn=-5;return result;}
      struct stat st{};
      if(::fstat(fd,&st)!=0 || !S_ISCHR(st.st_mode)){
        (void)::close(fd);
        result.guestReturn=-5;return result;
      }
      std::array<unsigned char,256> scratch{};
      size_t completed=0;
      unsigned retries=0;
      while(completed<bytes && retries<8) {
        const ssize_t readCount=::read(fd,scratch.data()+completed,
                static_cast<size_t>(bytes)-completed);
        if(readCount<0 && errno==EINTR){++retries;continue;}
        if(readCount<=0)break;
        completed+=static_cast<size_t>(readCount);
      }
      const bool closed=(::close(fd)==0);
      if(completed!=bytes || !closed){
        result.guestReturn=-5;return result; // partial host scratch only
      }
      result.nativeTrustedEntropySourceRead=true;
      // Source-proven owned anonymous RW VMA, never original ELF.
      std::memcpy(reinterpret_cast<void*>(static_cast<uintptr_t>(dst)),
                  scratch.data(),static_cast<size_t>(bytes));
      result.guestOwnedWritableEntropyFilled=true;
      result.guestReturn=static_cast<int64_t>(bytes);
      return result;
    }
    if(trap.guestNumber==c1::kMprotect){
      // Only whole guest-owner anonymous VMAs, host-page exact,
      // and read-only or readable-writable non-executable modes.
      // This does not grant access to source ELF PT_LOAD, ld-linux
      // code, Wine, FEX JIT or unowned Android host memory.
      const auto start=trap.args[0];
      const auto length=trap.args[1];
      const auto rights=trap.args[2];
      if(!Count())return result; // old no-VM ENOSYS behavior
      if(!c1::GuestRange(start,length) ||
         start%4096 || length%4096 ||
         (rights!=PROT_READ && rights!=(PROT_READ|PROT_WRITE))){
        result.guestReturn=-22;return result;
      }
      for(auto& slot:maps_){
        if(!slot.owner ||
           reinterpret_cast<uintptr_t>(slot.owner)!=start)continue;
        if(length!=slot.guestBytes ||
           slot.nativeBytes!=slot.guestBytes ||
           !NativePageGuestLengthSafe(length,
                  static_cast<uint64_t>(::sysconf(_SC_PAGESIZE)))){
          result.guestReturn=-22;return result;
        }
        if(::mprotect(slot.owner,slot.nativeBytes,
                      static_cast<int>(rights))!=0){
          result.guestReturn=-5;return result;
        }
        slot.protection=static_cast<int>(rights);
        result.nativeOwnedMapProtectionChanged=true;
        result.guestWritableDataMapped=(rights&PROT_WRITE)!=0;
        result.guestReturn=0;return result;
      }
      result.guestReturn=-22;return result;
    }
    if(trap.guestNumber==c1::kMunmap){
      const uint64_t start=trap.args[0];
      const uint64_t len=trap.args[1];
      for(auto& slot:maps_){
        if(!slot.owner)continue;
        if(start!=reinterpret_cast<uintptr_t>(slot.owner))continue;
        // Never permit guest partial-host-page unmaps, unknown lengths,
        // alias-mapped ranges or unmapping ELF/host/JIT memory.
        if(len!=slot.guestBytes){result.guestReturn=-22;return result;}
        if(::munmap(slot.owner,slot.nativeBytes)!=0){
          result.guestReturn=-5;return result;
        }
        slot={};
        result.nativeOwnedMapReleased=true;
        result.guestReturn=0;return result;
      }
      result.guestReturn=-22;return result;
    }
    // x86 Linux mmap ABI: RDI=addr, RSI=len, RDX=prot,
    // R10=MAP_PRIVATE|MAP_ANONYMOUS, R8=-1, R9=offset.
    const auto& a=trap.args;
    if(!c1::BoundedAnonymousMmapIntent(trap) ||
       a[1]>kMaxGuestRequest){
      result.guestReturn=-22;return result;
    }
    const uint64_t current=AllocatedRequestedBytes();
    if(current>kTotalGuestQuota || a[1]>kTotalGuestQuota-current){
      result.guestReturn=-12;return result;
    }
    Slot* target=nullptr;
    size_t targetIndex=0;
    for(size_t i=0;i<maps_.size();++i){
      if(!maps_[i].owner){target=&maps_[i];targetIndex=i;break;}
    }
    if(!target){result.guestReturn=-12;return result;}
    const long page=::sysconf(_SC_PAGESIZE);
    if(page!=4096 && page!=16384) {
      result.guestReturn=-38;return result;
    }
    const uint64_t hostPage=static_cast<uint64_t>(page);
    if(!NativePageGuestLengthSafe(a[1],hostPage)) {
      // Guest 4K subpages require software page protection on 16K
      // Android hosts; never claim it without implementation.
      result.guestReturn=-38;return result; // Linux x86 -ENOSYS
    }
    if(a[1]>UINT64_MAX-(hostPage-1)) {
      result.guestReturn=-22;return result;
    }
    const uint64_t rounded=(a[1]+hostPage-1)&~(hostPage-1);
    if(rounded>static_cast<uint64_t>(
          std::numeric_limits<size_t>::max())){
      result.guestReturn=-12;return result;
    }
    // Advisory canonical addresses ONLY; NEVER MAP_FIXED. Linux/Android
    // ARM64 may instead return 52-bit host VAs. Reject those and retry
    // using multiple independent guest-canonical hints. No page is ever
    // marked executable and no existing mapping can be replaced.
    for(size_t attempt=0;attempt<8;++attempt) {
      const uintptr_t hint=0x0000000800000000ULL +
        static_cast<uintptr_t>(targetIndex)*0x01000000ULL +
        static_cast<uintptr_t>(attempt)*0x0000001000000000ULL;
      void* ptr=::mmap(reinterpret_cast<void*>(hint),
                       static_cast<size_t>(rounded),
                       PROT_READ|PROT_WRITE,
                       MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
      result.nativeAnonymousMapCalled=true;
      if(ptr==MAP_FAILED)continue;
      const auto guest=reinterpret_cast<uintptr_t>(ptr);
      if(!c1::GuestRange(guest,rounded) || guest%hostPage!=0) {
        if(::munmap(ptr,static_cast<size_t>(rounded))!=0) {
          result.guestReturn=-5;
          return result; // Fail closed, never expose unowned host VM.
        }
        continue;
      }
      *target={ptr,a[1],static_cast<size_t>(rounded)};
      result.guestReturn=static_cast<int64_t>(guest);
      result.guestWritableDataMapped=true;
      return result;
    }
    result.guestReturn=-12;
    return result;
  }
private:
  struct Slot {
    void* owner=nullptr;
    uint64_t guestBytes=0;
    size_t nativeBytes=0;
    int protection=PROT_READ|PROT_WRITE;
  };
  std::array<Slot,kSlots> maps_{};
};
} // namespace kernix::g0
