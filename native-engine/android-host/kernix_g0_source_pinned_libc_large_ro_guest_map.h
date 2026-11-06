// SPDX-License-Identifier: MIT
#pragma once
// G0 experimental isolated native Linux ARM64 owner for the first genuine
// original GNU ld-linux mmap of SHA-locked libc. Not an ELF loader, not
// an Android production mapper, not an executable mapping. The original
// x86 syscall must be mmap(NULL,0x211d90,PROT_READ,
// MAP_PRIVATE|MAP_DENYWRITE,synthetic-libc-FD100,offset=0).
// Linux MAP_DENYWRITE is ignored (man-pages mmap(2)); never infer any
// other flags or grant writable/executable guest source pages.
// Source material is an immutable, SHA-256-verified in-memory snapshot.
// Beyond original libc file EOF, reserved pages remain PROT_NONE:
// intentionally fail closed instead of pretending full Linux SIGBUS-on-EOF
// semantics have been proven. Preserve separate W^X, TLS, loader gates.
#include "kernix_g2e_c1_x86_linux_syscall_boundary.h"
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <sys/mman.h>
#include <unistd.h>

namespace kernix::g0 {
class PinnedLibcLargeReadonlyGuestMap final {
 public:
  static constexpr size_t kPage=4096;
  static constexpr uint64_t kExpectedGuestLength=0x211d90ULL;
  static constexpr size_t kOriginalLibcSize=2118168;
  static constexpr uint64_t kExpectedGuestFlags=0x802ULL;
  static constexpr uint64_t kExpectedGuestFD=100;
  static constexpr size_t RoundUp(size_t n) noexcept {
    return (n+kPage-1)&~(kPage-1);
  }
  static_assert(RoundUp(kExpectedGuestLength)<4*1024*1024);
  static_assert(RoundUp(kOriginalLibcSize)<RoundUp(kExpectedGuestLength));
  struct Result {
    int64_t guestReturn=-ENOSYS;
    bool realGuestMmapAuthenticated=false;
    bool originalSourceSnapshotCopied=false;
    bool mappedOwnedGuestReadOnly=false;
    bool remainingBeyondEOFPagesInaccessible=false;
    bool noHostGuestFDOrPathForwarding=true;
    bool guestRWXEverGranted=false;
  };
  PinnedLibcLargeReadonlyGuestMap()=default;
  PinnedLibcLargeReadonlyGuestMap(const PinnedLibcLargeReadonlyGuestMap&)=delete;
  PinnedLibcLargeReadonlyGuestMap& operator=(const PinnedLibcLargeReadonlyGuestMap&)=delete;
  ~PinnedLibcLargeReadonlyGuestMap() { (void)Reset(); }
  bool Reset() noexcept {
    if(region_==MAP_FAILED)return true;
    if(::munmap(region_,length_)!=0)return false;
    region_=MAP_FAILED;
    length_=0;
    sourceBytes_=0;
    return true;
  }
  uint64_t Address() const noexcept {
    return region_==MAP_FAILED?0:reinterpret_cast<uintptr_t>(region_);
  }
  size_t BytesHeld() const noexcept {return length_;}
  size_t CopiedSourceBytes() const noexcept {return sourceBytes_;}
  const unsigned char* AuthenticatedReadonlyBytes(uint64_t address,
                                                  size_t bytes) const noexcept {
    if(region_==MAP_FAILED || bytes==0 ||
       address<Address() || bytes>RoundUp(sourceBytes_) ||
       address-Address()>RoundUp(sourceBytes_)-bytes)
      return nullptr;
    return reinterpret_cast<const unsigned char*>(
             static_cast<uintptr_t>(address));
  }
  Result Map(const kernix::g2e::c1::TrapClassification& trap,
             const uint8_t* immutableSource,
             size_t sourceLength) noexcept {
    namespace c1=kernix::g2e::c1;
    Result out{};
    if(region_!=MAP_FAILED || ::sysconf(_SC_PAGESIZE)!=4096 ||
       !immutableSource || sourceLength!=kOriginalLibcSize ||
       immutableSource[0]!=0x7f || immutableSource[1]!='E' ||
       immutableSource[2]!='L' || immutableSource[3]!='F' ||
       immutableSource[4]!=2 || immutableSource[5]!=1 ||
       !trap.trapBoundaryAuthenticated ||
       !trap.sourceRegisterMappingChecked ||
       trap.hostSyscallDispatched || trap.guestMemoryDereferenced ||
       trap.guestNumber!=c1::kMmap ||
       trap.category!=c1::CallCategory::NeedsGuestKernel ||
       trap.args[0]!=0 || trap.args[1]!=kExpectedGuestLength ||
       trap.args[2]!=PROT_READ ||
       trap.args[3]!=kExpectedGuestFlags ||
       trap.args[4]!=kExpectedGuestFD ||
       trap.args[5]!=0)
      return out;
    out.realGuestMmapAuthenticated=true;
    constexpr size_t kTotal=RoundUp(kExpectedGuestLength);
    constexpr size_t kFilePages=RoundUp(kOriginalLibcSize);
    // Let native Linux choose a new VMA; NO MAP_FIXED, never overwrite
    // main/ld-linux/libc originals, callret, guest heap, or user memory.
    constexpr std::array<uintptr_t,4> hints{{
      0x0000000804000000ULL,0x0000001004000000ULL,
      0x0000001804000000ULL,0x0000002004000000ULL}};
    void* owned=MAP_FAILED;
    for(const auto hint:hints) {
      void* attempt=::mmap(reinterpret_cast<void*>(hint),kTotal,
                           PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
      if(attempt==MAP_FAILED)continue;
      const uint64_t at=reinterpret_cast<uintptr_t>(attempt);
      if(c1::GuestRange(at,kTotal)) {
        owned=attempt;
        break;
      }
      if(::munmap(attempt,kTotal)!=0) {
        // Unexpected lost ownership must fail closed.
        out.guestReturn=-EIO;
        return out;
      }
    }
    if(owned==MAP_FAILED) {
      out.guestReturn=-ENOMEM;
      return out;
    }
    // Transient RW only for source-copy construction, never RX/WX;
    // seal the original SHA-locked bytes RO before guest execution.
    if(::mprotect(owned,kFilePages,PROT_READ|PROT_WRITE)!=0) {
      (void)::munmap(owned,kTotal);
      out.guestReturn=-EACCES;
      return out;
    }
    std::memcpy(owned,immutableSource,sourceLength);
    const bool bytewiseVerified=std::memcmp(
        owned,immutableSource,sourceLength)==0;
    if(!bytewiseVerified ||
       ::mprotect(owned,kFilePages,PROT_READ)!=0) {
      (void)::munmap(owned,kTotal);
      out.guestReturn=-EIO;
      return out;
    }
    // Remaining whole pages past the original ELF file EOF are still
    // PROT_NONE, not falsely readable anonymous source data.
    region_=owned;
    length_=kTotal;
    sourceBytes_=sourceLength;
    out.guestReturn=static_cast<int64_t>(Address());
    out.originalSourceSnapshotCopied=true;
    out.mappedOwnedGuestReadOnly=true;
    out.remainingBeyondEOFPagesInaccessible=(kTotal>kFilePages);
    return out;
  }
 private:
  void* region_=MAP_FAILED;
  size_t length_=0;
  size_t sourceBytes_=0;
};
} // namespace kernix::g0
