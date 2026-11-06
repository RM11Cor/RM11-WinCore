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
#include <elf.h>
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
  static_assert(((kExpectedGuestLength+kPage-1)&~(kPage-1))<4*1024*1024);
  static_assert(((kOriginalLibcSize+kPage-1)&~(kPage-1))<
                ((kExpectedGuestLength+kPage-1)&~(kPage-1)));
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
    originalTextRXSealed_=false;
    originalReadOnlyPTLoadConfirmed_=false;
    originalWritablePTLoadConfirmed_=false;
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
  struct RXResult {
    int64_t guestReturn=-ENOSYS;
    bool originalSourceRXPTLoadValidated=false;
    bool originalBytesUnchangedAfterMapping=false;
    bool nativeOwnedReadExecuteApplied=false;
    bool noNativeMAPFIXEDOrGuestFDForwarding=true;
    bool guestWritableExecutableEverGranted=false;
  };
  // Second actual unmodified ld-linux x86 mmap:
  // addr=first-owned-base+0x28000, len=0x188000, prot=R|X,
  // flags=0x812 (MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE), fd100,
  // source file offset=0x28000. Not general MAP_FIXED support.
  // Because the first owner already holds the *identical SHA-pinned
  // source bytes* at the same file-relative addresses, a validated
  // mprotect of ONLY an original RX PT_LOAD range preserves the
  // first private mapping without clobbering unrelated native VMAs.
  RXResult PromoteOriginalLibcSourceTextRX(
      const kernix::g2e::c1::TrapClassification& trap,
      const uint8_t* immutableSource,
      size_t sourceLength) noexcept {
    namespace c1=kernix::g2e::c1;
    RXResult out{};
    constexpr uint64_t kGuestOffset=0x28000ULL;
    constexpr uint64_t kGuestLength=0x188000ULL;
    constexpr uint64_t kGuestFlags=0x812ULL;
    if(region_==MAP_FAILED || originalTextRXSealed_ ||
       sourceBytes_!=kOriginalLibcSize ||
       sourceLength!=kOriginalLibcSize || !immutableSource ||
       ::sysconf(_SC_PAGESIZE)!=4096 ||
       !trap.trapBoundaryAuthenticated || !trap.sourceRegisterMappingChecked ||
       trap.hostSyscallDispatched || trap.guestMemoryDereferenced ||
       trap.guestNumber!=c1::kMmap ||
       trap.category!=c1::CallCategory::NeedsGuestKernel ||
       trap.args[0]!=Address()+kGuestOffset ||
       trap.args[1]!=kGuestLength ||
       trap.args[2]!=(PROT_READ|PROT_EXEC) ||
       trap.args[3]!=kGuestFlags ||
       trap.args[4]!=kExpectedGuestFD ||
       trap.args[5]!=kGuestOffset ||
       kGuestOffset>length_ || kGuestLength>length_-kGuestOffset ||
       kGuestOffset>RoundUp(sourceBytes_) ||
       kGuestLength>RoundUp(sourceBytes_)-kGuestOffset)
      return out;
    // Independently derive executable source permission boundaries
    // from the original immutable x86-64 ELF PT_LOAD program headers,
    // not from the guest-provided PROT_EXEC flag alone.
    if(sourceLength<sizeof(Elf64_Ehdr))return out;
    Elf64_Ehdr elf{};
    std::memcpy(&elf,immutableSource,sizeof(elf));
    if(std::memcmp(elf.e_ident,ELFMAG,SELFMAG)!=0 ||
       elf.e_ident[EI_CLASS]!=ELFCLASS64 ||
       elf.e_ident[EI_DATA]!=ELFDATA2LSB ||
       elf.e_ident[EI_VERSION]!=EV_CURRENT ||
       elf.e_machine!=EM_X86_64 ||
       elf.e_type!=ET_DYN ||
       elf.e_phentsize!=sizeof(Elf64_Phdr) ||
       elf.e_phnum==0 || elf.e_phnum>128 ||
       elf.e_phoff>sourceLength ||
       static_cast<size_t>(elf.e_phnum)>
         (sourceLength-elf.e_phoff)/sizeof(Elf64_Phdr))
      return out;
    bool allowed=false;
    for(uint16_t i=0;i<elf.e_phnum;++i) {
      Elf64_Phdr ph{};
      std::memcpy(&ph,immutableSource+elf.e_phoff+
                  size_t(i)*sizeof(ph),sizeof(ph));
      if(ph.p_type!=PT_LOAD || ph.p_flags!=(PF_R|PF_X) ||
         ph.p_filesz==0 || ph.p_filesz>ph.p_memsz ||
         ph.p_offset>sourceLength ||
         ph.p_filesz>sourceLength-ph.p_offset ||
         (ph.p_vaddr%kPage)!=(ph.p_offset%kPage))
        continue;
      const uint64_t spanStart=ph.p_offset&~uint64_t(kPage-1);
      const uint64_t spanEnd=RoundUp(
        static_cast<size_t>(ph.p_offset+ph.p_filesz));
      if(kGuestOffset>=spanStart && kGuestOffset<=spanEnd &&
         kGuestLength<=spanEnd-kGuestOffset) {
        allowed=true;break;
      }
    }
    if(!allowed)return out;
    out.originalSourceRXPTLoadValidated=true;
    const auto nativeAt=reinterpret_cast<void*>(
      static_cast<uintptr_t>(Address()+kGuestOffset));
    if(std::memcmp(nativeAt,immutableSource+kGuestOffset,
                   static_cast<size_t>(kGuestLength))!=0)
      return out;
    out.originalBytesUnchangedAfterMapping=true;
    // The selected pages are already owned and PROT_READ, and source
    // PT_LOAD says R|X. No writable mapping, host file descriptor or
    // host MAP_FIXED is ever introduced by this promotion.
    if(::mprotect(nativeAt,static_cast<size_t>(kGuestLength),
                  PROT_READ|PROT_EXEC)!=0) {
      out.guestReturn=-EACCES;
      return out;
    }
    originalTextRXSealed_=true;
    out.nativeOwnedReadExecuteApplied=true;
    out.guestReturn=static_cast<int64_t>(Address()+kGuestOffset);
    return out;
  }
  bool OriginalSourceTextRXSealed() const noexcept {
    return originalTextRXSealed_;
  }

  struct ReadOnlyPTLoadResult {
    int64_t guestReturn=-ENOSYS;
    bool originalReadOnlyPTLoadSourceVerified=false;
    bool originalSourceContentsUnchanged=false;
    bool nativeOwnedExistingReadOnlyPagesPreserved=false;
    bool noNativeMAPFIXEDOrUntrustedHostFD=true;
    bool guestWritableExecutableEverGranted=false;
  };
  // Exact third original GNU libc mmap:
  //  addr=source-owned-base+0x1b0000; length=0x4f000
  //  PROT_READ, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE=0x812
  //  synthetic FD100, file offset=0x1b0000.
  // The first mapping already copied the immutable source bytes and
  // sealed them read-only; the second PT_LOAD RX conversion ended at
  // 0x1b0000. Prove these third segment source pages are originally
  // PF_R (not PF_X/PF_W), unchanged and still RO; do NOT blindly issue
  // host mmap(MAP_FIXED) or modify an arbitrary guest page.
  ReadOnlyPTLoadResult ConfirmOriginalLibcSourceReadOnlyPTLoad(
      const kernix::g2e::c1::TrapClassification& trap,
      const uint8_t* immutableSource,
      size_t sourceLength) noexcept {
    namespace c1=kernix::g2e::c1;
    ReadOnlyPTLoadResult out{};
    constexpr uint64_t kOffset=0x1b0000ULL;
    constexpr uint64_t kLength=0x4f000ULL;
    constexpr uint64_t kFlags=0x812ULL;
    if(region_==MAP_FAILED || !originalTextRXSealed_ ||
       originalReadOnlyPTLoadConfirmed_ ||
       sourceBytes_!=kOriginalLibcSize ||
       sourceLength!=kOriginalLibcSize || !immutableSource ||
       ::sysconf(_SC_PAGESIZE)!=4096 ||
       !trap.trapBoundaryAuthenticated ||
       !trap.sourceRegisterMappingChecked ||
       trap.hostSyscallDispatched || trap.guestMemoryDereferenced ||
       trap.guestNumber!=c1::kMmap ||
       trap.category!=c1::CallCategory::NeedsGuestKernel ||
       trap.args[0]!=Address()+kOffset ||
       trap.args[1]!=kLength ||
       trap.args[2]!=PROT_READ ||
       trap.args[3]!=kFlags ||
       trap.args[4]!=kExpectedGuestFD ||
       trap.args[5]!=kOffset ||
       kOffset>length_ || kLength>length_-kOffset ||
       kOffset>RoundUp(sourceBytes_) ||
       kLength>RoundUp(sourceBytes_)-kOffset)
      return out;
    if(sourceLength<sizeof(Elf64_Ehdr))return out;
    Elf64_Ehdr elf{};
    std::memcpy(&elf,immutableSource,sizeof(elf));
    if(std::memcmp(elf.e_ident,ELFMAG,SELFMAG)!=0 ||
       elf.e_ident[EI_CLASS]!=ELFCLASS64 ||
       elf.e_ident[EI_DATA]!=ELFDATA2LSB ||
       elf.e_ident[EI_VERSION]!=EV_CURRENT ||
       elf.e_machine!=EM_X86_64 ||
       elf.e_type!=ET_DYN ||
       elf.e_phentsize!=sizeof(Elf64_Phdr) ||
       elf.e_phnum==0 || elf.e_phnum>128 ||
       elf.e_phoff>sourceLength ||
       static_cast<size_t>(elf.e_phnum)>
         (sourceLength-elf.e_phoff)/sizeof(Elf64_Phdr))
      return out;
    bool originalPFROnly=false;
    for(uint16_t i=0;i<elf.e_phnum;++i) {
      Elf64_Phdr ph{};
      std::memcpy(&ph,immutableSource+elf.e_phoff+
                  size_t(i)*sizeof(ph),sizeof(ph));
      if(ph.p_type!=PT_LOAD || ph.p_flags!=PF_R ||
         ph.p_filesz==0 || ph.p_filesz>ph.p_memsz ||
         ph.p_offset>sourceLength ||
         ph.p_filesz>sourceLength-ph.p_offset ||
         (ph.p_offset%kPage)!=(ph.p_vaddr%kPage))
        continue;
      const uint64_t start=ph.p_offset&~uint64_t(kPage-1);
      const uint64_t stop=RoundUp(
          static_cast<size_t>(ph.p_offset+ph.p_filesz));
      if(kOffset>=start && kOffset<=stop &&
         kLength<=stop-kOffset) {
        originalPFROnly=true;break;
      }
    }
    if(!originalPFROnly)return out;
    out.originalReadOnlyPTLoadSourceVerified=true;
    if(std::memcmp(reinterpret_cast<const void*>(
            static_cast<uintptr_t>(Address()+kOffset)),
            immutableSource+kOffset,static_cast<size_t>(kLength))!=0)
      return out;
    out.originalSourceContentsUnchanged=true;
    // Page permissions are live-verified by caller using /proc/self/maps:
    // at this stage these pages are still RO, without ever being changed
    // to RW or RX, so there is no host syscall to map or reprotect them.
    originalReadOnlyPTLoadConfirmed_=true;
    out.nativeOwnedExistingReadOnlyPagesPreserved=true;
    out.guestReturn=static_cast<int64_t>(Address()+kOffset);
    return out;
  }
  bool OriginalSourceReadOnlyPTLoadConfirmed() const noexcept {
    return originalReadOnlyPTLoadConfirmed_;
  }
  struct WritablePTLoadResult {
    int64_t guestReturn=-ENOSYS;
    bool originalRWPTLoadVaddrOffsetVerified=false;
    bool fileSourceSubrangeVerified=false;
    bool nativeOwnedReadWriteApplied=false;
    bool noHostFixedMappingOrGuestFileFDForwarding=true;
    bool writableExecutableEverGranted=false;
  };
  // Real fourth original GNU ld-linux mmap:
  // destination base+0x1ff000, len=0x6000, PROT_READ|PROT_WRITE,
  // MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE=0x812, FD100,
  // source offset=0x1fe000. The source offset differs from the target
  // guest virtual address by one whole 4KiB page. Merely mprotecting
  // previously RO file-offset-identical bytes would be INCORRECT:
  // build a private writable original source-backed copy, but only for
  // an ELF PT_LOAD that is exactly PF_R|PF_W, source-file span owned,
  // never PROT_EXEC and never native MAP_FIXED.
  WritablePTLoadResult PromoteOriginalLibcSourceWritablePTLoad(
      const kernix::g2e::c1::TrapClassification& trap,
      const uint8_t* immutableSource,size_t sourceLength) noexcept {
    namespace c1=kernix::g2e::c1;
    WritablePTLoadResult out{};
    constexpr uint64_t kTargetOffset=0x1ff000ULL;
    constexpr uint64_t kFileOffset=0x1fe000ULL;
    constexpr uint64_t kLength=0x6000ULL;
    constexpr uint64_t kFlags=0x812ULL;
    if(region_==MAP_FAILED || !originalTextRXSealed_ ||
       !originalReadOnlyPTLoadConfirmed_ ||
       originalWritablePTLoadConfirmed_ ||
       sourceBytes_!=kOriginalLibcSize ||
       sourceLength!=kOriginalLibcSize || !immutableSource ||
       ::sysconf(_SC_PAGESIZE)!=4096 ||
       !trap.trapBoundaryAuthenticated ||
       !trap.sourceRegisterMappingChecked ||
       trap.hostSyscallDispatched || trap.guestMemoryDereferenced ||
       trap.guestNumber!=c1::kMmap ||
       trap.category!=c1::CallCategory::NeedsGuestKernel ||
       trap.args[0]!=Address()+kTargetOffset ||
       trap.args[1]!=kLength ||
       trap.args[2]!=(PROT_READ|PROT_WRITE) ||
       trap.args[3]!=kFlags ||
       trap.args[4]!=kExpectedGuestFD ||
       trap.args[5]!=kFileOffset ||
       kTargetOffset>length_ ||
       kLength>length_-kTargetOffset ||
       kFileOffset>sourceLength ||
       kLength>sourceLength-kFileOffset ||
       kFileOffset<=0x1b0000ULL ||
       kTargetOffset<=0x1b0000ULL)
      return out;
    if(sourceLength<sizeof(Elf64_Ehdr))return out;
    Elf64_Ehdr elf{};
    std::memcpy(&elf,immutableSource,sizeof(elf));
    if(std::memcmp(elf.e_ident,ELFMAG,SELFMAG)!=0 ||
       elf.e_ident[EI_CLASS]!=ELFCLASS64 ||
       elf.e_ident[EI_DATA]!=ELFDATA2LSB ||
       elf.e_ident[EI_VERSION]!=EV_CURRENT ||
       elf.e_machine!=EM_X86_64 || elf.e_type!=ET_DYN ||
       elf.e_phentsize!=sizeof(Elf64_Phdr) ||
       elf.e_phnum==0 || elf.e_phnum>128 ||
       elf.e_phoff>sourceLength ||
       static_cast<size_t>(elf.e_phnum)>
         (sourceLength-elf.e_phoff)/sizeof(Elf64_Phdr))
      return out;
    bool originalPF_RW=false;
    for(uint16_t i=0;i<elf.e_phnum;++i) {
      Elf64_Phdr ph{};
      std::memcpy(&ph,immutableSource+elf.e_phoff+
                  size_t(i)*sizeof(ph),sizeof(ph));
      if(ph.p_type!=PT_LOAD || ph.p_flags!=(PF_R|PF_W) ||
         ph.p_filesz==0 || ph.p_filesz>ph.p_memsz ||
         ph.p_offset>sourceLength ||
         ph.p_filesz>sourceLength-ph.p_offset ||
         (ph.p_offset%kPage)!=(ph.p_vaddr%kPage))
        continue;
      const uint64_t pageFile=ph.p_offset&~uint64_t(kPage-1);
      const uint64_t pageGuest=ph.p_vaddr&~uint64_t(kPage-1);
      if(pageFile!=kFileOffset || pageGuest!=kTargetOffset)
        continue;
      const uint64_t sourcePageEnd=RoundUp(
          static_cast<size_t>(ph.p_offset+ph.p_filesz));
      if(kFileOffset>sourcePageEnd ||
         kLength>sourcePageEnd-kFileOffset)
        continue;
      originalPF_RW=true;break;
    }
    if(!originalPF_RW)return out;
    out.originalRWPTLoadVaddrOffsetVerified=true;
    // Snapshot came from original SHA-pinned immutable ELF, and source
    // subrange exactly matches source PT_LOAD file-backed bytes.
    // It is native anonymous memory; never pass guest FD100 to host.
    const auto* src=immutableSource+kFileOffset;
    const uint64_t at=Address()+kTargetOffset;
    if(!c1::GuestRange(at,kLength))return out;
    out.fileSourceSubrangeVerified=true;
    void* target=reinterpret_cast<void*>(static_cast<uintptr_t>(at));
    if(::mprotect(target,static_cast<size_t>(kLength),
                  PROT_READ|PROT_WRITE)!=0) {
      out.guestReturn=-EACCES;
      return out;
    }
    std::memcpy(target,src,static_cast<size_t>(kLength));
    if(std::memcmp(target,src,static_cast<size_t>(kLength))!=0) {
      // Fail closed: even the transient RW VMA remains non-executable.
      out.guestReturn=-EIO;
      return out;
    }
    originalWritablePTLoadConfirmed_=true;
    out.nativeOwnedReadWriteApplied=true;
    out.guestReturn=static_cast<int64_t>(at);
    return out;
  }
  bool OriginalSourceWritablePTLoadConfirmed() const noexcept {
    return originalWritablePTLoadConfirmed_;
  }
 private:
  void* region_=MAP_FAILED;
  size_t length_=0;
  size_t sourceBytes_=0;
  bool originalTextRXSealed_=false;
  bool originalReadOnlyPTLoadConfirmed_=false;
  bool originalWritablePTLoadConfirmed_=false;
};
} // namespace kernix::g0
