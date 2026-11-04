#pragma once
// SPDX-License-Identifier: MIT
// KERNIX G2-E/C3-D7B: rebase original authenticated Linux x86_64 ET_DYN
// main / ld-linux / libc and startup stack to OS-chosen native 4K regions.
// Guest numerical VAs equal bounded native host-owned VAs in this independent
// data-only experiment. No MAP_FIXED, PROT_EXEC, FEX, relocations, Wine.
// Not the historical high 0x5555/0x7fff guest fixtures or a final loader.
#include "kernix_g2e_pinned_glibc_preflight.h"
#include "kernix_g2b_guest_launch_plan.h"
#include "kernix_g2e_c1_x86_linux_syscall_boundary.h"
#include <algorithm>
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <elf.h>
#include <limits>
#include <string>
#include <sys/mman.h>
#include <unistd.h>
#include <vector>

namespace kernix::g2e::c3d7b {
inline constexpr size_t kImageCapacity=8*1024*1024;
inline constexpr size_t kStackCapacity=64*1024;
inline constexpr size_t kPagesize=4096;
enum class Phase : uint8_t {
  NotStarted, WrongKernelPage, VerifyOriginals, ParsePIE,
  ReserveHostSelectedGuestVAs, GenerateAuxvAndStack,
  CopyOriginalSegments, SealReadOnly, VerifySourceBytes,
  Complete, CleanupFailed
};
inline const char* PhaseName(Phase p) noexcept {
  switch(p) {
    case Phase::NotStarted:return "NOT_STARTED";
    case Phase::WrongKernelPage:return "WRONG_KERNEL_PAGE";
    case Phase::VerifyOriginals:return "VERIFY_ORIGINALS";
    case Phase::ParsePIE:return "PARSE_ORIGINAL_ET_DYN";
    case Phase::ReserveHostSelectedGuestVAs:return "RESERVE_HOST_CHOSEN_VAS";
    case Phase::GenerateAuxvAndStack:return "REBASE_ORIGINAL_AUXV_STACK";
    case Phase::CopyOriginalSegments:return "COPY_ORIGINAL_ELF_PT_LOAD";
    case Phase::SealReadOnly:return "SEAL_SOURCE_PAGES_RO";
    case Phase::VerifySourceBytes:return "VERIFY_ALL_SOURCE_BYTES";
    case Phase::Complete:return "COMPLETE";
    case Phase::CleanupFailed:return "CLEANUP_FAILED";
  }
  return "UNKNOWN";
}
struct Witness {
  Phase phase=Phase::NotStarted;
  size_t imagesVerified=0;
  size_t windowsReserved=0;
  size_t windowsReleasedOnFailure=0;
  size_t originalSegmentsCompared=0;
  int failureErrno=0;
  uint64_t originalInterpreterRebasedRIP=0;
  uint64_t mainRebasedEntry=0;
  uint64_t x86RebasedStackRSP=0;
  bool pinnedOriginalELFSHA256Verified=false;
  bool actualNativeKernel4K=false;
  bool guestAddressEqualsOwnedHostPage=false;
  bool linuxAuxvRebased=false;
  bool originalBytesCopiedReadOnly=false;
  bool originalELFCodeExecuted=false;
  bool originalLdsoExecuted=false;
  bool originalFEXGuestMemoryAttached=false;
  bool nativeExecutablePageGranted=false;
  bool androidDeviceTested=false;
};
struct ImageMeta {
  uint64_t lowestAlignedELFVA=0;
  uint64_t highestAlignedELFVA=0;
  uint64_t chosenImageStart=0;
  uint64_t loadBias=0;
  size_t loadSegments=0;
};
class NativeChosenPIEGuestLayout final {
  struct Region {
    void* ptr=MAP_FAILED;
    size_t length=0;
  };
  std::array<Region,4> regions_{};
  std::array<ImageMeta,3> metadata_{};
  g2b::X86GuestProcessLaunchPlan plan_{};
  bool validated_=false;
  static bool Span(uint64_t start,size_t bytes) noexcept {
    return c1::GuestRange(start,bytes) && start%kPagesize==0;
  }
  bool Owns(int idx) const noexcept {
    return idx>=0 && idx<4 && regions_[idx].ptr!=MAP_FAILED;
  }
  static bool ParseOriginalPIE(const unsigned char* raw,size_t size,
                                ImageMeta& out) noexcept {
    out={};
    if(!raw || size<sizeof(Elf64_Ehdr))return false;
    Elf64_Ehdr eh{};
    std::memcpy(&eh,raw,sizeof(eh));
    if(!g2b::GuestElfHeader(eh) || eh.e_type!=ET_DYN ||
       eh.e_machine!=EM_X86_64 ||
       eh.e_phentsize!=sizeof(Elf64_Phdr) ||
       eh.e_phnum==0 || eh.e_phnum>128 ||
       !g2b::ElfRange(eh.e_phoff,
                      uint64_t(eh.e_phnum)*sizeof(Elf64_Phdr),size))
      return false;
    uint64_t min=UINT64_MAX,max=0;
    size_t count=0;
    for(uint16_t i=0;i<eh.e_phnum;++i) {
      Elf64_Phdr ph{};
      std::memcpy(&ph,raw+eh.e_phoff+size_t(i)*sizeof(ph),sizeof(ph));
      if(ph.p_type!=PT_LOAD || ph.p_memsz==0)continue;
      if(ph.p_filesz>ph.p_memsz ||
         !g2b::ElfRange(ph.p_offset,ph.p_filesz,size) ||
         ph.p_vaddr>UINT64_MAX-ph.p_memsz ||
         (ph.p_flags&(PF_W|PF_X))==(PF_W|PF_X))return false;
      const uint64_t begin=ph.p_vaddr&~uint64_t(4095);
      const uint64_t limit=ph.p_vaddr+ph.p_memsz;
      if(limit>UINT64_MAX-4095)return false;
      const uint64_t past=(limit+4095)&~uint64_t(4095);
      min=std::min(min,begin);
      max=std::max(max,past);
      ++count;
    }
    if(!count || max<=min || max-min>kImageCapacity)return false;
    out.lowestAlignedELFVA=min;
    out.highestAlignedELFVA=max;
    out.loadSegments=count;
    return true;
  }
  bool CopyAndCompareImage(int idx,
       const unsigned char* raw,size_t size,
       size_t& segmentsCompared) noexcept {
    const auto& meta=metadata_[idx];
    if(!Owns(idx) || !raw || size<sizeof(Elf64_Ehdr))return false;
    Elf64_Ehdr eh{};
    std::memcpy(&eh,raw,sizeof(eh));
    auto* dest=static_cast<unsigned char*>(regions_[idx].ptr);
    for(uint16_t i=0;i<eh.e_phnum;++i) {
      Elf64_Phdr ph{};
      std::memcpy(&ph,raw+eh.e_phoff+size_t(i)*sizeof(ph),sizeof(ph));
      if(ph.p_type!=PT_LOAD || ph.p_memsz==0)continue;
      if(ph.p_vaddr<meta.lowestAlignedELFVA ||
         ph.p_memsz>kImageCapacity-(ph.p_vaddr-meta.lowestAlignedELFVA) ||
         ph.p_filesz>ph.p_memsz ||
         !g2b::ElfRange(ph.p_offset,ph.p_filesz,size))
        return false;
      const size_t offset=static_cast<size_t>(
          ph.p_vaddr-meta.lowestAlignedELFVA);
      std::memcpy(dest+offset,raw+ph.p_offset,ph.p_filesz);
      if(std::memcmp(dest+offset,raw+ph.p_offset,ph.p_filesz)!=0)
        return false;
      // MAP_ANONYMOUS begins zeroed; assert BSS was not inadvertently
      // overwritten. ELF PT_LOAD segments in this fixture are nonoverlap.
      for(size_t j=ph.p_filesz;j<ph.p_memsz;++j)
        if(dest[offset+j]!=0)return false;
      ++segmentsCompared;
    }
    return true;
  }
public:
  NativeChosenPIEGuestLayout()=default;
  NativeChosenPIEGuestLayout(const NativeChosenPIEGuestLayout&)=delete;
  NativeChosenPIEGuestLayout& operator=(const NativeChosenPIEGuestLayout&)=delete;
  ~NativeChosenPIEGuestLayout(){Release();}
  bool Release() noexcept {
    bool allReleased=true;
    for(auto& region:regions_) {
      if(region.ptr!=MAP_FAILED) {
        if(::munmap(region.ptr,region.length)==0) {
          region.ptr=MAP_FAILED;region.length=0;
        } else allReleased=false;
      }
    }
    if(allReleased) {
      validated_=false;
      metadata_={};
      plan_={};
    }
    return allReleased;
  }
  size_t WindowsHeld() const noexcept {
    size_t held=0;
    for(const auto& r:regions_)if(r.ptr!=MAP_FAILED)++held;
    return held;
  }
  const ImageMeta* Module(size_t idx) const noexcept {
    return validated_ && idx<3 ? &metadata_[idx] : nullptr;
  }
  const g2b::X86GuestProcessLaunchPlan* LaunchPlan() const noexcept {
    return validated_ ? &plan_ : nullptr;
  }
  const unsigned char* GuestReadOnlyBytes(
      size_t idx,uint64_t guestVA,size_t bytes) const noexcept {
    if(!validated_ || idx>=3 || !bytes || bytes>kImageCapacity ||
       !Owns(static_cast<int>(idx)))return nullptr;
    const auto& r=regions_[idx];
    const auto begin=reinterpret_cast<uintptr_t>(r.ptr);
    if(guestVA<begin || bytes>r.length ||
       guestVA-begin>r.length-bytes)return nullptr;
    return static_cast<const unsigned char*>(r.ptr)+(guestVA-begin);
  }
  bool Stage(int privateRootFd,const std::array<uint8_t,16>& entropy,
             Witness& w,size_t faultAfterReservations=4) noexcept {
    w={};
    if(WindowsHeld()!=0 || privateRootFd<0) {
      w.failureErrno=EINVAL;return false;
    }
    w.phase=Phase::WrongKernelPage;
    w.actualNativeKernel4K=(::sysconf(_SC_PAGESIZE)==4096);
    if(!w.actualNativeKernel4K) {
      w.failureErrno=ENOTSUP;return false;
    }
    try {
      w.phase=Phase::VerifyOriginals;
      GuestPreflight pinned;
      std::string why;
      if(!Validate(privateRootFd,pinned,why)) {
        w.failureErrno=ENOEXEC;return false;
      }
      w.pinnedOriginalELFSHA256Verified=true;
      w.phase=Phase::ParsePIE;
      for(size_t i=0;i<3;++i) {
        const auto& snap=pinned.snapshots[i];
        if(!snap.readOnlySnapshot() ||
           !ParseOriginalPIE(snap.bytes(),snap.size(),metadata_[i])) {
          w.failureErrno=ENOEXEC;return false;
        }
        ++w.imagesVerified;
      }
      w.phase=Phase::ReserveHostSelectedGuestVAs;
      for(size_t i=0;i<4;++i) {
        if(i>=faultAfterReservations) {
          w.failureErrno=ECANCELED;
          const size_t before=WindowsHeld();
          if(!Release())w.phase=Phase::CleanupFailed;
          w.windowsReleasedOnFailure=before-WindowsHeld();
          return false;
        }
        const size_t n=(i==3)?kStackCapacity:kImageCapacity;
        // Native ARM64 kernels may choose user VAs > 47 bits for a
        // null hint. Such host VAs are not canonical x86-64 guest VAs.
        // Non-fixed hints are suggestions only. The kernel still owns
        // allocation and can return another address: revalidate it.
        // Keep every attempted VMA bounded; never overwrite any mapping.
        constexpr std::array<uintptr_t,4> safeHints{
          0x0000000800000000ULL, // 32GiB
          0x0000001000000000ULL, // 64GiB
          0x0000001800000000ULL, // 96GiB
          0x0000002000000000ULL  // 128GiB
        };
        void* selected=MAP_FAILED;
        int lastFailure=ERANGE;
        for(size_t attempt=0;attempt<safeHints.size();++attempt) {
          const uintptr_t hint=
              safeHints[attempt]+i*0x01000000ULL;
          errno=0;
          void* candidate=::mmap(
              reinterpret_cast<void*>(hint),n,PROT_NONE,
              MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
          if(candidate==MAP_FAILED) {
            lastFailure=errno;
            continue;
          }
          const uint64_t actual=reinterpret_cast<uintptr_t>(candidate);
          if(Span(actual,n)) {
            selected=candidate;
            break;
          }
          // Abort the whole operation if unexpected VMA cleanup fails.
          if(::munmap(candidate,n)!=0) {
            regions_[i]={candidate,n};
            ++w.windowsReserved;
            w.failureErrno=EBUSY;
            const size_t before=WindowsHeld();
            if(!Release())w.phase=Phase::CleanupFailed;
            w.windowsReleasedOnFailure=before-WindowsHeld();
            return false;
          }
          lastFailure=ERANGE;
        }
        if(selected==MAP_FAILED) {
          w.failureErrno=lastFailure;
          const size_t before=WindowsHeld();
          if(!Release())w.phase=Phase::CleanupFailed;
          w.windowsReleasedOnFailure=before-WindowsHeld();
          return false;
        }
        regions_[i]={selected,n};
        ++w.windowsReserved;
        const auto va=reinterpret_cast<uintptr_t>(selected);
        if(i<3) {
          metadata_[i].chosenImageStart=va;
          if(va<metadata_[i].lowestAlignedELFVA) {
            w.failureErrno=ERANGE;
            const size_t before=WindowsHeld();
            if(!Release())w.phase=Phase::CleanupFailed;
            w.windowsReleasedOnFailure=before-WindowsHeld();
            return false;
          }
          metadata_[i].loadBias=
              va-metadata_[i].lowestAlignedELFVA;
        }
      }
      w.guestAddressEqualsOwnedHostPage=true;
      w.phase=Phase::GenerateAuxvAndStack;
      const auto fetch=[&pinned](std::string_view name,
                                  std::vector<unsigned char>& bytes)->bool {
        bytes.clear();
        for(size_t i=0;i<kGuest.size();++i) {
          if(name!=kGuest[i].path)continue;
          const auto& image=pinned.snapshots[i];
          if(!image.readOnlySnapshot() || !image.bytes() ||
             image.size()!=kGuest[i].bytes)return false;
          bytes.assign(image.bytes(),image.bytes()+image.size());
          return true;
        }
        return false;
      };
      g2b::X86GuestProcessAddresses a{};
      a.mainImageStart=metadata_[0].chosenImageStart;
      a.interpreterImageStart=metadata_[1].chosenImageStart;
      a.stackBottom=reinterpret_cast<uintptr_t>(regions_[3].ptr);
      a.stackBytes=kStackCapacity;
      a.guestPageBytes=kPagesize;
      a.uid=static_cast<uint32_t>(getuid());
      a.euid=static_cast<uint32_t>(geteuid());
      a.gid=static_cast<uint32_t>(getgid());
      a.egid=static_cast<uint32_t>(getegid());
      a.randomBytes=entropy;
      a.argv={kGuest[0].path};
      a.environment={"LANG=C"};
      if(!g2b::PrepareX86DynamicGuestLaunchPlanFromResolver(
          fetch,kGuest[0].path,a,plan_,why) ||
         !plan_.guestVirtualAddressesValidated ||
         !plan_.stackAndAuxvConsistent ||
         plan_.dependencyObjectsChecked!=3 ||
         plan_.mainLoadBias!=metadata_[0].loadBias ||
         plan_.interpreterLoadBias!=metadata_[1].loadBias ||
         plan_.guestInterpreterEntry<a.interpreterImageStart ||
         plan_.guestInterpreterEntry>=
             a.interpreterImageStart+kImageCapacity ||
         plan_.guestMainEntry<a.mainImageStart ||
         plan_.guestMainEntry>=a.mainImageStart+kImageCapacity ||
         plan_.stack.guestBottom!=a.stackBottom ||
         plan_.stack.bytes.size()!=kStackCapacity ||
         plan_.stack.guestRSP<a.stackBottom ||
         plan_.stack.guestRSP>=a.stackBottom+kStackCapacity ||
         plan_.guestMemoryMapped || plan_.dynamicLinkerExecuted) {
        w.failureErrno=ENOEXEC;
        const size_t before=WindowsHeld();
        if(!Release())w.phase=Phase::CleanupFailed;
        w.windowsReleasedOnFailure=before-WindowsHeld();
        return false;
      }
      w.originalInterpreterRebasedRIP=plan_.guestInterpreterEntry;
      w.mainRebasedEntry=plan_.guestMainEntry;
      w.x86RebasedStackRSP=plan_.stack.guestRSP;
      w.linuxAuxvRebased=true;
      w.phase=Phase::CopyOriginalSegments;
      for(size_t i=0;i<4;++i) {
        if(::mprotect(regions_[i].ptr,regions_[i].length,
                      PROT_READ|PROT_WRITE)!=0) {
          w.failureErrno=errno;
          const size_t before=WindowsHeld();
          if(!Release())w.phase=Phase::CleanupFailed;
          w.windowsReleasedOnFailure=before-WindowsHeld();
          return false;
        }
        if(i<3) {
          const auto& snap=pinned.snapshots[i];
          if(!CopyAndCompareImage(static_cast<int>(i),
               snap.bytes(),snap.size(),w.originalSegmentsCompared)) {
            w.failureErrno=EIO;
            const size_t before=WindowsHeld();
            if(!Release())w.phase=Phase::CleanupFailed;
            w.windowsReleasedOnFailure=before-WindowsHeld();
            return false;
          }
        } else {
          std::memcpy(regions_[i].ptr,plan_.stack.bytes.data(),kStackCapacity);
          if(std::memcmp(regions_[i].ptr,plan_.stack.bytes.data(),
                         kStackCapacity)!=0) {
            w.failureErrno=EIO;
            const size_t before=WindowsHeld();
            if(!Release())w.phase=Phase::CleanupFailed;
            w.windowsReleasedOnFailure=before-WindowsHeld();
            return false;
          }
        }
      }
      w.phase=Phase::SealReadOnly;
      for(const auto& region:regions_) {
        if(::mprotect(region.ptr,region.length,PROT_READ)!=0) {
          w.failureErrno=errno;
          const size_t before=WindowsHeld();
          if(!Release())w.phase=Phase::CleanupFailed;
          w.windowsReleasedOnFailure=before-WindowsHeld();
          return false;
        }
      }
      w.phase=Phase::VerifySourceBytes;
      for(size_t i=0;i<3;++i) {
        const auto& snap=pinned.snapshots[i];
        // All original PT_LOAD file bytes must survive the final RO seal.
        Elf64_Ehdr eh{};
        std::memcpy(&eh,snap.bytes(),sizeof(eh));
        for(uint16_t j=0;j<eh.e_phnum;++j) {
          Elf64_Phdr ph{};
          std::memcpy(&ph,snap.bytes()+eh.e_phoff+
                    size_t(j)*sizeof(ph),sizeof(ph));
          if(ph.p_type!=PT_LOAD || !ph.p_filesz)continue;
          const uint64_t start=metadata_[i].loadBias+ph.p_vaddr;
          const auto* actual=static_cast<const unsigned char*>(
              regions_[i].ptr)+(ph.p_vaddr-metadata_[i].lowestAlignedELFVA);
          if(start!=reinterpret_cast<uintptr_t>(actual) ||
             std::memcmp(actual,snap.bytes()+ph.p_offset,ph.p_filesz)!=0) {
            w.failureErrno=EIO;
            const size_t before=WindowsHeld();
            if(!Release())w.phase=Phase::CleanupFailed;
            w.windowsReleasedOnFailure=before-WindowsHeld();
            return false;
          }
        }
      }
      if(std::memcmp(regions_[3].ptr,plan_.stack.bytes.data(),
                     kStackCapacity)!=0) {
        w.failureErrno=EIO;
        const size_t before=WindowsHeld();
        if(!Release())w.phase=Phase::CleanupFailed;
        w.windowsReleasedOnFailure=before-WindowsHeld();
        return false;
      }
      validated_=true;
      w.originalBytesCopiedReadOnly=true;
      w.phase=Phase::Complete;
      return true;
    } catch(...) {
      w.failureErrno=ENOMEM;
      const size_t before=WindowsHeld();
      if(!Release())w.phase=Phase::CleanupFailed;
      w.windowsReleasedOnFailure=before-WindowsHeld();
      return false;
    }
  }
};
} // namespace kernix::g2e::c3d7b
