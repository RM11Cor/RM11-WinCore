#pragma once
// SPDX-License-Identifier: MIT
// G0: bounded Linux x86 guest openat(257), read(0), pread64(17),
// and source-checked MAP_PRIVATE PROT_READ or PROT_READ|PROT_EXEC
// mmap(9) ONLY for whole original PT_LOAD PF_R|PF_X ELF pages,
// close(3) for EXACT three original source SHA256 verified ELF snapshots.
// This is a BOUNDED source-ELF data/RX guest service, NOT full GNU ld-linux startup.
// NEVER pass any guest pathname, guest fd or host memory pointer into
// native openat/read/pread/close; only trusted native bootstrap owns FDs.
// It reuses the existing G2C immutable anonymous PROT_READ snapshots
// and G0 owner-held guest VM instead of creating parallel VMA allocators.
#include "kernix_g2c_native_readonly_guest_snapshots.h"
#include "kernix_g0_guest_owned_anonymous_vm_kernel.h"
#include "kernix_g0_original_libc_synthetic_x86_stat_abi.h"
#include "kernix_g0_source_pinned_libc_large_ro_guest_map.h"
#include "kernix_g2e_c3d7g_native_pt_load_wx_apply_gate.h"
#include <array>
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <elf.h>
#include <limits>
#include <string>
#include <string_view>
namespace kernix::g0 {
class SourceVerifiedGuestElfFDKernel final {
 public:
  static constexpr int kGuestBaseFD=100;
  static constexpr size_t kMaxGuestOpenSlots=8;
  static constexpr uint64_t kMaxRead=4096;
  struct Result {
    int64_t guestReturn=-38;
    bool guestSyscallAuthenticated=false;
    bool openedPinnedReadonlySnapshot=false;
    bool copiedSnapshotToAuthenticatedGuestWritable=false;
    bool guestFdClosed=false;
    bool guestVirtualStatWritten=false;
    bool guestOriginalLibcLargeReadonlyMapped=false;
    bool guestOriginalLibcBeyondEOFInaccessible=false;
    bool guestOriginalLdsoPostCloseAnonymous8KMapped=false;
    bool readonlySourceELFSnapshotMapped=false;
    bool guestReadonlySourceELFNativeProtectionApplied=false;
    bool executableSourceELFSnapshotMapped=false;
    bool guestExecutableSourceELFNativeProtectionApplied=false;
    bool hostPathOpened=false;
    bool hostGuestFdForwarded=false;
    bool hostAnyUntrustedSyscallForwarded=false;
  };
  SourceVerifiedGuestElfFDKernel()=default;
  SourceVerifiedGuestElfFDKernel(const SourceVerifiedGuestElfFDKernel&)=delete;
  SourceVerifiedGuestElfFDKernel& operator=(const SourceVerifiedGuestElfFDKernel&)=delete;
  ~SourceVerifiedGuestElfFDKernel()=default;
  void Reset() noexcept {
    (void)postCloseAnonymousGuestVM_.Reset();
    originalPostCloseFSBaseVerified_=false;
    originalPostCloseFSBase_=0;
    originalPostCloseClearChildTIDVerified_=false;
    originalPostCloseClearChildTID_=0;
    originalPostCloseRobustListVerified_=false;
    originalPostCloseRobustListHead_=0;
    (void)largeLibcROMap_.Reset();
    originalLibcClosedAfterBSS_=false;
    for(auto& v:open_)v={};
    for(auto& image:source_)image.reset();
    bound_=false;
  }
  // Trusted host bootstrap supplies exactly three ORIGINAL guest ELF FDs
  // already opened securely. Source contents are rehashed while copying
  // to immutable anonymous snapshots; no mutable file FD survives inside
  // the guest kernel service. Binding failure clears all state.
  bool BindSourceOriginalTriad(const std::array<int,3>& trustedFds) {
    Reset();
    std::string why;
    for(size_t i=0;i<source_.size();++i){
      if(!source_[i].Capture(trustedFds[i],kSources[i].size,
                            kSources[i].sha,why)) {
        Reset();return false;
      }
    }
    bound_=true;
    return true;
  }
  bool Bound() const noexcept{return bound_;}
  size_t OpenCount() const noexcept {
    size_t n=0;
    for(const auto& slot:open_)if(slot.active)++n;
    return n;
  }
  // Diagnostic-only isolated original GNU loader continuation after FEX
  // SIGBUS. A guest pointer is NEVER trusted without source triad, owned
  // 4K startup-stack mapping, executable-page policy and actual RW VMA
  // attestation by the caller. This returns an in-memory synthetic x86 FD;
  // it does not use native openat, host guest pathname or host filesystem.
  // Deliberately narrow: only the SHA-locked original libc from kSources[2].
  Result DispatchOriginalLdsoPinnedLibcStackOpenat(
      const kernix::g2e::c1::TrapClassification& t,
      const kernix::g2e::c3d7b::NativeChosenPIEGuestLayout& owner,
      const kernix::g2e::c3d7g::PermissionPlan& rights,
      const kernix::g2e::c3d7g::ApplyWitness& wx,
      bool actualNativeGuestStackPageRW) noexcept {
    namespace c1=kernix::g2e::c1;
    Result out{};
    out.guestReturn=-ENOSYS;
    constexpr uint64_t kSignedATFDCWD=UINT64_MAX-99;
    constexpr uint64_t kZeroExtendedATFDCWD=UINT32_MAX-99;
    constexpr uint64_t kOReadOnlyCloexec=0x80000ULL;
    constexpr char kLibcPath[]="/lib/x86_64-linux-gnu/libc.so.6";
    constexpr size_t kLibcIndex=2;
    static_assert(sizeof(kLibcPath)==32);
    if(::sysconf(_SC_PAGESIZE)!=4096 || !bound_ ||
       !source_[kLibcIndex].readOnlySnapshot() ||
       !source_[kLibcIndex].bytes() ||
       source_[kLibcIndex].size()!=kSources[kLibcIndex].size ||
       !actualNativeGuestStackPageRW ||
       !t.trapBoundaryAuthenticated || !t.sourceRegisterMappingChecked ||
       t.hostSyscallDispatched || t.guestMemoryDereferenced ||
       t.guestNumber!=c1::kOpenat ||
       t.category!=c1::CallCategory::NeedsGuestKernel ||
       (t.args[0]!=kSignedATFDCWD &&
        t.args[0]!=kZeroExtendedATFDCWD) ||
       t.args[2]!=kOReadOnlyCloexec ||
       !rights.sourceShaVerified || !rights.nativeGuestVAIdentityOwned ||
       !rights.allPTLoadPagesPlanned ||
       !rights.deniedWritableExecutablePages ||
       !wx.originalPinnedSourceValidated ||
       !wx.nativeNoWritableExecutablePage ||
       !wx.nativeNonPTLoadHolesDenied || wx.androidDeviceTested ||
       owner.WindowsHeld()!=4 || !owner.Module(1) ||
       !owner.Module(kLibcIndex) || !owner.LaunchPlan())
      return out;
    const auto& stack=owner.LaunchPlan()->stack;
    const uint64_t guestPath=t.args[1];
    if(stack.guestTop<=stack.guestBottom+4096 ||
       guestPath<stack.guestBottom+4096 ||
       guestPath>=stack.guestTop ||
       !c1::GuestRange(guestPath,sizeof(kLibcPath)) ||
       stack.guestTop-guestPath<sizeof(kLibcPath) ||
       (guestPath&4095)>4096-sizeof(kLibcPath))
      return out;
    // A verified path is read only from the exact originally owned
    // read/write x86 guest stack page. No host path access is possible.
    if(std::memcmp(reinterpret_cast<const void*>(
           static_cast<uintptr_t>(guestPath)),kLibcPath,
           sizeof(kLibcPath))!=0) {
      out.guestReturn=-ENOENT;
      return out;
    }
    out.guestSyscallAuthenticated=true;
    for(size_t i=0;i<open_.size();++i) {
      if(open_[i].active)continue;
      open_[i]={true,kLibcIndex,0};
      out.openedPinnedReadonlySnapshot=true;
      out.guestReturn=kGuestBaseFD+static_cast<int64_t>(i);
      return out;
    }
    out.guestReturn=-EMFILE;
    return out;
  }
  // Isolated original ld-linux post-open libc read. Proven authentic
  // guest request: x86 read(fd=100, owned stack RW buffer, 832). This
  // copies original immutable SHA-locked libc bytes to owned guest stack.
  // No native read/openat, syscall forwarding, executable mapping or
  // guest pointer access outside its independently attested 4K VMA.
  Result DispatchOriginalLdsoPinnedLibcReadToStack(
      const kernix::g2e::c1::TrapClassification& t,
      const kernix::g2e::c3d7b::NativeChosenPIEGuestLayout& owner,
      const kernix::g2e::c3d7g::PermissionPlan& rights,
      const kernix::g2e::c3d7g::ApplyWitness& wx,
      bool actualNativeGuestStackPageRW) noexcept {
    namespace c1=kernix::g2e::c1;
    Result out{};
    out.guestReturn=-ENOSYS;
    constexpr size_t kOriginalLibcIndex=2;
    if(::sysconf(_SC_PAGESIZE)!=4096 || !bound_ ||
       !source_[kOriginalLibcIndex].readOnlySnapshot() ||
       !source_[kOriginalLibcIndex].bytes() ||
       source_[kOriginalLibcIndex].size()!=kSources[kOriginalLibcIndex].size ||
       !t.trapBoundaryAuthenticated || !t.sourceRegisterMappingChecked ||
       t.hostSyscallDispatched || t.guestMemoryDereferenced ||
       t.guestNumber!=c1::kRead ||
       t.category!=c1::CallCategory::NeedsGuestKernel ||
       !actualNativeGuestStackPageRW ||
       !rights.sourceShaVerified || !rights.nativeGuestVAIdentityOwned ||
       !rights.allPTLoadPagesPlanned || !rights.deniedWritableExecutablePages ||
       !wx.originalPinnedSourceValidated || !wx.nativeNoWritableExecutablePage ||
       !wx.nativeNonPTLoadHolesDenied || wx.androidDeviceTested ||
       owner.WindowsHeld()!=4 || !owner.Module(kOriginalLibcIndex) ||
       !owner.LaunchPlan() ||
       t.args[0]!=static_cast<uint64_t>(kGuestBaseFD) ||
       !open_[0].active ||
       open_[0].sourceIndex!=kOriginalLibcIndex ||
       open_[0].position!=0)
       return out;
    const uint64_t dest=t.args[1],requested=t.args[2];
    const auto& stack=owner.LaunchPlan()->stack;
    if(requested==0 || requested>kMaxRead ||
       stack.guestTop<=stack.guestBottom+4096 ||
       dest<stack.guestBottom+4096 || dest>=stack.guestTop ||
       !c1::GuestRange(dest,requested) ||
       requested>stack.guestTop-dest ||
       requested>4096-(dest&4095))
       return out;
    const size_t count=static_cast<size_t>(std::min<uint64_t>(
        requested,source_[kOriginalLibcIndex].size()));
    if(count==0) {
      out.guestReturn=0;out.guestSyscallAuthenticated=true;
      return out;
    }
    std::memcpy(reinterpret_cast<void*>(static_cast<uintptr_t>(dest)),
                source_[kOriginalLibcIndex].bytes(),count);
    open_[0].position=count;
    out.guestSyscallAuthenticated=true;
    out.copiedSnapshotToAuthenticatedGuestWritable=true;
    out.guestReturn=static_cast<int64_t>(count);
    return out;
  }
  // Isolated real original ld-linux pread64 from the already-opened,
  // exact SHA256-pinned libc synthetic guest FD 100. The source offset
  // comes from authentic FEX x86 syscall R10, never from guessed file
  // offsets. Native host file IO and arbitrary guest VMA are forbidden.
  Result DispatchOriginalLdsoPinnedLibcPreadToStack(
      const kernix::g2e::c1::TrapClassification& t,
      const kernix::g2e::c3d7b::NativeChosenPIEGuestLayout& owner,
      const kernix::g2e::c3d7g::PermissionPlan& rights,
      const kernix::g2e::c3d7g::ApplyWitness& wx,
      bool actualNativeGuestStackPageRW) noexcept {
    namespace c1=kernix::g2e::c1;
    Result out{};
    out.guestReturn=-ENOSYS;
    constexpr size_t kOriginalLibcIndex=2;
    constexpr size_t kSlot=0;
    if(::sysconf(_SC_PAGESIZE)!=4096 || !bound_ ||
       !source_[kOriginalLibcIndex].readOnlySnapshot() ||
       !source_[kOriginalLibcIndex].bytes() ||
       source_[kOriginalLibcIndex].size()!=kSources[kOriginalLibcIndex].size ||
       !t.trapBoundaryAuthenticated || !t.sourceRegisterMappingChecked ||
       t.hostSyscallDispatched || t.guestMemoryDereferenced ||
       t.guestNumber!=c1::kPread64 ||
       t.category!=c1::CallCategory::NeedsGuestKernel ||
       !actualNativeGuestStackPageRW ||
       !rights.sourceShaVerified || !rights.nativeGuestVAIdentityOwned ||
       !rights.allPTLoadPagesPlanned || !rights.deniedWritableExecutablePages ||
       !wx.originalPinnedSourceValidated || !wx.nativeNoWritableExecutablePage ||
       !wx.nativeNonPTLoadHolesDenied || wx.androidDeviceTested ||
       owner.WindowsHeld()!=4 || !owner.Module(kOriginalLibcIndex) ||
       !owner.LaunchPlan() ||
       t.args[0]!=static_cast<uint64_t>(kGuestBaseFD) ||
       !open_[kSlot].active ||
       open_[kSlot].sourceIndex!=kOriginalLibcIndex ||
       open_[kSlot].position!=832)
       return out;
    const uint64_t dest=t.args[1];
    const uint64_t countRequested=t.args[2];
    const uint64_t sourceOffset=t.args[3];
    const auto& stack=owner.LaunchPlan()->stack;
    if(countRequested==0 || countRequested>kMaxRead ||
       stack.guestTop<=stack.guestBottom+4096 ||
       dest<stack.guestBottom+4096 || dest>=stack.guestTop ||
       !c1::GuestRange(dest,countRequested) ||
       countRequested>stack.guestTop-dest ||
       countRequested>4096-(dest&4095) ||
       sourceOffset>static_cast<uint64_t>(INT64_MAX))
       return out;
    const uint64_t sourceSize=
        static_cast<uint64_t>(source_[kOriginalLibcIndex].size());
    out.guestSyscallAuthenticated=true;
    if(sourceOffset>=sourceSize) {
      out.guestReturn=0;
      return out;
    }
    const size_t count=static_cast<size_t>(
        std::min<uint64_t>(countRequested,sourceSize-sourceOffset));
    std::memcpy(reinterpret_cast<void*>(static_cast<uintptr_t>(dest)),
                source_[kOriginalLibcIndex].bytes()+
                    static_cast<size_t>(sourceOffset),count);
    // Linux pread64 explicitly preserves the synthetic file position,
    // unlike read. This next loader read starts after prior read(832).
    out.copiedSnapshotToAuthenticatedGuestWritable=true;
    out.guestReturn=static_cast<int64_t>(count);
    return out;
  }
  // Original unmodified GNU ld-linux next x86 fstat(5) for the
  // already-open synthetic FD 100, backed only by the SHA-locked libc
  // immutable source. Produce Linux x86-64's 144-byte guest ABI, NOT
  // Android/ARM64 native struct stat. Synthetic filesystem fields
  // never claim to be original host file metadata; st_size is exact.
  // The output must live within one attested owned 4K guest stack page.
  Result DispatchOriginalLdsoPinnedLibcFstatToStack(
      const kernix::g2e::c1::TrapClassification& t,
      const kernix::g2e::c3d7b::NativeChosenPIEGuestLayout& owner,
      const kernix::g2e::c3d7g::PermissionPlan& rights,
      const kernix::g2e::c3d7g::ApplyWitness& wx,
      bool actualNativeGuestStackPageRW) noexcept {
    namespace c1=kernix::g2e::c1;
    namespace vstat=kernix::g0::statabi;
    Result out{};
    out.guestReturn=-ENOSYS;
    constexpr size_t kOriginalLibcIndex=2;
    constexpr size_t kSlot=0;
    if(::sysconf(_SC_PAGESIZE)!=4096 || !bound_ ||
       !source_[kOriginalLibcIndex].readOnlySnapshot() ||
       !source_[kOriginalLibcIndex].bytes() ||
       source_[kOriginalLibcIndex].size()!=kSources[kOriginalLibcIndex].size ||
       !t.trapBoundaryAuthenticated || !t.sourceRegisterMappingChecked ||
       t.hostSyscallDispatched || t.guestMemoryDereferenced ||
       t.guestNumber!=c1::kFstat ||
       t.category!=c1::CallCategory::NeedsGuestKernel ||
       !actualNativeGuestStackPageRW ||
       !rights.sourceShaVerified || !rights.nativeGuestVAIdentityOwned ||
       !rights.allPTLoadPagesPlanned || !rights.deniedWritableExecutablePages ||
       !wx.originalPinnedSourceValidated || !wx.nativeNoWritableExecutablePage ||
       !wx.nativeNonPTLoadHolesDenied || wx.androidDeviceTested ||
       owner.WindowsHeld()!=4 || !owner.Module(kOriginalLibcIndex) ||
       !owner.LaunchPlan() ||
       t.args[0]!=static_cast<uint64_t>(kGuestBaseFD) ||
       OpenCount()!=1 || !open_[kSlot].active ||
       open_[kSlot].sourceIndex!=kOriginalLibcIndex ||
       open_[kSlot].position!=832)
      return out;
    const uint64_t dest=t.args[1];
    const auto& stack=owner.LaunchPlan()->stack;
    constexpr uint64_t kBytes=sizeof(vstat::LinuxX86_64Stat);
    if(stack.guestTop<=stack.guestBottom+4096 ||
       dest<stack.guestBottom+4096 || dest>=stack.guestTop ||
       !c1::GuestRange(dest,kBytes) ||
       kBytes>stack.guestTop-dest ||
       kBytes>4096-(dest&4095))
      return out;
    const auto virtualStat=vstat::SourcePinnedLibcVirtualStat(
      source_[kOriginalLibcIndex].size(),
      static_cast<uint32_t>(::getuid()),static_cast<uint32_t>(::getgid()));
    // Typed guest ABI was source-audited against Linux x86-64 stat.h,
    // compile-time checked for all field offsets and exact total size.
    std::memcpy(reinterpret_cast<void*>(static_cast<uintptr_t>(dest)),
                &virtualStat,sizeof(virtualStat));
    out.guestSyscallAuthenticated=true;
    out.guestVirtualStatWritten=true;
    out.guestReturn=0;
    return out;
  }
  // Original GNU ld-linux file-backed mmap(9), first full-length
  // private read-only libc reservation. Exact authentic guest R10 flags
  // MAP_PRIVATE|MAP_DENYWRITE (the latter ignored by Linux), R8 fd=100,
  // R9 file offset 0. The 2.17MB guest RO mapping is NEW owned VMA,
  // distinct from 4K small guest anonymous heap and source PT_LOAD.
  // Never map arbitrary host file descriptor or grant executable rights.
  Result DispatchOriginalLdsoPinnedLibcLargeReadonlyMmap(
      const kernix::g2e::c1::TrapClassification& t,
      const kernix::g2e::c3d7b::NativeChosenPIEGuestLayout& owner,
      const kernix::g2e::c3d7g::PermissionPlan& rights,
      const kernix::g2e::c3d7g::ApplyWitness& wx) noexcept {
    Result out{};
    out.guestReturn=-ENOSYS;
    constexpr size_t kOriginalLibcIndex=2;
    if(!bound_ || !source_[kOriginalLibcIndex].readOnlySnapshot() ||
       !source_[kOriginalLibcIndex].bytes() ||
       source_[kOriginalLibcIndex].size()!=kSources[kOriginalLibcIndex].size ||
       !rights.sourceShaVerified || !rights.nativeGuestVAIdentityOwned ||
       !rights.allPTLoadPagesPlanned ||
       !rights.deniedWritableExecutablePages ||
       !wx.originalPinnedSourceValidated ||
       !wx.nativeNoWritableExecutablePage ||
       !wx.nativeNonPTLoadHolesDenied || wx.androidDeviceTested ||
       owner.WindowsHeld()!=4 || !owner.Module(kOriginalLibcIndex) ||
       !owner.LaunchPlan() || OpenCount()!=1 ||
       !open_[0].active || open_[0].sourceIndex!=kOriginalLibcIndex ||
       open_[0].position!=832)
      return out;
    const auto large=largeLibcROMap_.Map(
       t,source_[kOriginalLibcIndex].bytes(),
       source_[kOriginalLibcIndex].size());
    out.guestReturn=large.guestReturn;
    out.guestSyscallAuthenticated=large.realGuestMmapAuthenticated;
    out.guestOriginalLibcLargeReadonlyMapped=
       large.originalSourceSnapshotCopied &&
       large.mappedOwnedGuestReadOnly &&
       !large.guestRWXEverGranted;
    out.guestOriginalLibcBeyondEOFInaccessible=
       large.remainingBeyondEOFPagesInaccessible;
    out.hostPathOpened=false;
    out.hostGuestFdForwarded=false;
    out.hostAnyUntrustedSyscallForwarded=
       !large.noHostGuestFDOrPathForwarding;
    return out;
  }
  // Diagnostic-only exact second genuine loader MAP_FIXED request.
  // Do not permit arbitrary MAP_FIXED or guest-controlled replacement:
  // only add RX to already-owned source-equal libc pages after validating
  // the actual original x86 ELF PF_R|PF_X PT_LOAD program header.
  PinnedLibcLargeReadonlyGuestMap::RXResult
  DispatchOriginalLdsoPinnedLibcOwnedTextRX(
      const kernix::g2e::c1::TrapClassification& t,
      const kernix::g2e::c3d7b::NativeChosenPIEGuestLayout& owner,
      const kernix::g2e::c3d7g::PermissionPlan& rights,
      const kernix::g2e::c3d7g::ApplyWitness& wx) noexcept {
    PinnedLibcLargeReadonlyGuestMap::RXResult out{};
    constexpr size_t kLibc=2;
    if(!bound_ || !source_[kLibc].readOnlySnapshot() ||
       !source_[kLibc].bytes() ||
       source_[kLibc].size()!=kSources[kLibc].size ||
       !rights.sourceShaVerified || !rights.nativeGuestVAIdentityOwned ||
       !rights.allPTLoadPagesPlanned || !rights.deniedWritableExecutablePages ||
       !wx.originalPinnedSourceValidated ||
       !wx.nativeNoWritableExecutablePage ||
       !wx.nativeNonPTLoadHolesDenied || wx.androidDeviceTested ||
       owner.WindowsHeld()!=4 || !owner.Module(kLibc) ||
       !owner.LaunchPlan() || OpenCount()!=1 || !open_[0].active ||
       open_[0].sourceIndex!=kLibc || open_[0].position!=832 ||
       largeLibcROMap_.Address()==0 || largeLibcROMap_.BytesHeld()==0 ||
       largeLibcROMap_.OriginalSourceTextRXSealed())
      return out;
    return largeLibcROMap_.PromoteOriginalLibcSourceTextRX(
        t,source_[kLibc].bytes(),source_[kLibc].size());
  }

  // Third genuine loader mmap is only a PF_R, privately mapped piece of
  // the same original libc snapshot FD100 already held by the first
  // source-verified owning mapping. No native MAP_FIXED or guest path.
  PinnedLibcLargeReadonlyGuestMap::ReadOnlyPTLoadResult
  DispatchOriginalLdsoPinnedLibcOwnedReadOnlyPTLoad(
      const kernix::g2e::c1::TrapClassification& t,
      const kernix::g2e::c3d7b::NativeChosenPIEGuestLayout& owner,
      const kernix::g2e::c3d7g::PermissionPlan& rights,
      const kernix::g2e::c3d7g::ApplyWitness& wx) noexcept {
    PinnedLibcLargeReadonlyGuestMap::ReadOnlyPTLoadResult out{};
    constexpr size_t kLibc=2;
    if(!bound_ || !source_[kLibc].readOnlySnapshot() ||
       !source_[kLibc].bytes() ||
       source_[kLibc].size()!=kSources[kLibc].size ||
       !rights.sourceShaVerified || !rights.nativeGuestVAIdentityOwned ||
       !rights.allPTLoadPagesPlanned || !rights.deniedWritableExecutablePages ||
       !wx.originalPinnedSourceValidated ||
       !wx.nativeNoWritableExecutablePage ||
       !wx.nativeNonPTLoadHolesDenied || wx.androidDeviceTested ||
       owner.WindowsHeld()!=4 || !owner.Module(kLibc) ||
       !owner.LaunchPlan() || OpenCount()!=1 || !open_[0].active ||
       open_[0].sourceIndex!=kLibc || open_[0].position!=832 ||
       largeLibcROMap_.Address()==0 || largeLibcROMap_.BytesHeld()==0 ||
       !largeLibcROMap_.OriginalSourceTextRXSealed())
      return out;
    return largeLibcROMap_.ConfirmOriginalLibcSourceReadOnlyPTLoad(
        t,source_[kLibc].bytes(),source_[kLibc].size());
  }
  // Fourth genuine GNU ld-linux x86 mmap; only a PF_R|PF_W
  // source-proven PT_LOAD inside the same already-owned 4KiB guest VMA.
  // The file offset is one page behind its guest virtual offset,
  // so actual original bytes are privately copied to the writable
  // destination; never host mmap(MAP_FIXED) or WX.
  PinnedLibcLargeReadonlyGuestMap::WritablePTLoadResult
  DispatchOriginalLdsoPinnedLibcOwnedWritablePTLoad(
      const kernix::g2e::c1::TrapClassification& t,
      const kernix::g2e::c3d7b::NativeChosenPIEGuestLayout& owner,
      const kernix::g2e::c3d7g::PermissionPlan& rights,
      const kernix::g2e::c3d7g::ApplyWitness& wx) noexcept {
    PinnedLibcLargeReadonlyGuestMap::WritablePTLoadResult out{};
    constexpr size_t kLibc=2;
    if(!bound_ || !source_[kLibc].readOnlySnapshot() ||
       !source_[kLibc].bytes() ||
       source_[kLibc].size()!=kSources[kLibc].size ||
       !rights.sourceShaVerified || !rights.nativeGuestVAIdentityOwned ||
       !rights.allPTLoadPagesPlanned || !rights.deniedWritableExecutablePages ||
       !wx.originalPinnedSourceValidated ||
       !wx.nativeNoWritableExecutablePage ||
       !wx.nativeNonPTLoadHolesDenied || wx.androidDeviceTested ||
       owner.WindowsHeld()!=4 || !owner.Module(kLibc) ||
       !owner.LaunchPlan() || OpenCount()!=1 || !open_[0].active ||
       open_[0].sourceIndex!=kLibc || open_[0].position!=832 ||
       largeLibcROMap_.Address()==0 || largeLibcROMap_.BytesHeld()==0 ||
       !largeLibcROMap_.OriginalSourceTextRXSealed() ||
       !largeLibcROMap_.OriginalSourceReadOnlyPTLoadConfirmed())
      return out;
    return largeLibcROMap_.PromoteOriginalLibcSourceWritablePTLoad(
        t,source_[kLibc].bytes(),source_[kLibc].size());
  }
  // Fifth original GNU libc mmap: original PF_R|PF_W PT_LOAD BSS
  // ending at original guest virtual layout bound. Only anonymous
  // zero-backed pages inside the owner reserved by the first map,
  // with proper x86 flags and virtual fd -1; no host MAP_FIXED.
  PinnedLibcLargeReadonlyGuestMap::BSSResult
  DispatchOriginalLdsoPinnedLibcOwnedAnonymousBSS(
      const kernix::g2e::c1::TrapClassification& t,
      const kernix::g2e::c3d7b::NativeChosenPIEGuestLayout& owner,
      const kernix::g2e::c3d7g::PermissionPlan& rights,
      const kernix::g2e::c3d7g::ApplyWitness& wx) noexcept {
    PinnedLibcLargeReadonlyGuestMap::BSSResult out{};
    constexpr size_t kLibc=2;
    if(!bound_ || !source_[kLibc].readOnlySnapshot() ||
       !source_[kLibc].bytes() ||
       source_[kLibc].size()!=kSources[kLibc].size ||
       !rights.sourceShaVerified || !rights.nativeGuestVAIdentityOwned ||
       !rights.allPTLoadPagesPlanned || !rights.deniedWritableExecutablePages ||
       !wx.originalPinnedSourceValidated ||
       !wx.nativeNoWritableExecutablePage ||
       !wx.nativeNonPTLoadHolesDenied || wx.androidDeviceTested ||
       owner.WindowsHeld()!=4 || !owner.Module(kLibc) ||
       !owner.LaunchPlan() || OpenCount()!=1 || !open_[0].active ||
       open_[0].sourceIndex!=kLibc || open_[0].position!=832 ||
       largeLibcROMap_.Address()==0 || largeLibcROMap_.BytesHeld()==0 ||
       !largeLibcROMap_.OriginalSourceTextRXSealed() ||
       !largeLibcROMap_.OriginalSourceReadOnlyPTLoadConfirmed() ||
       !largeLibcROMap_.OriginalSourceWritablePTLoadConfirmed())
      return out;
    return largeLibcROMap_.ZeroOriginalLibcOwnedBSS(
        t,source_[kLibc].bytes(),source_[kLibc].size());
  }
  // Exact authentic x86 close(3) issued by original GNU ld-linux
  // after original source libc first RO, PF_RX, PF_R, shifted PF_RW and
  // anonymous zero BSS. Close ONLY the virtual guest FD100 handle;
  // existing private mapped source ELF pages must remain valid. There
  // is NO native host close(2), forwarding or releasing guest VMAs.
  Result DispatchOriginalLdsoPinnedLibcCloseAfterBSS(
      const kernix::g2e::c1::TrapClassification& t,
      const kernix::g2e::c3d7b::NativeChosenPIEGuestLayout& owner,
      const kernix::g2e::c3d7g::PermissionPlan& rights,
      const kernix::g2e::c3d7g::ApplyWitness& wx) noexcept {
    namespace c1=kernix::g2e::c1;
    Result out{};
    out.guestReturn=-ENOSYS;
    constexpr size_t kLibc=2;
    if(originalLibcClosedAfterBSS_ || !bound_ ||
       !source_[kLibc].readOnlySnapshot() ||
       !source_[kLibc].bytes() ||
       source_[kLibc].size()!=kSources[kLibc].size ||
       !rights.sourceShaVerified || !rights.nativeGuestVAIdentityOwned ||
       !rights.allPTLoadPagesPlanned ||
       !rights.deniedWritableExecutablePages ||
       !wx.originalPinnedSourceValidated ||
       !wx.nativeNoWritableExecutablePage ||
       !wx.nativeNonPTLoadHolesDenied || wx.androidDeviceTested ||
       owner.WindowsHeld()!=4 || !owner.Module(kLibc) ||
       !owner.LaunchPlan() || OpenCount()!=1 ||
       !open_[0].active || open_[0].sourceIndex!=kLibc ||
       open_[0].position!=832 ||
       !largeLibcROMap_.OriginalSourceTextRXSealed() ||
       !largeLibcROMap_.OriginalSourceReadOnlyPTLoadConfirmed() ||
       !largeLibcROMap_.OriginalSourceWritablePTLoadConfirmed() ||
       !largeLibcROMap_.OriginalOwnedBSSZeroed() ||
       largeLibcROMap_.Address()==0 ||
       largeLibcROMap_.BytesHeld()!=0x212000ULL ||
       !t.trapBoundaryAuthenticated || !t.sourceRegisterMappingChecked ||
       t.hostSyscallDispatched || t.guestMemoryDereferenced ||
       t.guestNumber!=c1::kClose ||
       t.category!=c1::CallCategory::NeedsGuestKernel ||
       t.args[0]!=static_cast<uint64_t>(kGuestBaseFD))
      return out;
    // File descriptor ownership is entirely synthetic in this service.
    // Never reset pinned snapshots or large source image on close.
    open_[0]={};
    originalLibcClosedAfterBSS_=true;
    out.guestSyscallAuthenticated=true;
    out.guestFdClosed=true;
    out.guestReturn=0;
    return out;
  }
  bool OriginalLibcClosedAfterBSS() const noexcept {
    return originalLibcClosedAfterBSS_;
  }
  // First genuine ld-linux anonymous guest mmap after closing the
  // original SHA-pinned synthetic libc FD100. The guest requests exactly
  // mmap(NULL,8192,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,
  // fd=-1,offset=0). Reuse existing authenticated bounded owner VM;
  // NEVER forward guest pointers, guest FD, flags or MAP_FIXED to
  // native host. This is not a new ELF source-file mapping.
  Result DispatchOriginalLdsoPostLibcCloseAnonymous8K(
      const kernix::g2e::c1::TrapClassification& t,
      const kernix::g2e::c3d7b::NativeChosenPIEGuestLayout& owner,
      const kernix::g2e::c3d7g::PermissionPlan& rights,
      const kernix::g2e::c3d7g::ApplyWitness& wx) noexcept {
    namespace c1=kernix::g2e::c1;
    Result out{};
    out.guestReturn=-ENOSYS;
    constexpr size_t kLibc=2;
    if(!bound_ || !originalLibcClosedAfterBSS_ ||
       !source_[kLibc].readOnlySnapshot() ||
       !source_[kLibc].bytes() ||
       source_[kLibc].size()!=kSources[kLibc].size ||
       !rights.sourceShaVerified || !rights.nativeGuestVAIdentityOwned ||
       !rights.allPTLoadPagesPlanned || !rights.deniedWritableExecutablePages ||
       !wx.originalPinnedSourceValidated ||
       !wx.nativeNoWritableExecutablePage ||
       !wx.nativeNonPTLoadHolesDenied || wx.androidDeviceTested ||
       owner.WindowsHeld()!=4 || !owner.Module(kLibc) ||
       !owner.LaunchPlan() || OpenCount()!=0 ||
       !largeLibcROMap_.OriginalSourceTextRXSealed() ||
       !largeLibcROMap_.OriginalSourceReadOnlyPTLoadConfirmed() ||
       !largeLibcROMap_.OriginalSourceWritablePTLoadConfirmed() ||
       !largeLibcROMap_.OriginalOwnedBSSZeroed() ||
       largeLibcROMap_.Address()==0 ||
       largeLibcROMap_.BytesHeld()!=0x212000ULL ||
       postCloseAnonymousGuestVM_.Count()!=0 ||
       !t.trapBoundaryAuthenticated || !t.sourceRegisterMappingChecked ||
       t.hostSyscallDispatched || t.guestMemoryDereferenced ||
       t.guestNumber!=c1::kMmap ||
       t.category!=c1::CallCategory::NeedsGuestKernel ||
       t.args[0]!=0 || t.args[1]!=8192 ||
       t.args[2]!=(PROT_READ|PROT_WRITE) ||
       t.args[3]!=0x22 ||
       !c1::IsGuestMmapFdAnonymous(t.args[4]) || t.args[5]!=0)
      return out;
    const auto vm=postCloseAnonymousGuestVM_.Dispatch(t);
    out.guestReturn=vm.guestReturn;
    out.guestSyscallAuthenticated=vm.guestSyscallAuthenticated;
    out.guestOriginalLdsoPostCloseAnonymous8KMapped=
      vm.nativeAnonymousMapCalled && vm.guestWritableDataMapped &&
      vm.guestReturn>0 && postCloseAnonymousGuestVM_.Count()==1 &&
      postCloseAnonymousGuestVM_.AllocatedRequestedBytes()==8192 &&
      !vm.hostAnyUntrustedSyscallForwarded;
    out.hostAnyUntrustedSyscallForwarded=vm.hostAnyUntrustedSyscallForwarded;
    return out;
  }
  const BoundedGuestAnonymousVM&
  OriginalLdsoPostCloseAnonymousVM() const noexcept {
    return postCloseAnonymousGuestVM_;
  }
  struct OriginalLdsoArchSetFSResult {
    int64_t guestReturn=-ENOSYS;
    uint64_t authenticatedGuestFSBase=0;
    bool originalGuestArchPrctlSetFSAuthenticated=false;
    bool ownedAnonymousGuestTLSWindowValidated=false;
    bool noNativeHostTLSMutation=true;
    bool noWExecutableGuestPagesGranted=true;
  };
  // After libc FD100 close and first new anonymous 8K allocation,
  // original GNU loader issues x86 arch_prctl(ARCH_SET_FS=0x1002,
  // owner_8k_base+0x10c0). Verify the guest TLS/TCB belongs exclusively
  // to the new bounded guest anonymous RW VMA, not host TLS, source ELF
  // RX image, Android Bionic, FEX JIT or arbitrary guest pointers.
  // The caller MUST set frame->State.fs_cached to returned verified base
  // and x86 RAX=0. NEVER call native arch_prctl/prctl/set_tls here.
  OriginalLdsoArchSetFSResult
  AuthenticateOriginalLdsoPostCloseArchSetFS(
      const kernix::g2e::c1::TrapClassification& t,
      const kernix::g2e::c3d7b::NativeChosenPIEGuestLayout& owner,
      const kernix::g2e::c3d7g::PermissionPlan& rights,
      const kernix::g2e::c3d7g::ApplyWitness& wx) noexcept {
    namespace c1=kernix::g2e::c1;
    OriginalLdsoArchSetFSResult out{};
    constexpr size_t kLibc=2;
    constexpr uint64_t kArchSetFS=0x1002ULL;
    constexpr uint64_t kOriginalGuestFSOffset=0x10c0ULL;
    constexpr uint64_t kTCBSmallAttestedWindow=0x80ULL;
    if(originalPostCloseFSBaseVerified_ || !bound_ ||
       !originalLibcClosedAfterBSS_ ||
       !source_[kLibc].readOnlySnapshot() ||
       !source_[kLibc].bytes() ||
       source_[kLibc].size()!=kSources[kLibc].size ||
       !rights.sourceShaVerified || !rights.nativeGuestVAIdentityOwned ||
       !rights.allPTLoadPagesPlanned || !rights.deniedWritableExecutablePages ||
       !wx.originalPinnedSourceValidated ||
       !wx.nativeNoWritableExecutablePage ||
       !wx.nativeNonPTLoadHolesDenied || wx.androidDeviceTested ||
       owner.WindowsHeld()!=4 || !owner.Module(kLibc) ||
       !owner.LaunchPlan() || OpenCount()!=0 ||
       !largeLibcROMap_.OriginalSourceTextRXSealed() ||
       !largeLibcROMap_.OriginalSourceReadOnlyPTLoadConfirmed() ||
       !largeLibcROMap_.OriginalSourceWritablePTLoadConfirmed() ||
       !largeLibcROMap_.OriginalOwnedBSSZeroed() ||
       !largeLibcROMap_.Address() ||
       largeLibcROMap_.BytesHeld()!=0x212000ULL ||
       postCloseAnonymousGuestVM_.Count()!=1 ||
       postCloseAnonymousGuestVM_.AllocatedRequestedBytes()!=8192 ||
       !t.trapBoundaryAuthenticated || !t.sourceRegisterMappingChecked ||
       t.hostSyscallDispatched || t.guestMemoryDereferenced ||
       t.guestNumber!=c1::kArchPrctl ||
       t.category!=c1::CallCategory::NeedsGuestKernel ||
       t.args[0]!=kArchSetFS ||
       !c1::GuestRange(t.args[1],kTCBSmallAttestedWindow))
      return out;
    const auto tls=postCloseAnonymousGuestVM_.AuthenticatedRW(
        t.args[1],kTCBSmallAttestedWindow);
    if(!tls.attested || !tls.guestRead || !tls.guestWrite ||
       tls.guestExecute || tls.start>UINT64_MAX-kOriginalGuestFSOffset ||
       t.args[1]!=tls.start+kOriginalGuestFSOffset ||
       tls.pastLast-tls.start!=8192 ||
       (tls.start<largeLibcROMap_.Address()+largeLibcROMap_.BytesHeld() &&
        tls.pastLast>largeLibcROMap_.Address()))
      return out;
    // Verify no overlap with immutable ELF source image and never grant
    // execute permission. Caller sets only FEX X86 CPUState.fs_cached.
    originalPostCloseFSBaseVerified_=true;
    originalPostCloseFSBase_=t.args[1];
    out.authenticatedGuestFSBase=t.args[1];
    out.originalGuestArchPrctlSetFSAuthenticated=true;
    out.ownedAnonymousGuestTLSWindowValidated=true;
    out.guestReturn=0;
    return out;
  }
  bool OriginalLdsoPostCloseFSBaseVerified() const noexcept {
    return originalPostCloseFSBaseVerified_;
  }
  uint64_t OriginalLdsoPostCloseFSBase() const noexcept {
    return originalPostCloseFSBase_;
  }
  struct OriginalLdsoSetTidAddressResult {
    int64_t guestReturn=-ENOSYS;
    uint64_t authenticatedGuestClearChildTID=0;
    bool originalGuestSetTidAddressAuthenticated=false;
    bool ownedThreadClearChildTidPointerVerified=false;
    bool noGuestMemoryWrittenAtRegistration=true;
    bool noHostSetTidAddressOrTLSMutation=true;
    bool diagnosticMainThreadIdentityOnly=false;
  };
  // Real first GNU ld-linux set_tid_address(218) after rebasing the
  // source-authenticated x86 FS to new 8K guest TLS. Linux only
  // *registers* clear_child_tid here. It writes zero and futex wakes
  // at thread exit, NOT at set_tid_address entry. This G0 diagnostic
  // has no complete guest thread/task lifecycle; return only bounded
  // synthetic MAIN guest tid=1, never native host gettid() and never
  // invoke host set_tid_address with guest pointer.
  OriginalLdsoSetTidAddressResult
  RegisterOriginalLdsoGuestClearChildTid(
      const kernix::g2e::c1::TrapClassification& t,
      const kernix::g2e::c3d7b::NativeChosenPIEGuestLayout& owner,
      const kernix::g2e::c3d7g::PermissionPlan& rights,
      const kernix::g2e::c3d7g::ApplyWitness& wx) noexcept {
    namespace c1=kernix::g2e::c1;
    OriginalLdsoSetTidAddressResult out{};
    constexpr size_t kLibc=2;
    constexpr uint64_t kClearChildTIDRelativeFS=0x2d0ULL;
    constexpr int64_t kDiagnosticMainGuestTID=1;
    if(!bound_ || !originalLibcClosedAfterBSS_ ||
       !originalPostCloseFSBaseVerified_ ||
       originalPostCloseClearChildTIDVerified_ ||
       !source_[kLibc].readOnlySnapshot() ||
       !source_[kLibc].bytes() ||
       source_[kLibc].size()!=kSources[kLibc].size ||
       !rights.sourceShaVerified || !rights.nativeGuestVAIdentityOwned ||
       !rights.allPTLoadPagesPlanned || !rights.deniedWritableExecutablePages ||
       !wx.originalPinnedSourceValidated ||
       !wx.nativeNoWritableExecutablePage ||
       !wx.nativeNonPTLoadHolesDenied || wx.androidDeviceTested ||
       owner.WindowsHeld()!=4 || !owner.Module(kLibc) ||
       !owner.LaunchPlan() || OpenCount()!=0 ||
       !largeLibcROMap_.OriginalSourceTextRXSealed() ||
       !largeLibcROMap_.OriginalSourceReadOnlyPTLoadConfirmed() ||
       !largeLibcROMap_.OriginalSourceWritablePTLoadConfirmed() ||
       !largeLibcROMap_.OriginalOwnedBSSZeroed() ||
       largeLibcROMap_.Address()==0 ||
       largeLibcROMap_.BytesHeld()!=0x212000ULL ||
       postCloseAnonymousGuestVM_.Count()!=1 ||
       postCloseAnonymousGuestVM_.AllocatedRequestedBytes()!=8192 ||
       !t.trapBoundaryAuthenticated || !t.sourceRegisterMappingChecked ||
       t.hostSyscallDispatched || t.guestMemoryDereferenced ||
       t.guestNumber!=c1::kSetTidAddress ||
       t.category!=c1::CallCategory::NeedsGuestKernel ||
       originalPostCloseFSBase_>UINT64_MAX-kClearChildTIDRelativeFS ||
       t.args[0]!=originalPostCloseFSBase_+kClearChildTIDRelativeFS ||
       (t.args[0]&3ULL)!=0 || !c1::GuestRange(t.args[0],sizeof(uint32_t)))
      return out;
    const auto target=postCloseAnonymousGuestVM_.AuthenticatedRW(
        t.args[0],sizeof(uint32_t));
    if(!target.attested || !target.guestRead || !target.guestWrite ||
       target.guestExecute || target.start>originalPostCloseFSBase_ ||
       originalPostCloseFSBase_>=target.pastLast ||
       target.pastLast-target.start!=8192 ||
       originalPostCloseFSBase_-target.start!=0x10c0ULL)
      return out;
    // Original FS/TLS field resides inside verified new anonymous RW
    // guest owner only, after old libc FD100 is fully closed. Record
    // virtual clear_child_tid without touching its actual guest bytes.
    originalPostCloseClearChildTID_=t.args[0];
    originalPostCloseClearChildTIDVerified_=true;
    out.authenticatedGuestClearChildTID=t.args[0];
    out.originalGuestSetTidAddressAuthenticated=true;
    out.ownedThreadClearChildTidPointerVerified=true;
    out.diagnosticMainThreadIdentityOnly=true;
    out.guestReturn=kDiagnosticMainGuestTID;
    return out;
  }
  bool OriginalLdsoClearChildTIDVerified() const noexcept {
    return originalPostCloseClearChildTIDVerified_;
  }
  uint64_t OriginalLdsoClearChildTID() const noexcept {
    return originalPostCloseClearChildTID_;
  }
  struct OriginalLdsoRobustListResult {
    int64_t guestReturn=-ENOSYS;
    uint64_t authenticatedGuestRobustListHead=0;
    bool originalGuestSetRobustListAuthenticated=false;
    bool ownedGuestTLSRobustListHeadVerified=false;
    bool noGuestRobustListMemoryWrittenOnRegistration=true;
    bool noHostRobustListSyscallOrFutexWake=true;
    bool noGuestThreadExitSideEffects=true;
  };
  // Genuine original GNU ld-linux x86 syscall set_robust_list(273):
  // head=anon_8k_base+0x13a0 = FS+0x2e0, len=24. This merely
  // registers a per-guest-thread robust futex list head; kernel
  // fixups/wakeups belong to a future verified x86 guest task exit,
  // NEVER guest registration. This G0 probe has no complete futex,
  // clone or guest task scheduler and must not call native
  // set_robust_list(2) with an x86 guest pointer.
  OriginalLdsoRobustListResult
  RegisterOriginalLdsoGuestRobustList(
      const kernix::g2e::c1::TrapClassification& t,
      const kernix::g2e::c3d7b::NativeChosenPIEGuestLayout& owner,
      const kernix::g2e::c3d7g::PermissionPlan& rights,
      const kernix::g2e::c3d7g::ApplyWitness& wx) noexcept {
    namespace c1=kernix::g2e::c1;
    OriginalLdsoRobustListResult out{};
    constexpr size_t kLibc=2;
    constexpr uint64_t kRobustListRelativeFS=0x2e0ULL;
    constexpr uint64_t kX86RobustListHeadBytes=24;
    if(!bound_ || !originalLibcClosedAfterBSS_ ||
       !originalPostCloseFSBaseVerified_ ||
       !originalPostCloseClearChildTIDVerified_ ||
       originalPostCloseRobustListVerified_ ||
       !source_[kLibc].readOnlySnapshot() ||
       !source_[kLibc].bytes() ||
       source_[kLibc].size()!=kSources[kLibc].size ||
       !rights.sourceShaVerified || !rights.nativeGuestVAIdentityOwned ||
       !rights.allPTLoadPagesPlanned || !rights.deniedWritableExecutablePages ||
       !wx.originalPinnedSourceValidated ||
       !wx.nativeNoWritableExecutablePage ||
       !wx.nativeNonPTLoadHolesDenied || wx.androidDeviceTested ||
       owner.WindowsHeld()!=4 || !owner.Module(kLibc) ||
       !owner.LaunchPlan() || OpenCount()!=0 ||
       !largeLibcROMap_.OriginalSourceTextRXSealed() ||
       !largeLibcROMap_.OriginalSourceReadOnlyPTLoadConfirmed() ||
       !largeLibcROMap_.OriginalSourceWritablePTLoadConfirmed() ||
       !largeLibcROMap_.OriginalOwnedBSSZeroed() ||
       largeLibcROMap_.Address()==0 ||
       largeLibcROMap_.BytesHeld()!=0x212000ULL ||
       postCloseAnonymousGuestVM_.Count()!=1 ||
       postCloseAnonymousGuestVM_.AllocatedRequestedBytes()!=8192 ||
       !t.trapBoundaryAuthenticated || !t.sourceRegisterMappingChecked ||
       t.hostSyscallDispatched || t.guestMemoryDereferenced ||
       t.guestNumber!=c1::kSetRobustList ||
       t.category!=c1::CallCategory::NeedsGuestKernel ||
       t.args[1]!=kX86RobustListHeadBytes ||
       originalPostCloseFSBase_>UINT64_MAX-kRobustListRelativeFS ||
       t.args[0]!=originalPostCloseFSBase_+kRobustListRelativeFS ||
       originalPostCloseClearChildTID_!=originalPostCloseFSBase_+0x2d0ULL ||
       (t.args[0]&7ULL)!=0 ||
       !c1::GuestRange(t.args[0],kX86RobustListHeadBytes))
      return out;
    const auto guestOwner=postCloseAnonymousGuestVM_.AuthenticatedRW(
        t.args[0],kX86RobustListHeadBytes);
    if(!guestOwner.attested || !guestOwner.guestRead ||
       !guestOwner.guestWrite || guestOwner.guestExecute ||
       guestOwner.start>originalPostCloseFSBase_ ||
       originalPostCloseFSBase_>=guestOwner.pastLast ||
       guestOwner.pastLast-guestOwner.start!=8192 ||
       originalPostCloseFSBase_-guestOwner.start!=0x10c0ULL)
      return out;
    // This service records *only* the guest-thread pointer; it does
    // not traverse, mutate or wake any robust futex nodes at registration.
    originalPostCloseRobustListHead_=t.args[0];
    originalPostCloseRobustListVerified_=true;
    out.authenticatedGuestRobustListHead=t.args[0];
    out.originalGuestSetRobustListAuthenticated=true;
    out.ownedGuestTLSRobustListHeadVerified=true;
    out.guestReturn=0;
    return out;
  }
  bool OriginalLdsoRobustListVerified() const noexcept {
    return originalPostCloseRobustListVerified_;
  }
  uint64_t OriginalLdsoRobustListHead() const noexcept {
    return originalPostCloseRobustListHead_;
  }
  const PinnedLibcLargeReadonlyGuestMap&
  OriginalLibcLargeReadonlyMap() const noexcept {return largeLibcROMap_;}
  Result Dispatch(const kernix::g2e::c1::TrapClassification& trap,
                  BoundedGuestAnonymousVM& guestVM) noexcept {
    namespace c1=kernix::g2e::c1;
    Result r{};
    if(!bound_ || !trap.trapBoundaryAuthenticated ||
       !trap.sourceRegisterMappingChecked ||
       trap.hostSyscallDispatched || trap.guestMemoryDereferenced)
       return r;
    const uint64_t n=trap.guestNumber;
    if(n!=c1::kOpenat && n!=c1::kRead && n!=c1::kPread64 &&
       n!=c1::kClose && n!=c1::kMmap)return r;
    r.guestSyscallAuthenticated=true;
    if(n==c1::kOpenat){
      // Source x86 guest kernel AT_FDCWD=-100 (sign extended).
      // Linux guest O_RDONLY|O_CLOEXEC only; no arbitrary flags/mode.
      constexpr uint64_t kGuestATFDCWD=static_cast<uint64_t>(
                                             static_cast<int64_t>(-100));
      constexpr uint64_t kGuestCloexec=0x80000ULL;
      if(trap.args[0]!=kGuestATFDCWD ||
         trap.args[2]!=kGuestCloexec || trap.args[3]!=0) {
        r.guestReturn=-22;return r;
      }
      std::array<char,96> path{};
      bool complete=false;
      for(size_t i=0;i<path.size();++i){
        const uint64_t at=trap.args[1]+i;
        if(at<trap.args[1] || !c1::GuestRange(at,1)){
          r.guestReturn=-14;return r;
        }
        const auto valid=guestVM.AuthenticatedRW(at,1);
        if(!valid.attested || !valid.guestRead || valid.guestExecute){
          r.guestReturn=-14;return r;
        }
        std::memcpy(&path[i],
           reinterpret_cast<const void*>(static_cast<uintptr_t>(at)),1);
        if(path[i]=='\0'){complete=true;break;}
      }
      if(!complete){r.guestReturn=-36;return r;} // ENAMETOOLONG
      const std::string_view requested(path.data());
      size_t imageIndex=source_.size();
      for(size_t i=0;i<kSources.size();++i){
        if(requested==kSources[i].name){imageIndex=i;break;}
      }
      if(imageIndex==source_.size()){
        r.guestReturn=-2;return r; // ENOENT, NEVER host search
      }
      for(size_t i=0;i<open_.size();++i){
        if(open_[i].active)continue;
        open_[i]={true,imageIndex,0};
        r.openedPinnedReadonlySnapshot=true;
        r.guestReturn=kGuestBaseFD+static_cast<int64_t>(i);
        return r;
      }
      r.guestReturn=-24;return r; // EMFILE
    }
    if(n==c1::kMmap){
      // The synthetic fd is x86 syscall R8 (arg4), NOT Linux/Bionic
      // native FD and NEVER host-file MAP_PRIVATE. Materialize exactly
      // source-pinned bytes in the existing guest owner VMA manager.
      // Callers MUST route file-backed mmap here before the anonymous
      // allocator; no Linux guest syscall forwarding to the host.
      const uint64_t rawFD=trap.args[4];
      const int64_t fd=static_cast<int64_t>(rawFD);
      if(fd<kGuestBaseFD ||
         fd>=kGuestBaseFD+static_cast<int64_t>(open_.size())){
        r.guestReturn=-9;return r;
      }
      const auto& file=open_[static_cast<size_t>(fd-kGuestBaseFD)];
      if(!file.active || file.sourceIndex>=source_.size()){
        r.guestReturn=-9;return r;
      }
      const auto& image=source_[file.sourceIndex];
      if(!image.readOnlySnapshot() || !image.bytes()){
        r.guestReturn=-5;return r;
      }
      const bool requestedRX=trap.args[2]==(PROT_READ|PROT_EXEC);
      if(requestedRX && !OriginalSourceRXFullPageAuthorized(
                             image.bytes(),image.size(),
                             trap.args[5],trap.args[1])){
        r.guestReturn=-22;return r;
      }
      const auto mapped=guestVM.MapTrustedSourceReadonly(
          trap,image.bytes(),image.size(),requestedRX);
      r.guestReturn=mapped.guestReturn;
      r.readonlySourceELFSnapshotMapped=mapped.guestReadonlySourceELFPageMapped;
      r.guestReadonlySourceELFNativeProtectionApplied=
          mapped.nativeSourceSnapshotSealedReadOnly;
      r.executableSourceELFSnapshotMapped=
          mapped.guestExecutableSourceELFPageMapped;
      r.guestExecutableSourceELFNativeProtectionApplied=
          mapped.nativeSourceSnapshotSealedExecutable;
      return r;
    }
    const int64_t signedFd=static_cast<int64_t>(trap.args[0]);
    if(signedFd<kGuestBaseFD ||
       signedFd>=kGuestBaseFD+static_cast<int64_t>(open_.size())){
      r.guestReturn=-9;return r; // EBADF
    }
    auto& slot=open_[static_cast<size_t>(signedFd-kGuestBaseFD)];
    if(!slot.active || slot.sourceIndex>=source_.size()){
      r.guestReturn=-9;return r;
    }
    if(n==c1::kClose){
      slot={};r.guestFdClosed=true;r.guestReturn=0;return r;
    }
    const uint64_t ptr=trap.args[1],requested=trap.args[2];
    if(requested>kMaxRead){
      r.guestReturn=-22;return r;
    }
    if(!requested){r.guestReturn=0;return r;}
    const auto owner=guestVM.AuthenticatedRW(ptr,requested);
    if(!owner.attested || !owner.guestRead || !owner.guestWrite ||
       owner.guestExecute){
      r.guestReturn=-14;return r; // EFAULT
    }
    const auto& snapshot=source_[slot.sourceIndex];
    if(!snapshot.readOnlySnapshot() || !snapshot.bytes()){
      r.guestReturn=-5;return r;
    }
    const uint64_t offset=n==c1::kPread64?trap.args[3]:slot.position;
    const uint64_t sourceSize=static_cast<uint64_t>(snapshot.size());
    if(offset>static_cast<uint64_t>(INT64_MAX)){
      r.guestReturn=-22;return r;
    }
    if(offset>=sourceSize){r.guestReturn=0;return r;}
    const size_t count=static_cast<size_t>(
        std::min<uint64_t>(requested,sourceSize-offset));
    // Copy only bytes from the source-verified immutable guest ELF
    // snapshot into previously authenticated native-owned guest RW.
    std::memcpy(reinterpret_cast<void*>(static_cast<uintptr_t>(ptr)),
                snapshot.bytes()+static_cast<size_t>(offset),count);
    if(n==c1::kRead)slot.position=offset+count;
    r.copiedSnapshotToAuthenticatedGuestWritable=true;
    r.guestReturn=static_cast<int64_t>(count);
    return r;
  }
 private:
  // Real ELF64 original x86-64 program headers, not path names or
  // fixed hardcoded offsets, authorize an ENTIRE native-host-page
  // source span. Reject mixed PF_W/PF_X, file end, non-PT_LOAD,
  // malformed sections, integer overflow and partial guest 4K/host16K.
  // ELF64 program headers are untrusted until the snapshot's SHA256
  // was independently verified by Capture() at trusted startup.
  static bool OriginalSourceRXFullPageAuthorized(
      const uint8_t* bytes,size_t length,
      uint64_t fileOffset,uint64_t requested) noexcept {
    if(!bytes || length<sizeof(Elf64_Ehdr) ||
       !requested || fileOffset>UINT64_MAX-requested ||
       fileOffset+requested>length)return false;
    Elf64_Ehdr elf{};
    std::memcpy(&elf,bytes,sizeof(elf));
    if(std::memcmp(elf.e_ident,ELFMAG,SELFMAG)!=0 ||
       elf.e_ident[EI_CLASS]!=ELFCLASS64 ||
       elf.e_ident[EI_DATA]!=ELFDATA2LSB ||
       elf.e_ident[EI_VERSION]!=EV_CURRENT ||
       elf.e_machine!=EM_X86_64 ||
       (elf.e_type!=ET_EXEC && elf.e_type!=ET_DYN) ||
       elf.e_phentsize!=sizeof(Elf64_Phdr) ||
       elf.e_phnum==0 || elf.e_phnum>64 ||
       elf.e_phoff>length ||
       static_cast<uint64_t>(elf.e_phnum)>
        (length-elf.e_phoff)/sizeof(Elf64_Phdr))return false;
    for(uint16_t i=0;i<elf.e_phnum;++i){
      Elf64_Phdr ph{};
      const auto at=static_cast<size_t>(elf.e_phoff)+
                    static_cast<size_t>(i)*sizeof(ph);
      std::memcpy(&ph,bytes+at,sizeof(ph));
      if(ph.p_type!=PT_LOAD ||
         (ph.p_flags&(PF_R|PF_W|PF_X))!=(PF_R|PF_X) ||
         ph.p_filesz==0 || ph.p_filesz>ph.p_memsz ||
         ph.p_offset>length || ph.p_filesz>length-ph.p_offset ||
         (ph.p_vaddr%4096)!=(ph.p_offset%4096))continue;
      if(fileOffset>=ph.p_offset &&
         requested<=ph.p_filesz-(fileOffset-ph.p_offset))
        return true;
    }
    return false;
  }
  struct OriginalSource {
    std::string_view name;
    size_t size;
    const char* sha;
  };
  static constexpr std::array<OriginalSource,3> kSources{{
    {"/bin/kernix-g2e-dynamic-guest",15976,
      "9fb072db2732c7c6a1b2a53bd946d54904feaac5980e0d79b39f7ce300784412"},
    {"/lib64/ld-linux-x86-64.so.2",235408,
      "cff2a563ca82b90beb5c43db38b84efe0c610a9a0e3394083882abcf8431fbae"},
    {"/lib/x86_64-linux-gnu/libc.so.6",2118168,
      "7e262ac92a454f36664b9c95a8927ecc4fb0f0f007206c2613b1e9ce14e76906"}
  }};
  struct OpenSlot {bool active=false;size_t sourceIndex=0;uint64_t position=0;};
  std::array<kernix::g2c::ReadonlyGuestSnapshot,3> source_{};
  std::array<OpenSlot,kMaxGuestOpenSlots> open_{};
  PinnedLibcLargeReadonlyGuestMap largeLibcROMap_{};
  BoundedGuestAnonymousVM postCloseAnonymousGuestVM_{};
  bool originalPostCloseFSBaseVerified_=false;
  uint64_t originalPostCloseFSBase_=0;
  bool originalPostCloseClearChildTIDVerified_=false;
  uint64_t originalPostCloseClearChildTID_=0;
  bool originalPostCloseRobustListVerified_=false;
  uint64_t originalPostCloseRobustListHead_=0;
  bool originalLibcClosedAfterBSS_=false;
  bool bound_=false;
};
} // namespace kernix::g0
