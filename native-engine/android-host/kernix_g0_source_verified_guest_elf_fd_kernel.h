#pragma once
// SPDX-License-Identifier: MIT
// G0: bounded Linux x86 guest openat(257), read(0), pread64(17),
// close(3) for EXACT three original source SHA256 verified ELF snapshots.
// This is a DATA-ONLY guest service, NOT full GNU ld-linux startup.
// NEVER pass any guest pathname, guest fd or host memory pointer into
// native openat/read/pread/close; only trusted native bootstrap owns FDs.
// It reuses the existing G2C immutable anonymous PROT_READ snapshots
// and G0 owner-held guest VM instead of creating parallel VMA allocators.
#include "kernix_g2c_native_readonly_guest_snapshots.h"
#include "kernix_g0_guest_owned_anonymous_vm_kernel.h"
#include <array>
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
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
    bool hostPathOpened=false;
    bool hostGuestFdForwarded=false;
    bool hostAnyUntrustedSyscallForwarded=false;
  };
  SourceVerifiedGuestElfFDKernel()=default;
  SourceVerifiedGuestElfFDKernel(const SourceVerifiedGuestElfFDKernel&)=delete;
  SourceVerifiedGuestElfFDKernel& operator=(const SourceVerifiedGuestElfFDKernel&)=delete;
  ~SourceVerifiedGuestElfFDKernel()=default;
  void Reset() noexcept {
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
  Result Dispatch(const kernix::g2e::c1::TrapClassification& trap,
                  const BoundedGuestAnonymousVM& guestVM) noexcept {
    namespace c1=kernix::g2e::c1;
    Result r{};
    if(!bound_ || !trap.trapBoundaryAuthenticated ||
       !trap.sourceRegisterMappingChecked ||
       trap.hostSyscallDispatched || trap.guestMemoryDereferenced)
       return r;
    const uint64_t n=trap.guestNumber;
    if(n!=c1::kOpenat && n!=c1::kRead && n!=c1::kPread64 &&
       n!=c1::kClose)return r;
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
  bool bound_=false;
};
} // namespace kernix::g0
