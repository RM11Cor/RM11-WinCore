#pragma once
// SPDX-License-Identifier: MIT
// KERNIX G0 original x86_64 dynamic guest file table: 3 source-SHA256
// verified, immutable anonymous RX-free snapshots, never guest paths.
// This is NOT yet the fully running guest ld-linux+glibc process.
#include "kernix_g2e_pinned_glibc_preflight.h"
#include "kernix_g2e_c1_x86_linux_syscall_boundary.h"
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <string>
#include <sys/mman.h>
#include <unistd.h>

namespace kernix::g0 {
class OriginalGuestSnapshotTable final {
public:
  struct Result {
    int64_t linuxReturn=-38;
    bool authenticated=false;
    bool readFromImmutableSnapshot=false;
    bool guestWritableSpanValidated=false;
    bool guestFdClosed=false;
    bool anyHostSyscallForwarded=false;
  };
  OriginalGuestSnapshotTable()=default;
  OriginalGuestSnapshotTable(const OriginalGuestSnapshotTable&)=delete;
  OriginalGuestSnapshotTable& operator=(const OriginalGuestSnapshotTable&)=delete;
  ~OriginalGuestSnapshotTable(){Reset();}
  void Reset() noexcept {
    for(auto& f:files_) {
      if(f.memory) ::munmap(f.memory,f.bytes);
      f={};
    }
    mounted_=false;
  }

  // Actual production entry: root was opened by the Android supervisor under
  // its private owned no-symlink directory. Validate() independently checks
  // the precise *original* x86 main/ld-linux/glibc triad + SHA256 + closure.
  // Copy its read-only snapshots into *independently owned* anonymous memory.
  // After Validate's snapshots are released, no mutable disk FD remains.
  bool MountVerifiedAppPrivateOriginalRoot(int privateRootFD,
                                            std::string& reason) {
    Reset();
    kernix::g2e::GuestPreflight pinned;
    if(!kernix::g2e::Validate(privateRootFD,pinned,reason) ||
       !pinned.exactSha256Matched ||
       !pinned.readOnlyAnonymousSnapshots ||
       !pinned.exactInterpreterAndGlibcClosure ||
       pinned.guestCodeExecuted || pinned.dynamicLinkerExecuted ||
       pinned.fexAttached || pinned.wineExecuted) {
      reason="G0_ORIGINAL_GUEST_SNAPSHOT_SOURCE_OR_CLOSURE_NOT_VERIFIED";
      return false;
    }
    std::array<View,3> inputs{};
    for(size_t i=0;i<inputs.size();++i) {
      const auto& snap=pinned.snapshots[i];
      if(!snap.readOnlySnapshot() || !snap.bytes() ||
         snap.size()!=kernix::g2e::kGuest[i].bytes) {
        reason="G0_ORIGINAL_GUEST_SNAPSHOT_SIZE_NOT_PINNED";
        return false;
      }
      inputs[i]={snap.bytes(),snap.size()};
    }
    return MountOwnedCopies(inputs,reason);
  }

#ifdef KERNIX_G0_SNAPSHOT_TABLE_UNIT_TEST_ONLY
  // This constructor does NOT exist in release/Android integration builds.
  // Unit test synthetic data cannot assert source-pinned Linux guest proof.
  bool MountSyntheticBytesForHostUnitTest(
      const std::array<std::pair<const uint8_t*,size_t>,3>& data,
      std::string& reason) {
    std::array<View,3> views{};
    for(size_t i=0;i<3;++i)views[i]={data[i].first,data[i].second};
    return MountOwnedCopies(views,reason);
  }
#endif

  // Guest Linux read(0), pread64(17), close(3) for fixed virtual 3/4/5.
  // Linux x86 R10 is pread offset, NOT RCX; the C1 trap decoded it.
  // File IDs are installed by the verified host, not path-opened by guest.
  Result Dispatch(const kernix::g2e::c1::TrapClassification& trap,
                  const kernix::g2e::c1::GuestVmInterval& guestWritable) noexcept {
    using namespace kernix::g2e::c1;
    Result result{};
    if(!mounted_ || !trap.trapBoundaryAuthenticated ||
       !trap.sourceRegisterMappingChecked || trap.hostSyscallDispatched ||
       trap.guestMemoryDereferenced) return result;
    if(trap.guestNumber!=kRead && trap.guestNumber!=kPread64 &&
       trap.guestNumber!=kClose) return result;
    const uint64_t virtualFD=trap.args[0];
    if(virtualFD<3 || virtualFD>5) {result.linuxReturn=-9;return result;}
    auto& file=files_[static_cast<size_t>(virtualFD-3)];
    if(!file.open || !file.memory || !file.bytes) {
      result.linuxReturn=-9;return result;
    }
    result.authenticated=true;
    if(trap.guestNumber==kClose) {
      file.open=false;
      result.linuxReturn=0;
      result.guestFdClosed=true;
      return result;
    }
    const uint64_t dst=trap.args[1],wanted=trap.args[2];
    if(wanted>4096) {result.linuxReturn=-22;return result;}
    const uint64_t offset=trap.guestNumber==kPread64 ?
         trap.args[3] : file.offset;
    if(offset>static_cast<uint64_t>(std::numeric_limits<int64_t>::max())) {
      result.linuxReturn=-22;return result;
    }
    if(!wanted || offset>=file.bytes) {
      result.linuxReturn=0;return result;
    }
    // Check full requested destination span, not only its EOF-clamped
    // subset, to reject guest VM escapes and unverified regions.
    if(!PinnedGuestSpan(dst,wanted,GuestDataAccess::Write,guestWritable)) {
      result.linuxReturn=-14;return result;
    }
    result.guestWritableSpanValidated=true;
    const uint64_t available=file.bytes-offset;
    const size_t count=static_cast<size_t>(wanted<available?wanted:available);
    std::memcpy(reinterpret_cast<void*>(static_cast<uintptr_t>(dst)),
      static_cast<const uint8_t*>(file.memory)+offset,count);
    if(trap.guestNumber==kRead)file.offset=offset+count;
    result.readFromImmutableSnapshot=true;
    result.linuxReturn=static_cast<int64_t>(count);
    return result;
  }
  bool Mounted() const noexcept {return mounted_;}
private:
  struct View {const uint8_t* bytes=nullptr;size_t size=0;};
  struct Owned {
    void* memory=nullptr;
    size_t bytes=0;
    uint64_t offset=0;
    bool open=false;
  };
  std::array<Owned,3> files_{};
  bool mounted_=false;
  bool MountOwnedCopies(const std::array<View,3>& originals,
                        std::string& reason) {
    Reset();
    constexpr size_t kMaxBytes=4*1024*1024;
    size_t sum=0;
    for(const auto& original:originals) {
      if(!original.bytes || original.size<1 ||
         original.size>kMaxBytes-sum) {
        reason="G0_SOURCE_FILE_COUNT_OR_SIZE_REJECTED";
        return false;
      }
      sum+=original.size;
    }
    for(size_t i=0;i<3;++i) {
      const auto& view=originals[i];
      void* memory=::mmap(nullptr,view.size,PROT_READ|PROT_WRITE,
                 MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
      if(memory==MAP_FAILED) {
        reason="G0_IMMUTABLE_SOURCE_COPY_MMAP_FAILED";
        Reset();return false;
      }
      files_[i]={memory,view.size,0,true};
      std::memcpy(memory,view.bytes,view.size);
      if(::mprotect(memory,view.size,PROT_READ)!=0) {
        reason="G0_IMMUTABLE_SOURCE_MPROTECT_FAILED";
        Reset();return false;
      }
    }
    mounted_=true;reason="none";return true;
  }
};
} // namespace kernix::g0
