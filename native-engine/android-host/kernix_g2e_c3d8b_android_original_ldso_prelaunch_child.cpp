// SPDX-License-Identifier: MIT
// C3-D8B: opt-in physically executed Android/Bionic source-locked
// original x86-64 ld-linux native prelaunch guest owned memory test.
// Standalone, signed-app-private fixed native child, no FEX attach,
// no guest RIP, no Wine/PC games; fails on native !=4096 byte pages.
// Never reads external storage, patches original files or overwrites
// existing installed KERNIX prefix/game data.
#if !defined(__ANDROID__) || !defined(__aarch64__)
#error C3D8B Android/Bionic AArch64 separate child only
#endif
#include "kernix_g2e_c3d8a_original_loader_handoff_barrier.h"
#include <array>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
namespace b=kernix::g2e::c3d8a;
namespace {
constexpr const char kFlag[]=
    "--kernix-c3d8b-signed-original-ldso-prelaunch-android-v1";
void Failure(const char* reason) noexcept {
  std::fprintf(stderr,"KERNIX_C3D8B_ANDROID_PRELAUNCH_FAIL_CLOSED=%s\n",
      reason ? reason : "unknown");
}
bool FixedAppRoot(const char* root) {
  if(!root || root[0]!='/' || std::strlen(root)>2048)return false;
  const std::string path{root};
  if(path.find("..")!=std::string::npos ||
     path.find("//")!=std::string::npos ||
     !path.ends_with("/c3d8b-original-guest"))
    return false;
  // Do not accept a user-selected external/Download path even when it
  // contains a matching basename; files are only app-internal data.
  if(path.starts_with("/sdcard/") ||
     path.starts_with("/storage/") ||
     path.starts_with("/mnt/media_rw/") ||
     path.starts_with("/data/local/tmp/"))return false;
  if(!(path.starts_with("/data/user/0/org.kernix.ldsohandoffprobe/files/") ||
       path.starts_with("/data/data/org.kernix.ldsohandoffprobe/files/")))
    return false;
  return true;
}
}
int main(int argc,char** argv) {
  if(argc!=3 || !argv[1] || std::strcmp(argv[1],kFlag)!=0 ||
     !FixedAppRoot(argv[2])) {
    Failure("wrong_fixed_signed_root_or_flag");return 126;
  }
  if(::sysconf(_SC_PAGESIZE)!=4096) {
    Failure("native_page_size_not_4096_16K_needs_separate_gate");
    return 3;
  }
  const int fd=::open(argv[2],O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
  if(fd<0) { Failure("private_root_open_denied");return 4; }
  if(!b::ValidatePrivateRootFD(fd)) {
    ::close(fd);Failure("private_root_owner_permissions_denied");
    return 5;
  }
  std::array<uint8_t,16> entropy{};
  for(size_t i=0;i<entropy.size();++i)
     entropy[i]=static_cast<uint8_t>(i+1);
  b::Witness denied{};
  if(b::PrepareOriginalOwnedGuestHandoffNoExecute(-1,entropy,denied)) {
    ::close(fd);Failure("invalid_fd_was_allowed");return 6;
  }
  b::Witness injected{};
  if(b::PrepareOriginalOwnedGuestHandoffNoExecute(fd,entropy,injected,true) ||
     !injected.originalMemoryReleased ||
     injected.guestExecutionAttempted || injected.originalLoaderStarted ||
     injected.androidDeviceExecuted) {
    ::close(fd);Failure("native_mprotect_fault_rollback_denied");return 7;
  }
  b::Witness attested{};
  const bool passed=b::PrepareOriginalOwnedGuestHandoffNoExecute(
      fd,entropy,attested);
  ::close(fd);
  if(!passed || attested.originalModules!=3 ||
     attested.nativeProtectedModules!=3 ||
     attested.sourceCheckedPTLoadSegments<3 ||
     !attested.sourceSHA256Locked ||
     !attested.originalOpcodeANDAndLEAWhitelisted ||
     !attested.originalRWPTLoadDataAddressOwned ||
     !attested.originalRSIPointerOwned ||
     !attested.fileBackedPTLoadBytesMatch ||
     !attested.allNativeWXRejected ||
     !attested.guardedGuestStackProtected ||
     !attested.originalMemoryReleased ||
     attested.guestExecutionAttempted ||
     attested.originalLoaderStarted ||
     attested.androidDeviceExecuted) {
     Failure("original_rw_rx_source_or_cleanup_gate_failed");
     return 8;
  }
  // The only success marker. The Java supervisor requires exact ordered
  // lines and process exit 0; it cannot report a device PASS itself.
  std::puts("KERNIX_C3D8B_ANDROID_DEVICE_ORIGINAL_LDSO_PRELAUNCH_MEMORY_PASS");
  std::puts("ORIGINAL_THREE_X86_LINUX_ELF_SHA256_VERIFIED=1");
  std::puts("REAL_ANDROID_BIONIC_ARM64_CHILD_EXECUTED=1");
  std::puts("NATIVE_PAGE_SIZE=4096");
  std::puts("ORIGINAL_LDSO_SOURCE_CALL_TARGET_VERIFIED=1");
  std::puts("ORIGINAL_GUEST_RW_AND_LEA_RSI_SOURCE_VERIFIED=1");
  std::puts("REAL_NATIVE_ORIGINAL_PTLOAD_RX_RW_WX_ENFORCED=1");
  std::puts("REAL_NATIVE_GUEST_STACK_GUARD=1");
  std::puts("NATIVE_MPROTECT_FAULT_ROLLBACK_FOUR_WINDOWS=1");
  std::puts("EXACT_FILE_BACKED_SOURCE_BYTES_PRESERVED=1");
  std::puts("ORIGINAL_GUEST_WINDOWS_ALL_RELEASED=1");
  std::puts("FEX_GUEST_CONTEXT_CREATED=0");
  std::puts("ORIGINAL_LINUX_LDSO_EXECUTED=0");
  std::puts("WINE_OR_WINDOWS_PE_EXECUTED=0");
  return 0;
}
