#pragma once
// SPDX-License-Identifier: MIT
// Linux x86-64 guest access(21) special optional GNU ld-linux file
// probe. Source pathname must be NUL terminated in ONE previously
// SHA-attested, read-only or executable PT_LOAD *of original ld-linux*.
// It never forwards the guest pathname or guest pointers to native
// Android/Linux ::access, faccessat, open or arbitrary host FS APIs.
//
// The pinned isolated root has ONLY exact original GNU main, ldlinux
// and libc ELF files. In particular /etc/ld.so.preload is ABSENT,
// so Linux guest access("/etc/ld.so.preload", R_OK) must return -ENOENT.
// Other paths, modes, writable source and malformed pointers fail
// closed as unsupported, not accidentally expose a native host file.
#include "kernix_g2e_c3d7g_native_pt_load_wx_apply_gate.h"
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <sys/mman.h>
#include <unistd.h>

namespace kernix::g0::access21 {
struct Result {
  int64_t guestReturn=-ENOSYS;
  bool trustedGuestAccess=false;
  bool guestSourceLdlinuxPTLoadLiteralRead=false;
  bool optionalVirtualPreloadAbsent=false;
  bool nativeHostFileAccessCalled=false;
  bool guestPointerPassedToNativeHost=false;
  bool requestDenied=true;
};
inline Result DispatchOriginalLoaderOptionalAccess(
    const kernix::g2e::c1::TrapClassification& t,
    const kernix::g2e::c3d7b::NativeChosenPIEGuestLayout& guest,
    const kernix::g2e::c3d7g::PermissionPlan& rights,
    const kernix::g2e::c3d7g::ApplyWitness& wx) noexcept {
  namespace c1=kernix::g2e::c1;
  namespace g=kernix::g2e::c3d7g;
  Result r{};
  if(::sysconf(_SC_PAGESIZE)!=4096 ||
     !t.trapBoundaryAuthenticated || !t.sourceRegisterMappingChecked ||
     t.hostSyscallDispatched || t.guestMemoryDereferenced ||
     t.guestNumber!=c1::kAccess ||
     t.category!=c1::CallCategory::NeedsGuestKernel ||
     !rights.sourceShaVerified ||
     !rights.nativeGuestVAIdentityOwned ||
     !rights.allPTLoadPagesPlanned ||
     !rights.deniedWritableExecutablePages ||
     !wx.originalPinnedSourceValidated ||
     !wx.nativeNoWritableExecutablePage ||
     !wx.nativeNonPTLoadHolesDenied ||
     wx.androidDeviceTested ||
     guest.WindowsHeld()!=4 ||
     !guest.Module(1) || !guest.LaunchPlan() ||
     t.args[1]!=R_OK)
      return r;
  const auto* ldso=guest.Module(1);
  const uint64_t ptr=t.args[0];
  if(ptr<ldso->chosenImageStart ||
     ptr-ldso->chosenImageStart>=
       kernix::g2e::c3d7b::kImageCapacity)return r;
  const size_t page=static_cast<size_t>(
      (ptr-ldso->chosenImageStart)/4096);
  if(page>=g::kModulePages ||
     !(rights.modules[1].rights[page]==g::kRead ||
       rights.modules[1].rights[page]==(g::kRead|g::kExecute)))
     return r;
  const uint64_t room=4096-(ptr&4095);
  constexpr char kOptional[]="/etc/ld.so.preload";
  if(room<sizeof(kOptional))return r;
  const char* path=reinterpret_cast<const char*>(
      guest.GuestReadOnlyBytes(1,ptr,sizeof(kOptional)));
  if(!path || std::memcmp(path,kOptional,sizeof(kOptional))!=0)
      return r;
  r.trustedGuestAccess=true;
  r.guestSourceLdlinuxPTLoadLiteralRead=true;
  r.optionalVirtualPreloadAbsent=true;
  r.guestReturn=-ENOENT; // exact user-isolated virtual source root
  r.requestDenied=false;
  return r;
}
} // namespace kernix::g0::access21
