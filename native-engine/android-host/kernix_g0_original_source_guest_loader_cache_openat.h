#pragma once
// SPDX-License-Identifier: MIT
// GNU ld-linux original x86-64 guest openat(257) for the OPTIONAL
// "/etc/ld.so.cache" virtual file, backed only by an exact triad
// SHA256-pinned guest root (main, interpreter, libc). No host cache
// exists in this virtual root. Fail-closed for every other pathname.
// NEVER invoke host ::openat/access or forward guest pointers/paths.
// This does NOT implement the full dynamic linker or library lookup.
#include "kernix_g2e_c3d7g_native_pt_load_wx_apply_gate.h"
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <sys/fcntl.h>
#include <unistd.h>

namespace kernix::g0::cacheopen {
struct Result {
  int64_t guestReturn=-ENOSYS;
  bool authenticGuestOpenat=false;
  bool originalLdsoSourcePTLoadLiteralValidated=false;
  bool optionalVirtualCacheAbsent=false;
  bool originalTriadSourceClosureAttested=false;
  bool nativeHostOpenatCalled=false;
  bool guestPointerOrPathForwardedToHost=false;
  bool unsupportedRequestRejected=true;
};
inline Result DispatchOriginalLoaderOptionalCacheOpenat(
    const kernix::g2e::c1::TrapClassification& t,
    const kernix::g2e::c3d7b::NativeChosenPIEGuestLayout& guest,
    const kernix::g2e::c3d7g::PermissionPlan& rights,
    const kernix::g2e::c3d7g::ApplyWitness& wx,
    bool exactSourceMainInterpreterLibcTriadVerified) noexcept {
  namespace c1=kernix::g2e::c1;
  namespace g=kernix::g2e::c3d7g;
  Result r{};
  // mov edi, -100 zero-extends the low 32 bits on original x86-64:
  // both the zero-extended and sign-extended forms represent AT_FDCWD.
  constexpr uint64_t kGuestATFDCWSigned=UINT64_MAX-99;
  constexpr uint64_t kGuestATFDCWZero32=UINT32_MAX-99;
  constexpr uint64_t kGuestReadOnlyCloexec=0x80000ULL;
  if(::sysconf(_SC_PAGESIZE)!=4096 ||
     !exactSourceMainInterpreterLibcTriadVerified ||
     !t.trapBoundaryAuthenticated ||
     !t.sourceRegisterMappingChecked ||
     t.hostSyscallDispatched || t.guestMemoryDereferenced ||
     t.guestNumber!=c1::kOpenat ||
     t.category!=c1::CallCategory::NeedsGuestKernel ||
     (t.args[0]!=kGuestATFDCWSigned &&
      t.args[0]!=kGuestATFDCWZero32) ||
     t.args[2]!=kGuestReadOnlyCloexec ||
     !rights.sourceShaVerified ||
     !rights.nativeGuestVAIdentityOwned ||
     !rights.allPTLoadPagesPlanned ||
     !rights.deniedWritableExecutablePages ||
     !wx.originalPinnedSourceValidated ||
     !wx.nativeNoWritableExecutablePage ||
     !wx.nativeNonPTLoadHolesDenied ||
     wx.androidDeviceTested ||
     guest.WindowsHeld()!=4 || !guest.Module(1) ||
     !guest.LaunchPlan())return r;

  const auto* ldso=guest.Module(1);
  const uint64_t ptr=t.args[1];
  constexpr char kOptional[]="/etc/ld.so.cache";
  if(ptr<ldso->chosenImageStart ||
     ptr-ldso->chosenImageStart>=
       kernix::g2e::c3d7b::kImageCapacity ||
     (ptr&4095)>4096-sizeof(kOptional))return r;
  const size_t pg=static_cast<size_t>(
      (ptr-ldso->chosenImageStart)/4096);
  if(pg>=g::kModulePages ||
     (rights.modules[1].rights[pg]!=g::kRead &&
      rights.modules[1].rights[pg]!=(g::kRead|g::kExecute)))
      return r;
  const char* path=reinterpret_cast<const char*>(
      guest.GuestReadOnlyBytes(1,ptr,sizeof(kOptional)));
  if(!path ||
     std::memcmp(path,kOptional,sizeof(kOptional))!=0)return r;

  // Empty cache is not an implementation of library resolution.
  // It merely makes one optional cache probe return the Linux guest
  // ENOENT a kernel would return for this exact private triad root.
  // The real loader must then continue its own normal library search.
  r.authenticGuestOpenat=true;
  r.originalLdsoSourcePTLoadLiteralValidated=true;
  r.optionalVirtualCacheAbsent=true;
  r.originalTriadSourceClosureAttested=true;
  r.guestReturn=-ENOENT;
  r.unsupportedRequestRejected=false;
  return r;
}
} // namespace kernix::g0::cacheopen
