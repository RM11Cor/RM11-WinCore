#pragma once
// SPDX-License-Identifier: MIT
// C3-D8A bounded ORIGINAL x86 Linux ldso -> Android/Bionic handoff
// preparation gate. Source-pinned ELF, native guest-identity page
// permissions and authentic original data targets. NO GUEST EXECUTION.
// Fail-closed: never create a FEX guest context or launch Wine,
// never patch original code, page RWX or write source ELF files.
#include "kernix_g2e_c3d7g_native_pt_load_wx_apply_gate.h"
#include "kernix_g2e_c3d7n_original_ldso_call_source_target_gate.h"
#include <array>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <elf.h>
#include <fcntl.h>
#include <limits>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
namespace kernix::g2e::c3d8a {
struct Witness {
  uint32_t originalModules=0;
  uint32_t sourceCheckedPTLoadSegments=0;
  uint32_t nativeProtectedModules=0;
  uint64_t originalLdsoGuestEntry=0;
  uint64_t originalLdsoGuestCallTarget=0;
  uint64_t originalGuestStackRSP=0;
  uint64_t originalRWGuestTarget=0;
  uint64_t originalRSIGuestTarget=0;
  bool sourceSHA256Locked=false;
  bool fileBackedPTLoadBytesMatch=true;
  bool originalOpcodeANDAndLEAWhitelisted=false;
  bool originalRWPTLoadDataAddressOwned=false;
  bool originalRSIPointerOwned=false;
  bool allNativeWXRejected=false;
  bool guardedGuestStackProtected=false;
  bool originalMemoryReleased=false;
  bool guestExecutionAttempted=false;
  bool originalLoaderStarted=false;
  bool androidDeviceExecuted=false;
};
// Full-source equality across the *file-backed* PT_LOAD bytes of all
// three authenticated ELF images. Shared source headers have separately
// checked 4K/16K permission and PT_GNU_RELRO policy; this gate must not
// infer their completion from a boolean.
inline bool FileBackedSegmentsUnchanged(
    const GuestPreflight& originals,
    const c3d7b::NativeChosenPIEGuestLayout& owned,
    uint32_t& checked) noexcept {
  checked=0;
  for(size_t i=0;i<3;++i) {
    const auto& snap=originals.snapshots[i];
    const auto* m=owned.Module(i);
    if(!m || !snap.readOnlySnapshot() || !snap.bytes() ||
       snap.size()<sizeof(Elf64_Ehdr))return false;
    Elf64_Ehdr eh{};
    std::memcpy(&eh,snap.bytes(),sizeof(eh));
    if(eh.e_type!=ET_DYN || eh.e_machine!=EM_X86_64 ||
       eh.e_phentsize!=sizeof(Elf64_Phdr) ||
       eh.e_phoff>snap.size() ||
       uint64_t(eh.e_phnum)*sizeof(Elf64_Phdr)>snap.size()-eh.e_phoff)
      return false;
    for(uint16_t j=0;j<eh.e_phnum;++j) {
      Elf64_Phdr ph{};
      std::memcpy(&ph,snap.bytes()+eh.e_phoff+
          size_t(j)*sizeof(ph),sizeof(ph));
      if(ph.p_type!=PT_LOAD || ph.p_filesz==0)continue;
      if(ph.p_vaddr>UINT64_MAX-m->loadBias ||
         ph.p_offset>snap.size() ||
         ph.p_filesz>snap.size()-ph.p_offset ||
         ph.p_filesz>c3d7b::kImageCapacity)return false;
      const auto* addr=owned.GuestReadOnlyBytes(
          i,m->loadBias+ph.p_vaddr,static_cast<size_t>(ph.p_filesz));
      if(!addr || std::memcmp(addr,snap.bytes()+ph.p_offset,
          static_cast<size_t>(ph.p_filesz))!=0)return false;
      ++checked;
    }
  }
  return checked>=3;
}
inline bool ValidatePrivateRootFD(int fd) noexcept {
  struct stat st{};
  return fd>=0 && ::fstat(fd,&st)==0 && S_ISDIR(st.st_mode) &&
     st.st_uid==::getuid() && !(st.st_mode&(S_IWGRP|S_IWOTH));
}
// No result ever labels Android device execution or original ldso
// startup; this is an ABI and native page-ownership handoff barrier.
inline bool PrepareOriginalOwnedGuestHandoffNoExecute(
    int privateRootFd, const std::array<uint8_t,16>& entropy,
    Witness& out, bool failFirstNativeMprotect=false) {
  out={};
  if(!ValidatePrivateRootFD(privateRootFd) ||
     ::sysconf(_SC_PAGESIZE)!=4096)return false;
  GuestPreflight source;
  std::string why;
  if(!Validate(privateRootFd,source,why))return false;
  c3d7b::NativeChosenPIEGuestLayout layout;
  c3d7b::Witness stage;
  if(!layout.Stage(privateRootFd,entropy,stage) ||
     !stage.pinnedOriginalELFSHA256Verified ||
     !stage.guestAddressEqualsOwnedHostPage ||
     !stage.linuxAuxvRebased ||
     !stage.originalBytesCopiedReadOnly ||
     stage.originalFEXGuestMemoryAttached ||
     stage.originalLdsoExecuted || stage.originalELFCodeExecuted) {
    (void)layout.Release();return false;
  }
  out.originalModules=3;
  out.sourceSHA256Locked=true;
  out.originalGuestStackRSP=stage.x86RebasedStackRSP;
  c3d7g::PermissionPlan rights;
  c3d7g::Reject rejected;
  if(!c3d7g::BuildVerifiedOriginalPermissionPlan(
       source,layout,rights,rejected)) {
    (void)layout.Release();return false;
  }
  c3d7n::CallProof call;
  c3d7n::Reject callError;
  if(!c3d7n::VerifyAuthenticLdsoSecondCallTarget(
       source,layout,rights,call,callError)) {
    (void)layout.Release();return false;
  }
  out.originalLdsoGuestEntry=call.originalEntry;
  out.originalLdsoGuestCallTarget=call.originalTarget;
  // Read exactly 14 source-locked original instruction bytes.
  // ELF 0x20221 AND byte [RIP+0x18bde],0xdf targets ELF 0x38e06.
  // ELF 0x20228 LEA RSI,[RIP+0x188c1] targets ELF 0x38af0.
  constexpr std::array<uint8_t,14> opcodes{
    0x80,0x25,0xde,0x8b,0x01,0x00,0xdf,
    0x48,0x8d,0x35,0xc1,0x88,0x01,0x00};
  if(call.originalTarget>UINT64_MAX-79) {
    (void)layout.Release();return false;
  }
  const auto* originalBytes=layout.GuestReadOnlyBytes(
       1,call.originalTarget+65,opcodes.size());
  if(!originalBytes || std::memcmp(originalBytes,
       opcodes.data(),opcodes.size())!=0) {
    (void)layout.Release();return false;
  }
  out.originalOpcodeANDAndLEAWhitelisted=true;
  const auto* ldso=layout.Module(1);
  if(!ldso || ldso->loadBias>UINT64_MAX-0x38e06) {
    (void)layout.Release();return false;
  }
  // Original signed disp32-derived target ELF offsets previously
  // attested by C3-D7Z runtime CI, independently checked here.
  const uint64_t dataAt=ldso->loadBias+0x38e06;
  const uint64_t rsiAt=ldso->loadBias+0x38af0;
  const auto start=ldso->chosenImageStart;
  if(dataAt<start || rsiAt<start ||
     dataAt-start>=c3d7b::kImageCapacity ||
     rsiAt-start>=c3d7b::kImageCapacity) {
    (void)layout.Release();return false;
  }
  const auto dataPage=(dataAt-start)/4096;
  const auto rsiPage=(rsiAt-start)/4096;
  const auto& p=rights.modules[1].rights;
  if(dataPage>=p.size() || rsiPage>=p.size() ||
     p[dataPage]!=(c3d7g::kRead|c3d7g::kWrite) ||
     p[rsiPage]==0 ||
     (p[rsiPage]&(c3d7g::kWrite|c3d7g::kExecute))==
         (c3d7g::kWrite|c3d7g::kExecute)) {
    (void)layout.Release();return false;
  }
  out.originalRWGuestTarget=dataAt;
  out.originalRSIGuestTarget=rsiAt;
  out.originalRWPTLoadDataAddressOwned=true;
  out.originalRSIPointerOwned=true;
  c3d7g::ApplyWitness native;
  const auto injection=failFirstNativeMprotect?size_t{0}:
      std::numeric_limits<size_t>::max();
  if(!c3d7g::ApplyOwnedOriginalPTLoadPagePermissions(
      layout,source,native,injection)) {
    (void)layout.Release();
    out.originalMemoryReleased=(layout.WindowsHeld()==0);
    return false;
  }
  if(native.originalModulesProtected!=3 ||
     !native.nativeNoWritableExecutablePage ||
     !native.nativeNonPTLoadHolesDenied ||
     !native.nativeStackGuardDenied ||
     !native.nativeLinuxStackWritableNonExecutable ||
     !layout.GuestReadOnlyBytes(1,dataAt,1) ||
     !layout.GuestReadOnlyBytes(1,rsiAt,1)) {
    (void)layout.Release();return false;
  }
  out.nativeProtectedModules=3;
  out.allNativeWXRejected=true;
  out.guardedGuestStackProtected=true;
  uint32_t checked=0;
  out.fileBackedPTLoadBytesMatch=FileBackedSegmentsUnchanged(
      source,layout,checked);
  out.sourceCheckedPTLoadSegments=checked;
  const bool good=out.fileBackedPTLoadBytesMatch &&
       checked>=3 && !out.guestExecutionAttempted &&
       !out.originalLoaderStarted && !out.androidDeviceExecuted;
  out.originalMemoryReleased=layout.Release() &&
       layout.WindowsHeld()==0;
  return good && out.originalMemoryReleased;
}
} // namespace kernix::g2e::c3d8a
