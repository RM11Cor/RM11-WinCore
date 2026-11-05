// SPDX-License-Identifier: MIT
// C3-D7I Android/Bionic ARM64 ABI COMPILE-ONLY GATE. Inspect and bound
// SHA-locked original x86_64 Linux ELF dynamic RELA / PLT / RELR
// relocation pointers, NEEDED dependencies and PT_TLS. NEVER execute
// FEX guest RIP, initialize FS/GS, relocate, seal RELRO or launch Wine.
#include "kernix_g2e_c3d7i_original_x86_dynamic_tls_relocation_contract.h"
#include <array>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <string>
#if !defined(__ANDROID__) || !defined(__aarch64__)
#error C3-D7I original x86 Linux dynamic ABI requires Android ARM64
#endif
extern "C" __attribute__((visibility("default")))
int kernix_g2ec3d7i_original_linux_relocation_tls_inspection_BUILDONLY(
    int verifiedAppPrivateOriginalELFRootFd,
    const uint8_t* exactly16BytesOfEntropy,
    uint32_t* outOriginalELFRelocationEntries,
    uint32_t* outOriginalRELRDecodedTargets,
    uint32_t* outPTTLSModules,
    uint32_t* outActualFSGSInitialized) noexcept {
  if(outOriginalELFRelocationEntries)*outOriginalELFRelocationEntries=0;
  if(outOriginalRELRDecodedTargets)*outOriginalRELRDecodedTargets=0;
  if(outPTTLSModules)*outPTTLSModules=0;
  if(outActualFSGSInitialized)*outActualFSGSInitialized=0;
  if(verifiedAppPrivateOriginalELFRootFd<0 ||
     !exactly16BytesOfEntropy ||
     !outOriginalELFRelocationEntries ||
     !outOriginalRELRDecodedTargets ||
     !outPTTLSModules ||
     !outActualFSGSInitialized)return -EINVAL;
  std::array<uint8_t,16> seed{};
  std::memcpy(seed.data(),exactly16BytesOfEntropy,seed.size());
  kernix::g2e::GuestPreflight original;
  std::string why;
  if(!kernix::g2e::Validate(
       verifiedAppPrivateOriginalELFRootFd,original,why))
    return -ENOEXEC;
  kernix::g2e::c3d7b::NativeChosenPIEGuestLayout guest;
  kernix::g2e::c3d7b::Witness staged;
  if(!guest.Stage(verifiedAppPrivateOriginalELFRootFd,seed,staged) ||
     !staged.pinnedOriginalELFSHA256Verified ||
     staged.originalELFCodeExecuted ||
     staged.originalLdsoExecuted)return -ENOEXEC;
  kernix::g2e::c3d7g::PermissionPlan page;
  kernix::g2e::c3d7g::Reject pageRejected;
  const bool pages=kernix::g2e::c3d7g::BuildVerifiedOriginalPermissionPlan(
     original,guest,page,pageRejected);
  kernix::g2e::c3d7h::Plan relro;
  kernix::g2e::c3d7h::Reject relroRejected;
  const bool relroReady=pages &&
    kernix::g2e::c3d7h::BuildVerifiedOriginalThreeELFRelroPlan(
      original,guest,page,relro,relroRejected);
  kernix::g2e::c3d7i::Plan meta;
  kernix::g2e::c3d7i::Reject dynamicRejected;
  const bool dynamicReady=relroReady &&
    kernix::g2e::c3d7i::InspectOriginalThreeModules(
       original,guest,page,relro,meta,dynamicRejected);
  const bool pass=dynamicReady &&
    meta.originalThreeSHA256SourcesVerified &&
    meta.allOriginalDynamicTablesBounded &&
    meta.allOriginalTLSRangesBounded &&
    meta.totalRelaEntries>0 &&
    meta.totalRelrTargets>0 &&
    meta.totalTLSHeaders>0 &&
    meta.totalNeededLibraries==meta.totalValidatedNeededStrings &&
    meta.relocationTargetsOutsideInitialRW==0 &&
    !meta.originalELFRelocationsApplied &&
    !meta.x86GuestFSGSInitialized &&
    !meta.relroSealed &&
    !meta.originalLinuxLdsoExecuted;
  const uint64_t count=meta.totalRelaEntries+meta.totalPltRelaEntries;
  const uint64_t targets=meta.totalRelrTargets;
  const uint64_t tls=meta.totalTLSHeaders;
  const bool released=guest.Release()&&guest.WindowsHeld()==0;
  if(!pass || !released ||
     count>UINT32_MAX || targets>UINT32_MAX || tls>UINT32_MAX)
    return -ENOEXEC;
  *outOriginalELFRelocationEntries=static_cast<uint32_t>(count);
  *outOriginalRELRDecodedTargets=static_cast<uint32_t>(targets);
  *outPTTLSModules=static_cast<uint32_t>(tls);
  return 0;
}
