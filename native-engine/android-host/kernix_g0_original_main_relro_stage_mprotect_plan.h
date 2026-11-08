// SPDX-License-Identifier: MIT
#pragma once
// G0 planning gate for source-authentic GNU ld-linux x86 syscall 10.
//
// This function is PURE and never changes host page rights or returns a
// guest syscall success result. It cannot be used as a replacement for a
// source-SHA-verified native VMA owner registry, an actual kernel mprotect,
// an attested successful host return, and post-seal write-denial tests.
//
// The GNU dynamic loader's own IRELATIVE self-resolver executes AFTER
// the source main PT_GNU_RELRO 4K mprotect in native x86 reference.
// Therefore the source-original main page must be evaluated at the MAIN
// relocation barrier, not after all 1237 source main/ldso/libc relocations.
#include <cstddef>
#include <cstdint>
#include <limits>

namespace kernix::g0::originalmainrelro {
constexpr std::uint64_t kSourceGuestMainRelroPage = 0x800003000ULL;
constexpr std::uint64_t kSourceGuestMainRelroBytes = 0x1000ULL;
constexpr std::uint64_t kSourceGuestMprotectRIP = 0x801025db9ULL;
constexpr std::uint64_t kLinuxX86SyscallMprotect = 10;
constexpr std::uint64_t kLinuxProtRead = 1;
constexpr std::uint64_t kGuest4K = 4096;
constexpr std::uint64_t kHost16K = 16384;

enum class Decision {
  PlanAllowedOnly_NoSyscallExecuted = 0,
  DenyMissingOriginalSourceOrGuestProvenance,
  DenyMainRelocationWriterOrStageIncomplete,
  DenyInvalidGuestSyscallOrPTGNURELRO,
  DenyUnownedOrUnsafeGuestNativeMapping,
  DenyNonEquivalentNativePageOrSubpageAliasing
};

struct SourceStage {
  bool mainSha256Verified = false;
  bool originalLdsoSha256Verified = false;
  bool originalLibcSha256Verified = false;
  bool originalFexShaVerified = false;
  bool originalGuestSyscallInstructionFromLdsoRX = false;
  bool sourceGuestTrapAndOriginalRegisterMapAuthenticated = false;
  bool sourceOriginalMainNineWriterEventsExactGuestRIPs = false;
  bool originalMainEightRelroTargetsSourceAuth = false;
  bool sourceRELATIVE0FixtureIgnoredAndActualLdsoRewriteProven = false;
  bool mainRelocationPhaseDoneBeforeMainGuestMprotect = false;
  bool originalLibcRelroPhaseAlreadyReached = false;
  // 46 genuine source libc IRELATIVE native write instructions were observed;
  // this does not attest 46 correct returns or all remaining libc relocations.
  bool sourceLibc46IRELATIVEJitStoresObserved = false;
  // These two facts are intentionally NOT prerequisites. The GNU ldso
  // self-IRELATIVE and final self-RELRO belong to a later loader phase.
  bool originalLdsoSelfIRELATIVEResolverCompleted = false;
  bool allOriginalTriad1237RelocationsClosed = false;
};

struct OwnedVMA {
  bool ownedExactOriginalMainELF = false;
  bool sourceBackedMainPTGNURELRO = false;
  bool ownerRegistrySourceSHAIdentityChecked = false;
  bool noForeignHostPointerOrOverlappingVMA = false;
  bool noOverlappingLiveExecutableOrWritableGuestAlias = false;
  bool currentlyExactGuestRelroPageReadWriteAndNotExecute = false;
  bool pendingOriginalMainPageWriter = true;
  std::uint64_t hostNativePageBytes = 0;
  std::uint64_t guestPageBytes = 0;
  std::uint64_t exactOwnedNativeSpanBytes = 0;
  std::uint64_t mappedGuestPageStart = 0;
  std::uint64_t mappedHostPageStart = 0;
};

struct GuestSyscall {
  std::uint64_t syscallNumber = 0;
  std::uint64_t sourceGuestRIP = 0;
  std::uint64_t sourceGuestNextRIP = 0;
  std::uint64_t address = 0;
  std::uint64_t length = 0;
  std::uint64_t protection = 0;
  bool x86TrapFromAuthenticFexGuest = false;
};

struct Result {
  Decision decision = Decision::DenyMissingOriginalSourceOrGuestProvenance;
  bool canAttemptHostMprotectForThisOneSourcePage = false;
  bool nativeKernelProtectionChanged = false;
  bool guestSyscallSucceeded = false;
  bool sourceMainRELROSealed = false;
  bool originalLdsoSelfIFUNCExecuted = false;
  bool AndroidWineOrGamesProven = false;
};

inline Result PlanOneOriginalMainPage(
    const SourceStage& source,
    const OwnedVMA& owner,
    const GuestSyscall& syscall) noexcept {
  Result r{};
  if (!(source.mainSha256Verified &&
        source.originalLdsoSha256Verified &&
        source.originalLibcSha256Verified &&
        source.originalFexShaVerified &&
        source.originalGuestSyscallInstructionFromLdsoRX &&
        source.sourceGuestTrapAndOriginalRegisterMapAuthenticated))
    return r;
  if (!(source.sourceOriginalMainNineWriterEventsExactGuestRIPs &&
        source.originalMainEightRelroTargetsSourceAuth &&
        source.sourceRELATIVE0FixtureIgnoredAndActualLdsoRewriteProven &&
        source.mainRelocationPhaseDoneBeforeMainGuestMprotect &&
        source.originalLibcRelroPhaseAlreadyReached &&
        source.sourceLibc46IRELATIVEJitStoresObserved)) {
    r.decision = Decision::DenyMainRelocationWriterOrStageIncomplete;
    return r;
  }
  if (!(syscall.x86TrapFromAuthenticFexGuest &&
        syscall.syscallNumber == kLinuxX86SyscallMprotect &&
        syscall.sourceGuestRIP == kSourceGuestMprotectRIP &&
        syscall.sourceGuestNextRIP == kSourceGuestMprotectRIP + 2 &&
        syscall.address == kSourceGuestMainRelroPage &&
        syscall.length == kSourceGuestMainRelroBytes &&
        syscall.protection == kLinuxProtRead)) {
    r.decision = Decision::DenyInvalidGuestSyscallOrPTGNURELRO;
    return r;
  }
  if (!(owner.ownedExactOriginalMainELF &&
        owner.sourceBackedMainPTGNURELRO &&
        owner.ownerRegistrySourceSHAIdentityChecked &&
        owner.noForeignHostPointerOrOverlappingVMA &&
        owner.noOverlappingLiveExecutableOrWritableGuestAlias &&
        owner.currentlyExactGuestRelroPageReadWriteAndNotExecute &&
        !owner.pendingOriginalMainPageWriter &&
        owner.mappedGuestPageStart == kSourceGuestMainRelroPage &&
        owner.mappedHostPageStart != 0 &&
        owner.mappedHostPageStart % kGuest4K == 0)) {
    r.decision = Decision::DenyUnownedOrUnsafeGuestNativeMapping;
    return r;
  }
  // A 4KiB x86 guest RELRO subpage inside an ordinary 16KiB host VMA
  // CANNOT safely be mprotect()'d by rounding down/up: adjacent guest
  // pages may still need RW or RX and aliased bytes could change rights.
  // A future 16K design must isolate a whole native page per 4K guest
  // page or implement a separately proven subpage permission mechanism.
  // This bounded diagnostic authorizes no such mapping today.
  if (!(owner.hostNativePageBytes == kGuest4K &&
        owner.guestPageBytes == kGuest4K &&
        owner.exactOwnedNativeSpanBytes == kGuest4K &&
        owner.mappedHostPageStart % owner.hostNativePageBytes == 0)) {
    r.decision = Decision::DenyNonEquivalentNativePageOrSubpageAliasing;
    return r;
  }
  r.decision = Decision::PlanAllowedOnly_NoSyscallExecuted;
  r.canAttemptHostMprotectForThisOneSourcePage = true;
  // Deliberately unchanged: actual syscall + return/readback/write-denial
  // are independently mandatory before returning guest RAX=0.
  return r;
}
} // namespace kernix::g0::originalmainrelro
