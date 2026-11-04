#pragma once
// SPDX-License-Identifier: MIT
// KERNIX G2-E/C3-D3: independently bounded native kernel page-size and
// collision-safe MAP_FIXED_NOREPLACE CAPABILITY on the actual host.
//
// The OS chooses the only test address via mmap(NULL,..., PROT_NONE).
// Attempting to allocate that ALREADY-OWNED one-page address with the
// explicit NOREPLACE flag MUST return EEXIST; otherwise fail closed.
// Never MAP_FIXED, never PROT_EXEC/WRITE/READ, never mprotect, never
// use another address or any Linux-x86 guest VA, no FEX/JIT/thread.
// All acquired mappings are released on every path; at most two native
// pages are temporarily claimed, depending on an unsupported-flag kernel.
#include <cerrno>
#include <cstdint>
#include <sys/mman.h>
#include <unistd.h>

namespace kernix::g2e::c3d3 {
struct NativePageWitness {
    uint64_t nativeKernelPageBytes=0;
    bool kernelPageVerified=false;
    bool native16KObserved=false;
    bool noreplaceFlagCompiled=false;
    bool singleOwnedHostPageMmapSucceeded=false;
    bool existingOwnedMappingProtectedFromReplacement=false;
    bool unsupportedFlagReturnedDifferentAddress=false;
    bool exactOriginalMappingStillOwned=false;
    bool originalOwnedMappingReleased=false;
    bool hostUsedProtNoneOnly=true;
    bool guestX86CodeExecuted=false;
    bool originalGuestVAsReserved=false;
    bool originalGuestPtLoadInstalled=false;
    bool fexCoreAttached=false;
    bool realHostSubpageProtectionImplemented=false;
};
inline bool RunOneHostNativePageCollisionProbe(
    NativePageWitness& witness) noexcept {
    witness={};
    const long rawBytes=::sysconf(_SC_PAGESIZE);
    if(rawBytes!=4096 && rawBytes!=16384)
        return false;
    const auto nativeBytes=static_cast<size_t>(rawBytes);
    witness.nativeKernelPageBytes=static_cast<uint64_t>(nativeBytes);
    witness.kernelPageVerified=true;
    witness.native16KObserved=(nativeBytes==16384);
#if !defined(MAP_FIXED_NOREPLACE)
    return false; // Never define an unsafe substitute.
#else
    witness.noreplaceFlagCompiled=true;
    // One single, fresh address *chosen by kernel*: no MAP_FIXED and no
    // high-address guest mapping. This test runs in an isolated child.
    void* owned=::mmap(nullptr,nativeBytes,PROT_NONE,
        MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    if(owned==MAP_FAILED)
        return false;
    witness.singleOwnedHostPageMmapSucceeded=true;
    // Sanity check our page is still mapped. mincore never dereferences it.
    unsigned char residency=0;
    const bool originalPresent=::mincore(owned,nativeBytes,&residency)==0;
    if(!originalPresent){
        ::munmap(owned,nativeBytes);
        witness.originalOwnedMappingReleased=true;
        return false;
    }
    errno=0;
    void* replacement=::mmap(owned,nativeBytes,PROT_NONE,
        MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0);
    const int replacementError=errno;
    if(replacement!=MAP_FAILED) {
        // Older kernels may ignore unknown NOREPLACE and map somewhere
        // else. Safely unmap only the new, separately returned VMA.
        if(replacement!=owned){
            witness.unsupportedFlagReturnedDifferentAddress=true;
            ::munmap(replacement,nativeBytes);
        }
        // If it returned exactly the old VMA, an old kernel could have
        // replaced our own page. Both pages are PROT_NONE, but this
        // STILL fails the capability test.
    } else if(replacementError==EEXIST){
        witness.existingOwnedMappingProtectedFromReplacement=true;
    }
    const bool stillPresent=
        ::mincore(owned,nativeBytes,&residency)==0;
    witness.exactOriginalMappingStillOwned=
        witness.existingOwnedMappingProtectedFromReplacement &&
        stillPresent;
    const bool unmapped=(::munmap(owned,nativeBytes)==0);
    witness.originalOwnedMappingReleased=unmapped;
    return witness.exactOriginalMappingStillOwned && unmapped;
#endif
}
} // namespace kernix::g2e::c3d3
