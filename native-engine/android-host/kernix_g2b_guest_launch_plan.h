#pragma once
// KERNIX G2-B: integrate independently verified dynamic ELF file metadata,
// PT_LOAD read-only views, Linux x86-64 process-entry stack and guest VAs.
// Host-only, non-executing *plan*. NEVER maps guest memory into FEXCore.
// SPDX-License-Identifier: MIT
#include "kernix_guest_elf64_dependency_closure.h"
#include "kernix_guest_elf64_readonly_image.h"
#include "kernix_guest_linux_x86_initial_stack.h"
#include <elf.h>
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kernix::g2b {
struct X86GuestProcessAddresses {
    uint64_t mainImageStart = 0;         // Guest VA at first aligned PT_LOAD
    uint64_t interpreterImageStart = 0;  // Guest VA at first aligned PT_LOAD
    uint64_t stackBottom = 0;
    uint64_t stackBytes = 0;
    uint64_t guestPageBytes = 0;         // Guest page != Android host page
    uint32_t uid = 0, euid = 0, gid = 0, egid = 0;
    std::array<uint8_t,16> randomBytes{};
    std::vector<std::string> argv;
    std::vector<std::string> environment;
};
struct X86GuestProcessRegion {
    uint64_t first = 0;
    uint64_t pastLast = 0;
    uint32_t originalElfFlags = 0;
    bool isGuestStack = false;
};
struct X86GuestProcessLaunchPlan {
    std::string guestExecutable;
    std::string guestInterpreter;
    uint64_t mainLoadBias = 0;
    uint64_t interpreterLoadBias = 0;
    uint64_t guestMainEntry = 0;
    uint64_t guestMainPHDR = 0;
    uint64_t guestInterpreterEntry = 0;
    uint16_t mainPHNUM = 0;
    std::vector<X86GuestProcessRegion> regions;
    LinuxX86StackImage stack;
    size_t dependencyObjectsChecked = 0;
    bool guestVirtualAddressesValidated = false;
    bool stackAndAuxvConsistent = false;
    bool guestAddressSpaceReserved = false;
    bool guestMemoryMapped = false;
    bool fexEntryPointAssigned = false;
    bool dynamicLinkerExecuted = false;
    bool guestCodeExecuted = false;
    bool androidWineTested = false;
};

inline bool X86GuestRange(uint64_t a, uint64_t size) {
    return size && a >= 0x10000 && a < kLinuxGuestUserLimit &&
           size < kLinuxGuestUserLimit - a;
}
inline bool X86GuestNonOverlap(const X86GuestProcessRegion& a,
                               const X86GuestProcessRegion& b) {
    return a.pastLast <= b.first || b.pastLast <= a.first;
}
inline bool ReadGuestElfRuntimePhdr(int rootfd, std::string_view guestPath,
                                    bool mainExecutable, uint64_t& entry,
                                    uint64_t& phdrVaddr, uint16_t& phnum,
                                    std::string& error) {
    entry=0; phdrVaddr=0; phnum=0;
    int fd=OpenGuestFileWithScopedSymlinks(rootfd,guestPath);
    if (fd < 0) {error="GUEST_ELF_OBJECT_NOT_IN_ROOT"; return false;}
    std::vector<unsigned char> file;
    const bool bytesOk=ReadFilePrefix(fd,file,kMaxAuditedGuestBytes);
    close(fd);
    if (!bytesOk || file.size()<sizeof(Elf64_Ehdr)) {
        error="GUEST_ELF_HEADER_UNAVAILABLE"; return false;
    }
    Elf64_Ehdr eh{};
    std::memcpy(&eh,file.data(),sizeof(eh));
    if (!GuestElfHeader(eh) || eh.e_type!=ET_DYN ||
        eh.e_phnum==0 || eh.e_phnum>128 ||
        eh.e_phentsize!=sizeof(Elf64_Phdr) ||
        !ElfRange(eh.e_phoff,
                  static_cast<uint64_t>(eh.e_phnum)*sizeof(Elf64_Phdr),
                  file.size())) {
        error="GUEST_ELF_NOT_SUPPORTED_PIE"; return false;
    }
    const uint64_t headerBytes=
        static_cast<uint64_t>(eh.e_phnum)*sizeof(Elf64_Phdr);
    uint64_t derived=0;
    bool covered=false;
    bool hasPhdr=false;
    uint64_t declared=0;
    for (uint16_t i=0; i<eh.e_phnum; ++i) {
        Elf64_Phdr ph{};
        std::memcpy(&ph,file.data()+eh.e_phoff+i*sizeof(ph),sizeof(ph));
        if (ph.p_type==PT_PHDR) {
            if (hasPhdr || ph.p_offset!=eh.e_phoff ||
                ph.p_filesz<headerBytes) {
                error="GUEST_PHDR_HEADER_INCONSISTENT"; return false;
            }
            hasPhdr=true;
            declared=ph.p_vaddr;
        }
        if (ph.p_type!=PT_LOAD) continue;
        if (eh.e_phoff<ph.p_offset) continue;
        const uint64_t delta=eh.e_phoff-ph.p_offset;
        if (!ElfRange(delta,headerBytes,ph.p_filesz) ||
            ph.p_vaddr>UINT64_MAX-delta) continue;
        const uint64_t candidate=ph.p_vaddr+delta;
        if (covered && derived!=candidate) {
            error="GUEST_PHDR_AMBIGUOUS_LOAD"; return false;
        }
        derived=candidate;
        covered=true;
    }
    if (!covered || (hasPhdr && declared!=derived)) {
        error="GUEST_PHDR_NOT_FILE_BACKED"; return false;
    }
    if (mainExecutable && eh.e_entry==0) {
        error="GUEST_MAIN_ENTRY_EMPTY"; return false;
    }
    entry=eh.e_entry;
    phdrVaddr=derived;
    phnum=eh.e_phnum;
    error="none";
    return true;
}
inline bool PlanGuestELFRegions(const GuestReadonlyImage& image,
                               uint64_t guestStart, uint64_t pageBytes,
                               std::vector<X86GuestProcessRegion>& regions,
                               uint64_t& bias) {
    if (!image.hostView || !image.hostViewReadOnly ||
        image.hostViewExecutable || image.guestCodeExecuted ||
        image.relocationsApplied || image.androidWineTested ||
        !image.hostViewBytes || !X86GuestRange(guestStart,image.hostViewBytes) ||
        guestStart%pageBytes || image.guestPageAlignedBase>guestStart)
        return false;
    bias=guestStart-image.guestPageAlignedBase;
    for (const auto& part : image.segments) {
        if (part.guestVaddr>UINT64_MAX-bias ||
            !X86GuestRange(part.guestVaddr+bias,part.memoryBytes))
            return false;
        const X86GuestProcessRegion next{
            part.guestVaddr+bias,part.guestVaddr+bias+part.memoryBytes,
            part.guestFlags,false
        };
        for (const auto& current:regions)
            if (!X86GuestNonOverlap(next,current)) return false;
        regions.push_back(next);
    }
    return true;
}

// The Linux guest image paths and their direct+transitive ELF dependencies
// must already live under an app-owned, immutable/trusted rootfs. This API
// reads ELF, stages RO bytes in anonymous host memory, validates guest VAs
// and prepares stack bytes, then *discards* both host PT_LOAD views.
// It never reserves VAs, creates host executable pages, enters FEX, runs
// ld-linux, relocates glibc or calls Wine. Explicit guestStart addresses
// are deterministic CI/test inputs, NOT an ASLR allocator for production.
inline bool PrepareX86DynamicGuestLaunchPlan(
    int trustedRootFd, std::string_view guestExecutable,
    const X86GuestProcessAddresses& addresses,
    X86GuestProcessLaunchPlan& result, std::string& failure) {
    result={};
    auto fail=[&](const char* reason) -> bool {
        result={};
        failure=reason;
        return false;
    };
    if (trustedRootFd<0 || guestExecutable.empty() ||
        guestExecutable.front()!='/' ||
        (addresses.guestPageBytes!=4096 &&
         addresses.guestPageBytes!=16384))
        return fail("GUEST_LAUNCH_BAD_INITIAL_INPUT");
    GuestDependencyClosure closure;
    std::string reason;
    if (!AuditGuestELFDependencyClosure(
            trustedRootFd,guestExecutable,closure,reason) ||
        !closure.allDirectAndTransitiveFilesPresent ||
        closure.guestInterpreter.empty() ||
        closure.nodes.size()<2 || closure.guestCodeExecuted)
        return fail("GUEST_LAUNCH_TRANSITIVE_CLOSURE_FAILED");

    GuestReadonlyImage mainImage,loaderImage;
    if (!StageReadOnlyGuestELFImage(
            trustedRootFd,guestExecutable,mainImage,reason,true) ||
        !StageReadOnlyGuestELFImage(
            trustedRootFd,closure.guestInterpreter,loaderImage,reason,false))
        return fail("GUEST_LAUNCH_ELF_IMAGE_STAGING_FAILED");
    uint64_t mainEntry=0,mainPhdr=0,loaderEntry=0,unusedPhdr=0;
    uint16_t mainPhnum=0,loaderPhnum=0;
    if (!ReadGuestElfRuntimePhdr(trustedRootFd,guestExecutable,true,
                                 mainEntry,mainPhdr,mainPhnum,reason) ||
        !ReadGuestElfRuntimePhdr(trustedRootFd,closure.guestInterpreter,false,
                                 loaderEntry,unusedPhdr,loaderPhnum,reason))
        return fail("GUEST_LAUNCH_PHDR_METADATA_REJECTED");
    std::vector<X86GuestProcessRegion> regions;
    uint64_t mainBias=0,loaderBias=0;
    if (!PlanGuestELFRegions(mainImage,addresses.mainImageStart,
                             addresses.guestPageBytes,regions,mainBias) ||
        !PlanGuestELFRegions(loaderImage,addresses.interpreterImageStart,
                             addresses.guestPageBytes,regions,loaderBias))
        return fail("GUEST_LAUNCH_IMAGES_OVERLAP_OR_BAD_ADDRESS");
    if (!X86GuestRange(addresses.stackBottom,addresses.stackBytes) ||
        addresses.stackBottom%addresses.guestPageBytes ||
        addresses.stackBytes%addresses.guestPageBytes)
        return fail("GUEST_LAUNCH_BAD_STACK_REGION");
    X86GuestProcessRegion stackRegion{
        addresses.stackBottom,addresses.stackBottom+addresses.stackBytes,
        0,true
    };
    for(const auto& reg:regions)
        if(!X86GuestNonOverlap(reg,stackRegion))
            return fail("GUEST_LAUNCH_STACK_OVERLAPS_IMAGE");
    regions.push_back(stackRegion);

    // Verify all computed runtime addresses are in the corresponding
    // exact file-backed guest PT_LOAD intervals, never just canonical.
    const auto relocated=[&](uint64_t bias,uint64_t vaddr,uint64_t& out) {
        if (vaddr>UINT64_MAX-bias) return false;
        out=bias+vaddr;
        return ValidLinuxGuestPointer(out);
    };
    uint64_t mainRuntimeEntry=0,mainRuntimePhdr=0,loaderRuntimeEntry=0;
    if (!relocated(mainBias,mainEntry,mainRuntimeEntry) ||
        !relocated(mainBias,mainPhdr,mainRuntimePhdr) ||
        !relocated(loaderBias,loaderEntry,loaderRuntimeEntry))
        return fail("GUEST_LAUNCH_RUNTIME_POINTER_OVERFLOW");
    const auto inside=[&](uint64_t value,const GuestReadonlyImage& image,
                          uint64_t bias,bool executable,size_t length) {
        if (value>UINT64_MAX-length) return false;
        for(const auto& segment:image.segments) {
            if (segment.guestVaddr>UINT64_MAX-bias) return false;
            const uint64_t start=segment.guestVaddr+bias;
            if (start>value || segment.fileBytes<length ||
                value-start>segment.fileBytes-length) continue;
            if (executable && !(segment.guestFlags&PF_X)) continue;
            if (!executable && !(segment.guestFlags&PF_R)) continue;
            return true;
        }
        return false;
    };
    if (!inside(mainRuntimeEntry,mainImage,mainBias,true,1) ||
        !inside(loaderRuntimeEntry,loaderImage,loaderBias,true,1) ||
        !inside(mainRuntimePhdr,mainImage,mainBias,false,
                static_cast<size_t>(mainPhnum)*sizeof(Elf64_Phdr)))
        return fail("GUEST_LAUNCH_ENTRY_OR_PHDR_NOT_FILE_BACKED");
    LinuxX86StackInput st{};
    st.guestStackBottom=addresses.stackBottom;
    st.guestStackBytes=addresses.stackBytes;
    st.guestPageBytes=addresses.guestPageBytes;
    st.guestMainProgramHeaders=mainRuntimePhdr;
    st.guestMainEntry=mainRuntimeEntry;
    st.guestInterpreterBase=loaderBias;
    st.programHeaderCount=mainPhnum;
    st.uid=addresses.uid;st.euid=addresses.euid;
    st.gid=addresses.gid;st.egid=addresses.egid;
    st.randomBytes=addresses.randomBytes;
    st.args=addresses.argv;
    st.environment=addresses.environment;
    LinuxX86StackImage stack;
    if (!PrepareLinuxX86InitialStack(st,stack,reason) ||
        !stack.initialStackLayoutValidated ||
        stack.guestMemoryMapped || stack.guestCodeExecuted ||
        stack.androidWineTested)
        return fail("GUEST_LAUNCH_X86_STACK_AUXV_INVALID");
    result.guestExecutable=std::string(guestExecutable);
    result.guestInterpreter=closure.guestInterpreter;
    result.mainLoadBias=mainBias;
    result.interpreterLoadBias=loaderBias;
    result.guestMainEntry=mainRuntimeEntry;
    result.guestMainPHDR=mainRuntimePhdr;
    result.guestInterpreterEntry=loaderRuntimeEntry;
    result.mainPHNUM=mainPhnum;
    result.regions=std::move(regions);
    result.stack=std::move(stack);
    result.dependencyObjectsChecked=closure.nodes.size();
    result.guestVirtualAddressesValidated=true;
    result.stackAndAuxvConsistent=true;
    failure="none";
    return true;
}
} // namespace kernix::g2b
