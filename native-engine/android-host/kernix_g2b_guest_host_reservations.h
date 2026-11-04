#pragma once
// KERNIX G2-B: reserve host-controlled PROT_NONE address windows for an
// independently verified Linux x86-64 guest launch layout. No FEX execution.
// SPDX-License-Identifier: MIT
#include "kernix_g2b_guest_launch_plan.h"
#include <sys/mman.h>
#include <unistd.h>
#include <cerrno>
#include <cstdint>
#include <limits>
#include <string>
#include <string_view>
#include <vector>

namespace kernix::g2b {
constexpr uint64_t kMaxX86HostPlaceholderBytes=32ULL*1024*1024;
constexpr uint64_t kMaxX86HostTotalPlaceholderBytes=96ULL*1024*1024;

struct X86HostNoAccessReservation {
    void* hostMapping=nullptr;
    size_t hostMappingBytes=0;
    uint64_t guestStart=0;
    uint64_t guestBytes=0;
    uint64_t pageBytes=0;
    bool noAccess=true;
    bool executable=false;
    bool isFEXGuestAddressSpace=false;
    bool usedMAP_FIXED=false;

    X86HostNoAccessReservation()=default;
    X86HostNoAccessReservation(const X86HostNoAccessReservation&)=delete;
    X86HostNoAccessReservation& operator=(const X86HostNoAccessReservation&)=delete;
    void release() noexcept {
        if (hostMapping) munmap(hostMapping,hostMappingBytes);
        hostMapping=nullptr;
        hostMappingBytes=0;
        guestStart=0;
        guestBytes=0;
        pageBytes=0;
        noAccess=true;
        executable=false;
        isFEXGuestAddressSpace=false;
        usedMAP_FIXED=false;
    }
    ~X86HostNoAccessReservation(){release();}
};

inline bool ReserveX86NoAccessHostWindow(
    uint64_t requestedBytes, uint64_t guestPageBytes,
    X86HostNoAccessReservation& out, std::string& error) {
    out.release();
    if ((guestPageBytes!=4096 && guestPageBytes!=16384) ||
        requestedBytes<4096 ||
        requestedBytes>kMaxX86HostPlaceholderBytes ||
        requestedBytes%guestPageBytes!=0) {
        error="HOST_WINDOW_SIZE_OR_GUEST_PAGE_ALIGNMENT_REJECTED";
        return false;
    }
    const long hostPage=sysconf(_SC_PAGESIZE);
    if (hostPage!=4096 && hostPage!=16384 && hostPage!=65536) {
        error="HOST_WINDOW_HOST_PAGE_SIZE_REJECTED";
        return false;
    }
    const uint64_t align=static_cast<uint64_t>(hostPage)>guestPageBytes ?
        static_cast<uint64_t>(hostPage):guestPageBytes;
    // Reserve two real inaccessible guard pages, plus room to align the
    // guest window, without MAP_FIXED/MAP_FIXED_NOREPLACE or /proc maps scans.
    const uint64_t guard=static_cast<uint64_t>(hostPage);
    const uint64_t total=requestedBytes+2*guard+(align-1);
    if (total>kMaxX86HostPlaceholderBytes+2*65536+65535 ||
        total>static_cast<uint64_t>(std::numeric_limits<size_t>::max())) {
        error="HOST_WINDOW_TOTAL_RESERVATION_TOO_LARGE";
        return false;
    }
    // Native ARM64 Linux may choose a user VA above the x86-64 47-bit
    // canonical user range when given a nullptr hint. Give the KERNEL
    // ordinary non-fixed low canonical address preferences instead.
    // There is NO MAP_FIXED or MAP_FIXED_NOREPLACE here: occupied mappings
    // remain untouched, kernel can return a different address, and any
    // response outside x86 canonical user space is immediately unmapped.
    constexpr uintptr_t canonicalHints[] {
        0x0000600000000000ULL, 0x0000500000000000ULL,
        0x0000400000000000ULL, 0x0000300000000000ULL
    };
    for (const uintptr_t hint : canonicalHints) {
        void* mem=mmap(reinterpret_cast<void*>(hint),
                       static_cast<size_t>(total), PROT_NONE,
                       MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
        if (mem==MAP_FAILED) continue;
        const uint64_t base=static_cast<uint64_t>(
            reinterpret_cast<uintptr_t>(mem));
        if (base>UINT64_MAX-guard-align) {
            munmap(mem,static_cast<size_t>(total));
            continue;
        }
        const uint64_t aligned=(base+guard+align-1)&~(align-1);
        if (aligned<base+guard || aligned>UINT64_MAX-requestedBytes ||
            aligned+requestedBytes>UINT64_MAX-guard ||
            aligned+requestedBytes+guard>base+total ||
            !X86GuestRange(aligned,requestedBytes)) {
            munmap(mem,static_cast<size_t>(total));
            continue;
        }
        out.hostMapping=mem;
        out.hostMappingBytes=static_cast<size_t>(total);
        out.guestStart=aligned;
        out.guestBytes=requestedBytes;
        out.pageBytes=guestPageBytes;
        error="none";
        return true;
    }
    error="HOST_WINDOW_NO_CANONICAL_ADDRESS_WITH_SAFE_NONFIXED_HINTS";
    return false;
}
struct X86HostReservedGuestLaunch {
    X86HostNoAccessReservation main;
    X86HostNoAccessReservation interpreter;
    X86HostNoAccessReservation stack;
    X86GuestProcessLaunchPlan plan;
    bool hostVAsReservedPROT_NONE=false;
    bool hostImageBytesStagedReadonly=false;
    bool hostStackBytesStagedReadonly=false;
    bool guestVAsInstalledInFEX=false;
    bool executableGuestPagesMapped=false;
    bool guestCodeExecuted=false;
    bool androidWineTested=false;
    X86HostReservedGuestLaunch()=default;
    X86HostReservedGuestLaunch(const X86HostReservedGuestLaunch&)=delete;
    X86HostReservedGuestLaunch& operator=(const X86HostReservedGuestLaunch&)=delete;
    void release() noexcept {
        plan={};
        stack.release();
        interpreter.release();
        main.release();
        hostVAsReservedPROT_NONE=false;
        hostImageBytesStagedReadonly=false;
        hostStackBytesStagedReadonly=false;
        guestVAsInstalledInFEX=false;
        executableGuestPagesMapped=false;
        guestCodeExecuted=false;
        androidWineTested=false;
    }
    ~X86HostReservedGuestLaunch(){release();}
};

// Acquire real kernel-selected PROT_NONE windows in this same process, then
// validate that the real ELF main+interpreter+stack all fit those windows.
// Still intentionally disallows FEX execution: the image bytes and stack
// are NOT installed into these windows; no guest JIT or loader is running.
inline bool ReserveAndValidateX86HostGuestWindows(
    int trustedRootFD, std::string_view guestExecutable,
    uint64_t guestPageBytes, uint64_t guestStackBytes,
    const std::array<uint8_t,16>& externallySuppliedRandom,
    const std::vector<std::string>& argv,
    const std::vector<std::string>& envp,
    X86HostReservedGuestLaunch& output, std::string& error) {
    output.release();
    const auto fail=[&](const char* why)->bool {
        output.release();
        error=why;
        return false;
    };
    if (trustedRootFD<0 ||
        (guestPageBytes!=4096 && guestPageBytes!=16384) ||
        guestStackBytes<4096 || guestStackBytes>kMaxLinuxStackBytes ||
        guestStackBytes%guestPageBytes ||
        argv.empty() || guestExecutable.empty())
        return fail("HOST_WINDOWS_INVALID_INITIAL_PARAMETERS");
    GuestDependencyClosure deps;
    std::string reason;
    if (!AuditGuestELFDependencyClosure(
            trustedRootFD,guestExecutable,deps,reason) ||
        deps.guestInterpreter.empty() ||
        !deps.allDirectAndTransitiveFilesPresent)
        return fail("HOST_WINDOWS_GUEST_DEPENDENCY_CLOSURE_FAILED");
    GuestReadonlyImage main,loader;
    if (!StageReadOnlyGuestELFImage(
            trustedRootFD,guestExecutable,main,reason,true) ||
        !StageReadOnlyGuestELFImage(
            trustedRootFD,deps.guestInterpreter,loader,reason,false))
        return fail((std::string("HOST_WINDOWS_STAGED_ELF_INVALID:") + reason).c_str());
    if (!main.hostViewBytes || !loader.hostViewBytes ||
        main.hostViewBytes>kMaxX86HostPlaceholderBytes ||
        loader.hostViewBytes>kMaxX86HostPlaceholderBytes)
        return fail("HOST_WINDOWS_IMAGE_SPAN_REJECTED");
    if (!ReserveX86NoAccessHostWindow(main.hostViewBytes,guestPageBytes,
                                      output.main,reason) ||
        !ReserveX86NoAccessHostWindow(loader.hostViewBytes,guestPageBytes,
                                      output.interpreter,reason) ||
        !ReserveX86NoAccessHostWindow(guestStackBytes,guestPageBytes,
                                      output.stack,reason))
        return fail((std::string("HOST_WINDOWS_NOACCESS_RESERVATION_FAILED:")+reason).c_str());
    const uint64_t bytes=output.main.guestBytes+
                         output.interpreter.guestBytes+output.stack.guestBytes;
    if (bytes>kMaxX86HostTotalPlaceholderBytes)
        return fail("HOST_WINDOWS_TOTAL_SIZE_REJECTED");
    X86GuestProcessAddresses a{};
    a.mainImageStart=output.main.guestStart;
    a.interpreterImageStart=output.interpreter.guestStart;
    a.stackBottom=output.stack.guestStart;
    a.stackBytes=guestStackBytes;
    a.guestPageBytes=guestPageBytes;
    a.uid=static_cast<uint32_t>(getuid());
    a.euid=static_cast<uint32_t>(geteuid());
    a.gid=static_cast<uint32_t>(getgid());
    a.egid=static_cast<uint32_t>(getegid());
    a.randomBytes=externallySuppliedRandom;
    a.argv=argv;
    a.environment=envp;
    if (!PrepareX86DynamicGuestLaunchPlan(
            trustedRootFD,guestExecutable,a,output.plan,reason) ||
        !output.plan.stackAndAuxvConsistent ||
        !output.plan.guestVirtualAddressesValidated ||
        output.plan.guestAddressSpaceReserved ||
        output.plan.guestMemoryMapped ||
        output.plan.fexEntryPointAssigned ||
        output.plan.guestCodeExecuted ||
        output.plan.androidWineTested)
        return fail("HOST_WINDOWS_VERIFIED_LAYOUT_FAILED");
    const auto contains=[&](uint64_t first,uint64_t end,
                            const X86HostNoAccessReservation& win){
        return first>=win.guestStart &&
               end>first &&
               win.guestStart<=UINT64_MAX-win.guestBytes &&
               end<=win.guestStart+win.guestBytes;
    };
    for(const auto& reg:output.plan.regions) {
        if (reg.isGuestStack) {
            if (!contains(reg.first,reg.pastLast,output.stack))
                return fail("HOST_WINDOWS_STACK_OUTSIDE_PROTECTED_RESERVATION");
        } else if (!contains(reg.first,reg.pastLast,output.main) &&
                   !contains(reg.first,reg.pastLast,output.interpreter)) {
            return fail("HOST_WINDOWS_ELF_OUTSIDE_PROTECTED_RESERVATION");
        }
    }
    output.hostVAsReservedPROT_NONE=true;
    error="none";
    return true;
}
} // namespace kernix::g2b
