#pragma once
// KERNIX G2-E/C1 -- Linux x86_64 SYSCALL register/ABI contract, DATA ONLY.
// This header knows the x86 guest ABI; it neither imports Bionic/Linux host
// syscall numbers nor dispatches to ::syscall(), mmap(), openat() or FEX.
// Register fields are copied from FEXCpuState by a SEPARATE, future adapter.
// No arbitrary guest pointers are dereferenced here. SPDX-License-Identifier: MIT.
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>

namespace kernix::g2e::c1 {

// amd64 Linux: RAX=number, RDI,RSI,RDX,R10,R8,R9=arguments. RCX records
// the return RIP (after 0F 05), R11 flags. The fourth arg is R10, NOT RCX.
// Explicit constants are GUEST Linux numbers, never Android ARM64 syscall IDs.
constexpr uint64_t kRead=0,kWrite=1,kClose=3,kFstat=5,kMmap=9,
                   kMprotect=10,kMunmap=11,kBrk=12,kRtSigaction=13,
                   kRtSigprocmask=14,kPread64=17,kAccess=21,kGetpid=39,
                   kExit=60,kArchPrctl=158,kSetTidAddress=218,
                   kExitGroup=231,kOpenat=257,kNewfstatat=262,
                   kSetRobustList=273,kPrlimit64=302,kGetrandom=318;
constexpr uint64_t kGuestUserLimit=0x0000800000000000ULL;
constexpr uint64_t kMaxGuestIoBytes=64*1024ULL;
constexpr uint64_t kMaxGuestMappedBytes=32*1024*1024ULL;
constexpr uint64_t kGuestPage=4096ULL;
constexpr uint64_t kHostPage16K=16384ULL;

enum class CallCategory : uint8_t {
    UnknownDenied, // rejected; not a valid guest process operation
    NeedsGuestKernel, // known Linux ABI; no implementation or host dispatch
    ExitIntentOnly,  // exit/exit_group recognized, never ends host process
    HostlessIdentity // getpid recognized, not routed to Android getpid()
};
struct X86LinuxSyscallTrap {
    uint64_t rax=0;
    uint64_t rdi=0,rsi=0,rdx=0,r10=0,r8=0,r9=0;
    uint64_t rip=0,rcxNext=0,r11Flags=0,rsp=0;
};
struct X86GuestStackBoundary {
    uint64_t start=0;
    uint64_t pastLast=0;
    bool attestedFromPinnedGuest=false;
};
struct TrapClassification {
    uint64_t guestNumber=0;
    std::array<uint64_t,6> args{};
    uint64_t nextGuestRIP=0;
    CallCategory category=CallCategory::UnknownDenied;
    bool trapBoundaryAuthenticated=false;
    bool sourceRegisterMappingChecked=false;
    bool hostSyscallDispatched=false;
    bool guestMemoryDereferenced=false;
    bool fexGuestExecuted=false;
};

inline constexpr bool CanonicalGuestPointer(uint64_t ptr) noexcept {
    return ptr>=0x10000ULL && ptr<kGuestUserLimit;
}
inline constexpr bool GuestRange(uint64_t ptr,uint64_t length) noexcept {
    return length>0 && CanonicalGuestPointer(ptr) &&
           length<=kGuestUserLimit-ptr;
}
inline constexpr bool IsX86LinuxError(int64_t result) noexcept {
    return result>=-4095 && result<=-1;
}
inline constexpr int64_t X86LinuxErrno(int hostIndependentError) noexcept {
    // Linux x86-64 error results are -errno, never a Bionic errno packet.
    return hostIndependentError>=1 && hostIndependentError<=4095 ?
        -static_cast<int64_t>(hostIndependentError) : -38; // x86 ENOSYS
}
inline constexpr CallCategory ClassifyCall(uint64_t guestNumber) noexcept {
    switch(guestNumber) {
        case kRead: case kWrite: case kClose: case kFstat:
        case kMmap: case kMprotect: case kMunmap: case kBrk:
        case kRtSigaction: case kRtSigprocmask: case kPread64:
        case kAccess: case kArchPrctl: case kSetTidAddress:
        case kSetRobustList:
        case kOpenat: case kNewfstatat: case kPrlimit64:
        case kGetrandom:
            return CallCategory::NeedsGuestKernel;
        case kExit: case kExitGroup: return CallCategory::ExitIntentOnly;
        case kGetpid: return CallCategory::HostlessIdentity;
        default: return CallCategory::UnknownDenied;
    }
}

// C1 is a decoder/policy gate only. In particular, recognizing a syscall
// doesn't make it safe to forward to the host, and success is never synthetic.
inline bool ClassifyVerifiedTrap(
    const X86LinuxSyscallTrap& input,
    const X86GuestStackBoundary& stack,
    TrapClassification& output) noexcept {
    output={};
    if(!stack.attestedFromPinnedGuest ||
       !GuestRange(stack.start,stack.pastLast-stack.start) ||
       stack.pastLast<=stack.start || (stack.start&15U) ||
       !CanonicalGuestPointer(input.rip) ||
       input.rip>kGuestUserLimit-3 ||
       input.rcxNext!=input.rip+2 ||
       input.rsp<stack.start || input.rsp>stack.pastLast-8 ||
       (input.rsp&7U))
        return false;
    output.guestNumber=input.rax;
    output.args={input.rdi,input.rsi,input.rdx,input.r10,input.r8,input.r9};
    output.nextGuestRIP=input.rcxNext;
    output.category=ClassifyCall(input.rax);
    output.trapBoundaryAuthenticated=true;
    output.sourceRegisterMappingChecked=true; // explicit R10 not RCX
    return true;
}

enum class GuestDataAccess : uint8_t { Read, Write, Execute };
struct GuestVmInterval {
    uint64_t start=0,pastLast=0;
    bool guestRead=false,guestWrite=false,guestExecute=false;
    bool attested=false;
};
// Only require one precisely attested interval, not adjacent regions that
// the host might coalesce. This does NOT grant access or dereference memory.
inline bool PinnedGuestSpan(
    uint64_t ptr,uint64_t length,GuestDataAccess operation,
    const GuestVmInterval& region) noexcept {
    if(!region.attested || !GuestRange(ptr,length) ||
       !GuestRange(region.start,region.pastLast-region.start) ||
       region.pastLast<=region.start ||
       ptr<region.start || length>region.pastLast-ptr)
        return false;
    switch(operation){
        case GuestDataAccess::Read:return region.guestRead;
        case GuestDataAccess::Write:return region.guestWrite;
        case GuestDataAccess::Execute:return region.guestExecute;
    }
    return false;
}

inline constexpr bool IsGuestMmapFdAnonymous(uint64_t fd) noexcept {
    // int fd=-1 may be sign-extended or zero-extended when passed via R8.
    return fd==UINT64_MAX || fd==UINT32_MAX;
}
inline bool BoundedAnonymousMmapIntent(const TrapClassification& trap) noexcept {
    if(!trap.trapBoundaryAuthenticated ||
       trap.guestNumber!=kMmap ||
       trap.category!=CallCategory::NeedsGuestKernel)return false;
    const auto& a=trap.args;
    // x86 flags MAP_PRIVATE=2, MAP_ANONYMOUS=32;
    // only anon/read-write, never exec, shared, fixed or file-backed.
    return a[0]==0 &&
           a[1]>=kGuestPage && a[1]<=kMaxGuestMappedBytes &&
           a[1]%kGuestPage==0 && a[2]==3 && a[3]==0x22 &&
           IsGuestMmapFdAnonymous(a[4]) && a[5]==0;
}

// A 4K x86 guest PT_LOAD can share a 16K Android host page with a region
// of different permissions. Until explicit shadow subpage permissions
// exist, ANY executable vs mutable byte sharing that host page is rejected.
inline bool HostPageExecuteWriteConflict(
    const GuestVmInterval& first,const GuestVmInterval& second,
    uint64_t hostPageBytes) noexcept {
    if(!first.attested || !second.attested ||
       (hostPageBytes!=kGuestPage && hostPageBytes!=kHostPage16K) ||
       first.start>=first.pastLast || second.start>=second.pastLast ||
       first.pastLast>kGuestUserLimit ||
       second.pastLast>kGuestUserLimit)
        return true;
    if((!first.guestExecute && !second.guestExecute) ||
       (!first.guestWrite && !second.guestWrite))
        return false;
    if((first.guestExecute && first.guestWrite) ||
       (second.guestExecute && second.guestWrite))
        return true;
    const uint64_t mask=~(hostPageBytes-1);
    const uint64_t firstStart=first.start&mask;
    const uint64_t secondStart=second.start&mask;
    const uint64_t firstEnd=((first.pastLast-1)&mask)+hostPageBytes;
    const uint64_t secondEnd=((second.pastLast-1)&mask)+hostPageBytes;
    return firstStart<secondEnd && secondStart<firstEnd;
}

struct C1DispatchPlan {
    int64_t safeGuestReturn=-38; // -ENOSYS until a real guest kernel exists
    CallCategory category=CallCategory::UnknownDenied;
    bool requiresGuestKernel=false;
    bool hostSyscallInvoked=false;
    bool guestMemoryTouched=false;
    bool hostProcessExited=false;
};
// Fail-closed planning only. Cannot execute write/openat/mmap/getpid/exit.
inline C1DispatchPlan PlanHostlessGuestDispatch(
    const TrapClassification& trap) noexcept {
    C1DispatchPlan plan;
    if(!trap.trapBoundaryAuthenticated ||
       !trap.sourceRegisterMappingChecked ||
       trap.hostSyscallDispatched || trap.guestMemoryDereferenced ||
       trap.fexGuestExecuted)
        return plan;
    plan.category=trap.category;
    plan.requiresGuestKernel=trap.category!=CallCategory::UnknownDenied;
    return plan;
}
} // namespace kernix::g2e::c1
