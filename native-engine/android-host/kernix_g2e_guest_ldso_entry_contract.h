#pragma once
// KERNIX G2-E/C0: exact pinned x86-64 Linux PT_INTERP entry and AUXV proof.
// Statically builds a future FEX initial RIP/RSP *contract* from three
// SHA-256-attested read-only guest ELF snapshots.  NO GUEST EXECUTION.
// The fixed addresses below are synthetic virtual-plan TEST addresses;
// they are NOT reserved, mapped, installed in FEX, or production ASLR.
// SPDX-License-Identifier: MIT
#include "kernix_g2e_pinned_glibc_preflight.h"
#include "kernix_g2b_guest_launch_plan.h"
#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <sys/types.h>
#include <unistd.h>
#include <vector>

namespace kernix::g2e {
inline constexpr uint64_t kC0MainTestVA=0x0000555500000000ULL;
inline constexpr uint64_t kC0LdsoTestVA=0x0000711100000000ULL;
inline constexpr uint64_t kC0StackTestVA=0x00007fff10000000ULL;
inline constexpr uint64_t kC0StackBytes=65536ULL;

struct GuestLdsoEntryWitness {
    uint64_t futureFexRIP=0;      // must be PT_INTERP ld-linux entry, never main
    uint64_t futureFexRSP=0;      // x86_64 startup stack, currently NOT mapped
    uint64_t expectedATBase=0;
    uint64_t expectedATEntry=0;
    uint64_t expectedATPHDR=0;
    uint64_t expectedATRandom=0;
    uint16_t expectedATPHNUM=0;
    bool exactOriginalSha256Assets=false;
    bool guestPtInterpEntryContractVerified=false;
    bool linuxX86AuxvContractVerified=false;
    bool guestAddressSpaceReserved=false;
    bool fexThreadInitialized=false;
    bool guestLdsoEntered=false;
    bool glibcExecuted=false;
    bool wineExecuted=false;
};

inline bool ReadStackLE64(const g2b::LinuxX86StackImage& stack,
                          uint64_t address, uint64_t& result) {
    result=0;
    if(address<stack.guestBottom || address>stack.guestTop ||
       address%8 || stack.guestTop-address<8 ||
       stack.bytes.size()!=stack.guestTop-stack.guestBottom)return false;
    const size_t offset=static_cast<size_t>(address-stack.guestBottom);
    for(unsigned i=0;i<8;i++)
        result|=static_cast<uint64_t>(stack.bytes[offset+i])<<(8*i);
    return true;
}

inline bool StringInStack(const g2b::LinuxX86StackImage& stack,
                          uint64_t ptr,std::string_view text) {
    if(ptr<stack.guestBottom || ptr>stack.guestTop ||
       text.size()+1>stack.guestTop-ptr ||
       stack.bytes.size()!=stack.guestTop-stack.guestBottom)return false;
    const auto* src=stack.bytes.data()+
        static_cast<size_t>(ptr-stack.guestBottom);
    return std::memcmp(src,text.data(),text.size())==0 && src[text.size()]=='\0';
}

// Independently validates a computed real-ELF launch plan, including
// exact word-by-word Linux AUXV values and authenticated interpreter entry.
// Caller must not translate these plan VAs into host mappings or FEX RIP.
inline bool VerifyLdsoEntryPlanOnly(
    const g2b::X86GuestProcessLaunchPlan& plan,
    const std::array<uint8_t,16>& suppliedRandom,
    GuestLdsoEntryWitness& output,std::string& reason) {
    output={};
    const auto fail=[&](const char* why) {
        output={};reason=why;return false;
    };
    if(plan.guestExecutable!=kGuest[0].path ||
       plan.guestInterpreter!=kGuest[1].path ||
       plan.dependencyObjectsChecked!=3 ||
       !plan.guestVirtualAddressesValidated ||
       !plan.stackAndAuxvConsistent ||
       plan.guestAddressSpaceReserved ||
       plan.guestMemoryMapped ||
       plan.fexEntryPointAssigned ||
       plan.dynamicLinkerExecuted ||
       plan.guestCodeExecuted ||
       plan.androidWineTested)
        return fail("G2EC0_PINNED_GUEST_CLOSURE_OR_NO_EXECUTION_BOUNDARY");
    if(plan.guestMainEntry==0 || plan.guestMainPHDR==0 ||
       plan.guestInterpreterEntry==0 || plan.guestInterpreterEntry==plan.guestMainEntry ||
       plan.interpreterLoadBias==0 || plan.mainLoadBias==0 ||
       plan.mainPHNUM==0 ||
       plan.guestMainEntry<kC0MainTestVA ||
       plan.guestInterpreterEntry<kC0LdsoTestVA ||
       plan.guestMainEntry>=kC0MainTestVA+16*1024*1024ULL ||
       plan.guestInterpreterEntry>=kC0LdsoTestVA+16*1024*1024ULL)
        return fail("G2EC0_INTERPRETER_RIP_NOT_AUTHENTIC_EXECUTABLE_PT_LOAD");
    bool insideLdsoRX=false;
    for(const auto& seg:plan.regions)
        if(!seg.isGuestStack && (seg.originalElfFlags&PF_X) &&
           plan.guestInterpreterEntry>=seg.first &&
           plan.guestInterpreterEntry<seg.pastLast &&
           seg.first>=kC0LdsoTestVA &&
           seg.pastLast<=kC0LdsoTestVA+16*1024*1024ULL)
            insideLdsoRX=true;
    if(!insideLdsoRX)
        return fail("G2EC0_INTERPRETER_ENTRY_NOT_IN_LDSO_RX");
    const auto& stack=plan.stack;
    if(!stack.initialStackLayoutValidated ||
       stack.guestCodeExecuted || stack.guestMemoryMapped ||
       stack.androidWineTested ||
       stack.guestBottom!=kC0StackTestVA ||
       stack.guestTop!=kC0StackTestVA+kC0StackBytes ||
       stack.guestRSP<stack.guestBottom ||
       stack.guestRSP%16 || stack.guestTop-stack.guestRSP<64)
        return fail("G2EC0_INITIAL_RSP_NOT_LINUX_X86_64_ABI");
    uint64_t cursor=stack.guestRSP;
    auto next=[&](uint64_t& value) {
        if(!ReadStackLE64(stack,cursor,value))return false;
        cursor+=8;return true;
    };
    uint64_t argc=0,argv0=0,argvNull=0,env0=0,envNull=0;
    if(!next(argc)||argc!=1 || !next(argv0)|| !next(argvNull) ||
       argvNull!=0 || !next(env0) || !next(envNull) || envNull!=0 ||
       !StringInStack(stack,argv0,kGuest[0].path) ||
       !StringInStack(stack,env0,"LANG=C") ||
       argv0!=stack.guestExecFnPointer)
        return fail("G2EC0_ARGV_ENVP_POINTERS_INCONSISTENT");
    const std::array<std::pair<uint64_t,uint64_t>,14> expected{{
        {3,plan.guestMainPHDR}, {4,sizeof(Elf64_Phdr)},
        {5,plan.mainPHNUM},{6,4096},
        {7,plan.interpreterLoadBias},{8,0},
        {9,plan.guestMainEntry},
        {11,static_cast<uint64_t>(getuid())},
        {12,static_cast<uint64_t>(geteuid())},
        {13,static_cast<uint64_t>(getgid())},
        {14,static_cast<uint64_t>(getegid())},
        {23,0},{25,stack.guestRandomPointer},
        {31,stack.guestExecFnPointer}
    }};
    if(stack.auxEntryCount!=expected.size())
        return fail("G2EC0_AUXV_EXPECTED_TAG_COUNT_REJECTED");
    for(const auto& [tag,val]:expected) {
        uint64_t actualTag=0,actualVal=0;
        if(!next(actualTag)||!next(actualVal) ||
           tag!=actualTag||val!=actualVal)
            return fail("G2EC0_AUXV_ENTRY_MISMATCH");
    }
    uint64_t nullTag=UINT64_MAX,nullValue=UINT64_MAX;
    if(!next(nullTag)||!next(nullValue) ||
       nullTag!=0||nullValue!=0)
        return fail("G2EC0_AUXV_TERMINATOR_MISSING");
    if(stack.guestRandomPointer<stack.guestBottom ||
       stack.guestRandomPointer>stack.guestTop ||
       stack.guestTop-stack.guestRandomPointer<16 ||
       stack.bytes.size()!=kC0StackBytes ||
       std::memcmp(stack.bytes.data()+
                   static_cast<size_t>(stack.guestRandomPointer-stack.guestBottom),
                   suppliedRandom.data(),16)!=0)
        return fail("G2EC0_AT_RANDOM_NOT_FROM_CALLER");
    output.futureFexRIP=plan.guestInterpreterEntry;
    output.futureFexRSP=stack.guestRSP;
    output.expectedATBase=plan.interpreterLoadBias;
    output.expectedATEntry=plan.guestMainEntry;
    output.expectedATPHDR=plan.guestMainPHDR;
    output.expectedATPHNUM=plan.mainPHNUM;
    output.expectedATRandom=stack.guestRandomPointer;
    output.exactOriginalSha256Assets=true;
    output.guestPtInterpEntryContractVerified=true;
    output.linuxX86AuxvContractVerified=true;
    reason="none";
    return true;
}

inline bool PlanPinnedRealGlibcLdsoEntryDataOnly(
    const GuestPreflight& original,
    const std::array<uint8_t,16>& entropy,
    GuestLdsoEntryWitness& witness,std::string& reason,
    g2b::X86GuestProcessLaunchPlan* planOut=nullptr) {
    witness={};
    if(planOut)*planOut={};
    if(!original.exactSha256Matched ||
       !original.readOnlyAnonymousSnapshots ||
       !original.exactInterpreterAndGlibcClosure ||
       original.guestCodeExecuted || original.dynamicLinkerExecuted ||
       original.fexAttached || original.wineExecuted) {
        reason="G2EC0_ORIGINAL_GLIBC_SNAPSHOT_NOT_VERIFIED";
        return false;
    }
    const auto fetch=[&original](std::string_view path,
                                std::vector<unsigned char>& bytes) -> bool {
        bytes.clear();
        for(size_t i=0;i<kGuest.size();++i) {
            if(path!=kGuest[i].path)continue;
            const auto& snap=original.snapshots[i];
            if(!snap.readOnlySnapshot() || !snap.bytes() ||
               snap.size()!=kGuest[i].bytes)return false;
            bytes.assign(snap.bytes(),snap.bytes()+snap.size());
            return true;
        }
        return false;
    };
    g2b::X86GuestProcessAddresses in{};
    in.mainImageStart=kC0MainTestVA;
    in.interpreterImageStart=kC0LdsoTestVA;
    in.stackBottom=kC0StackTestVA;
    in.stackBytes=kC0StackBytes;
    in.guestPageBytes=4096; // guest ELF layout; no Android host pages involved
    in.uid=static_cast<uint32_t>(getuid());
    in.euid=static_cast<uint32_t>(geteuid());
    in.gid=static_cast<uint32_t>(getgid());
    in.egid=static_cast<uint32_t>(getegid());
    in.randomBytes=entropy;
    in.argv={kGuest[0].path};
    in.environment={"LANG=C"};
    g2b::X86GuestProcessLaunchPlan computed;
    std::string failure;
    if(!g2b::PrepareX86DynamicGuestLaunchPlanFromResolver(
            fetch,kGuest[0].path,in,computed,failure)) {
        reason="G2EC0_REAL_GUEST_ELF_LAUNCH_PLAN_REJECTED:"+failure;
        return false;
    }
    if(!VerifyLdsoEntryPlanOnly(computed,entropy,witness,reason))return false;
    if(planOut)*planOut=std::move(computed);
    return true;
}
} // namespace kernix::g2e
