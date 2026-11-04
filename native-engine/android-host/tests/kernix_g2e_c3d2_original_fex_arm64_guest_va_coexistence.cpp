// KERNIX G2-E/C3-D2 Linux ARM64 real-original-FEX guest-VA coexistence.
// Own exactly the authenticated original Linux x86 main / ld-linux / libc
// + startup stack synthetic 16K guest-VA groups as Linux PROT_NONE VMAs.
// Initialize a REAL SHA-pinned upstream FEXCore context and a not-executed
// FEX guest CPU frame while the reservations remain held. Verify every VMA
// remains exact, PROT_NONE. No guest PT_LOAD is installed into those VMAs,
// no FEX guest RIP is set, no Linux guest syscall, ld-linux or glibc executes.
// This is NOT an Android 16K native-kernel proof.
// SPDX-License-Identifier: MIT
#include "kernix_g2e_c3d1_prot_none_guest_va_lease.h"
#include <FEXCore/Config/Config.h>
#include <FEXCore/Core/Context.h>
#include <FEXCore/Core/HostFeatures.h>
#include <FEXCore/Core/CoreState.h>
#include <FEXCore/Core/SignalDelegator.h>
#include <FEXCore/Debug/InternalThreadState.h>
#include <FEXCore/HLE/SyscallHandler.h>
#include <FEXCore/Utils/AllocatorHooks.h>
#include <FEXCore/fextl/memory.h>

#include <array>
#include <cassert>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <fcntl.h>
#include <fstream>
#include <optional>
#include <string>
#include <sys/mman.h>
#include <unistd.h>

#if !defined(__aarch64__) || !defined(KERNIX_G2EC3D2_REAL_FEX_LINUX_ARM64_CI)
#error Only genuine Linux ARM64 original FEX source CI can claim C3-D2
#endif

namespace d=kernix::g2e::c3d;
namespace d1=kernix::g2e::c3d1;
using namespace kernix::g2e;

class NeverCalledGuestSyscall final: public FEXCore::HLE::SyscallHandler {
public:
    void HandleSyscall(FEXCore::Core::CpuStateFrame*) override {
        ++UnexpectedSyscallCount;
        // No guest code should run, so any callback is a hard failure.
        std::fputs("KERNIX_G2EC3D2_UNEXPECTED_REAL_X86_SYSCALL\n",stderr);
        _exit(63);
    }
    FEXCore::HLE::ExecutableRangeInfo QueryGuestExecutableRange(
        FEXCore::Core::InternalThreadState*,uint64_t) override {
        return {0,0,false};
    }
    std::optional<FEXCore::ExecutableFileSectionInfo> LookupExecutableFileSection(
        FEXCore::Core::InternalThreadState*,uint64_t) override {
        return std::nullopt;
    }
    unsigned UnexpectedSyscallCount=0;
};

static bool IsGuestVmaNoAccess(uint64_t address) {
    std::ifstream stream("/proc/self/maps");
    if(!stream)return false;
    std::string line;
    while(std::getline(stream,line)){
        unsigned long long start=0,end=0;
        char permission[5]{};
        if(std::sscanf(line.c_str(),"%llx-%llx %4s",
                       &start,&end,permission)!=3)continue;
        if(start<=address && address<end)
            return std::string(permission)=="---p";
    }
    return false;
}
static bool IsNotMapped(uint64_t address) {
    unsigned char vec[4]{};
    errno=0;
    return ::mincore(reinterpret_cast<void*>(
       static_cast<uintptr_t>(address)),d::HostPageBytes,vec)!=0 &&
       errno==ENOMEM;
}
static bool EveryGuestVmaIsProtNone(
    const d::UnifiedGuestShadow& source,
    const d1::ProtNoneGuestVALease& lease) {
    for(const auto& [address,group]:source.host16K){
        (void)group;
        if(!lease.ContainsExactReservedPage(address) ||
           !IsGuestVmaNoAccess(address))return false;
    }
    return true;
}
int main(int argc,char** argv) {
    if(argc!=2)return 2;
#if !defined(MAP_FIXED_NOREPLACE)
    std::fputs("KERNIX_G2EC3D2_NO_NOREPLACE_UNSUPPORTED_FAIL_CLOSED\n",
               stderr);
    return 3;
#endif
    const long nativePage=sysconf(_SC_PAGESIZE);
    if(nativePage!=4096 && nativePage!=16384) {
        std::fputs("KERNIX_G2EC3D2_UNSUPPORTED_NATIVE_KERNEL_PAGE\n",
                   stderr);
        return 4;
    }
    const int fd=open(argv[1],O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(fd<0)return 5;
    GuestPreflight pinned;
    std::string why;
    const bool valid=Validate(fd,pinned,why);
    close(fd);
    if(!valid)return 6;
    std::array<uint8_t,16> entropy{};
    for(size_t i=0;i<entropy.size();++i)
        entropy[i]=static_cast<uint8_t>(i+1);
    d::UnifiedGuestShadow shadow;
    if(!d::BuildUnifiedHost16KShadowFromPinnedOriginals(
        pinned,entropy,shadow,why))
        return 7;
    if(!d1::AttestedHost16KLayout(shadow) ||
       shadow.host16K.size()!=154 ||
       shadow.totalRealGuest4KPages!=609 ||
       shadow.host16KPagesWithWXSubpages!=1 ||
       shadow.pagesEligibleForRelro!=3 ||
       shadow.fexGuestMemoryAttached ||
       shadow.directGuestNativePointersExposed)
        return 8;
    const uint64_t first=shadow.host16K.begin()->first;
    if(!IsNotMapped(first))return 9;

    // FEXCore actually creates a native ARM64 JIT context / thread state,
    // while original x86 Linux image guest VAs remain PROT_NONE forever.
    {
        d1::ProtNoneGuestVALease lease;
        d1::ReservationWitness reservation;
        if(!lease.Reserve(shadow,reservation) ||
           lease.PagesHeld()!=154 ||
           reservation.successfullyReservedPages!=154 ||
           !reservation.allVAsExact ||
           !reservation.hostMappingWasProtNoneOnly ||
           reservation.hostPageWXGranted ||
           reservation.guestBytesInstalledInNativeVA ||
           reservation.fexContextAttached ||
           reservation.linuxLdsoExecuted ||
           !EveryGuestVmaIsProtNone(shadow,lease))
            return 10;

        FEXCore::Config::Initialize();
        FEXCore::Config::Load();
        FEXCore::Config::ReloadMetaLayer();
        FEXCore::Config::Set(FEXCore::Config::CONFIG_IS64BIT_MODE,"1");
        FEXCore::Config::Set(FEXCore::Config::CONFIG_MAXINST,"1");
        if(!FEXCore::Config::GetConv<bool>(
            FEXCore::Config::CONFIG_IS64BIT_MODE).value_or(false))
            return 11;
        FEXCore::HostFeatures features{};
        features.DCacheLineLog2=4;
        features.ProcessFeatures.HostType=
            FEXCore::HostFeatures::HostTypeEnum::Linux;
        features.ProcessFeatures.Is64BitMode=1;
        features.ProcessPID=static_cast<uint32_t>(getpid());
        features.CPUMIDRs.push_back(0);
        auto context=FEXCore::Context::Context::CreateNewContext(features);
        if(!context)return 12;
        FEXCore::SignalDelegator signals{};
        NeverCalledGuestSyscall denySyscalls;
        context->SetSignalDelegator(&signals);
        context->SetSyscallHandler(&denySyscalls);
        context->EnableExitOnHLT();
        if(!context->InitCore())return 13;
        auto* thread=context->CreateThread();
        if(!thread || !thread->CurrentFrame)return 14;
        // The real FEX CPUStateFrame exists, but it has NO guest entry or
        // executable guest memory attached. Do NOT call ExecuteThread().
        // The independently verified actual x86 syscall test remains C2.
        if(!EveryGuestVmaIsProtNone(shadow,lease) ||
           denySyscalls.UnexpectedSyscallCount!=0 ||
           shadow.fexGuestMemoryAttached ||
           shadow.fexCpuStateExecuted ||
           shadow.originalLdsoEntered ||
           shadow.originalLibcEntered)
            return 15;
        // The *same* real FEX context cannot overwrite a third unrelated
        // guest VA: this test asserts our owned VMA remains PROT_NONE
        // throughout upstream FEX native runtime initialization.
        std::printf(
          "KERNIX_G2EC3D2_REAL_ORIGINAL_FEX_ARM64_CONTEXT_COEXISTS_WITH_154_X86_GUEST_PROT_NONE_VAS_NO_EXEC_PASS native_kernel_page=%ld reserved_host16k=154 fex_context=1 fex_thread_created=1 fex_guest_executed=0 linux_ldso_entered=0 android_device=0\n",
          nativePage);
        // Context is destroyed before RAII lease releases owned pages.
    }
    if(!IsNotMapped(first))return 16;
    return 0;
}
