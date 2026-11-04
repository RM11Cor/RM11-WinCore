/*
 * KERNIX G2-C bounded FEXCore real x86_64 PIE direct-entry execution proof.
 * Reads real DT_NEEDED+PT_INTERP/ELF from an app-owned CI guest rootfs;
 * installs x86 PT_LOAD+argv/envp/AUXV bytes in guarded host VM, enables
 * RX only on the fixed guest executable's one text PT_LOAD, then enters
 * _start DIRECTLY through original upstream FEXCore. This deliberately
 * BYPASSES ld-linux. No glibc, Windows PE, Wine or game execution claims.
 * A dedicated disposable Linux ARM64 CI child+watchdog must supervise it.
 * SPDX-License-Identifier: MIT
 */
#include "kernix_g2b_readonly_host_install.h"
#include <FEXCore/Config/Config.h>
#include <FEXCore/Core/Context.h>
#include <FEXCore/Core/HostFeatures.h>
#include <FEXCore/Core/CoreState.h>
#include <FEXCore/Core/X86Enums.h>
#include <FEXCore/Core/SignalDelegator.h>
#include <FEXCore/Debug/InternalThreadState.h>
#include <FEXCore/HLE/SyscallHandler.h>
#include <FEXCore/Utils/AllocatorHooks.h>
#include <FEXCore/fextl/memory.h>

#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <optional>
#include <string>
#include <vector>

#if !defined(__aarch64__)
#error KERNIX G2-C requires a real AArch64 target
#endif
#if defined(__ANDROID__)
  #if !defined(KERNIX_G2C_ANDROID_BIONIC_BUILD_ONLY) || defined(KERNIX_G2C_NATIVE_ARM64_CI)
    #error Android G2-C is cross-link/build-only until the separately supervised device gate
  #endif
#else
  #if !defined(KERNIX_G2C_NATIVE_ARM64_CI) || defined(KERNIX_G2C_ANDROID_BIONIC_BUILD_ONLY)
    #error Linux G2-C real guest execution is allowed only in its native ARM64 CI gate
  #endif
#endif

namespace {
constexpr uint64_t kExpectedRax = 0x4b45524e49584732ULL;
constexpr const char* kPath = "/bin/kernix-dynamic-app";
constexpr const char* kPass =
    "KERNIX_G2C_REAL_X86_DYNAMIC_PIE_DIRECT_ENTRY_STACK_AUXV_FEX_ARM64_PASS_NOT_GLIBC";

class RejectAllGuestSyscalls final : public FEXCore::HLE::SyscallHandler {
public:
    RejectAllGuestSyscalls(uint64_t first, uint64_t bytes)
      : TextFirst(first), TextBytes(bytes) {}
    void HandleSyscall(FEXCore::Core::CpuStateFrame*) override {
        std::fputs("KERNIX_G2C_UNEXPECTED_GUEST_SYSCALL_REJECTED\n",stderr);
        std::fflush(stderr);
        _exit(83);
    }
    FEXCore::HLE::ExecutableRangeInfo QueryGuestExecutableRange(
       FEXCore::Core::InternalThreadState*, uint64_t at) override {
        if (at >= TextFirst && at - TextFirst < TextBytes)
            return {TextFirst,TextBytes,false};
        return {0,0,false};
    }
    std::optional<FEXCore::ExecutableFileSectionInfo>
    LookupExecutableFileSection(FEXCore::Core::InternalThreadState*,
                                uint64_t) override {
        return std::nullopt;
    }
private:
    uint64_t TextFirst=0;
    uint64_t TextBytes=0;
};

int ExecuteBoundedFixedGuest(const char* trustedRootfs) {
    const int rootfd=open(trustedRootfs,O_PATH|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if (rootfd<0) return 11;
    std::array<uint8_t,16> random{};
    for(unsigned i=0;i<random.size();++i)
        random[i]=static_cast<uint8_t>(i+1); // fixed TEST fixture, not production entropy
    kernix::g2b::X86HostReservedGuestLaunch host;
    std::string why;
    if (!kernix::g2b::ReserveAndValidateX86HostGuestWindows(
            rootfd,kPath,4096,65536,random,
            {kPath,"--bounded"},{"LANG=C"},host,why)) {
        std::fprintf(stderr,"KERNIX_G2C_BOUNDED_GUEST_PLAN_REJECTED %s\n",why.c_str());
        close(rootfd); return 12;
    }
    if (!kernix::g2b::StageX86ReadonlyHostBytes(rootfd,host,why)) {
        std::fprintf(stderr,"KERNIX_G2C_PTLOAD_HOST_STAGE_REJECTED %s\n",why.c_str());
        close(rootfd); return 13;
    }
    if (!host.hostImageBytesStagedReadonly ||
        !host.hostStackBytesStagedReadonly ||
        !host.plan.stackAndAuxvConsistent ||
        !host.plan.guestVirtualAddressesValidated ||
        host.plan.guestCodeExecuted ||
        host.plan.dynamicLinkerExecuted ||
        host.guestVAsInstalledInFEX ||
        host.executableGuestPagesMapped) {
        close(rootfd);return 14;
    }
    kernix::g2b::GuestReadonlyImage image;
    if (!kernix::g2b::StageReadOnlyGuestELFImage(
            rootfd,kPath,image,why,true)) {
        close(rootfd);return 15;
    }
    close(rootfd);

    const long pageSize=sysconf(_SC_PAGESIZE);
    if (pageSize!=4096) return 16;
    const uint64_t page=static_cast<uint64_t>(pageSize);
    uint64_t text=0,textSize=0;
    unsigned executableSections=0;
    for (const auto& seg:image.segments) {
        if (!(seg.guestFlags&PF_X)) continue;
        if (seg.guestFlags&PF_W || !seg.fileBytes ||
            ++executableSections!=1 ||
            seg.guestVaddr>UINT64_MAX-host.plan.mainLoadBias) return 17;
        text=host.plan.mainLoadBias+seg.guestVaddr;
        textSize=seg.memoryBytes;
        if (text<host.main.guestStart ||
            textSize>host.main.guestBytes ||
            text-host.main.guestStart>host.main.guestBytes-textSize ||
            text>UINT64_MAX-textSize-page+1) return 18;
        const uint64_t begin=text&~(page-1);
        const uint64_t end=(text+textSize+page-1)&~(page-1);
        if (end<=begin || end>host.main.guestStart+host.main.guestBytes ||
            mprotect(reinterpret_cast<void*>(static_cast<uintptr_t>(begin)),
                     static_cast<size_t>(end-begin),
                     PROT_READ|PROT_EXEC)!=0) return 19;
    }
    if (executableSections!=1 || !text || !textSize ||
        host.plan.guestMainEntry<text ||
        host.plan.guestMainEntry-text>=textSize ||
        host.plan.stack.guestRSP<host.stack.guestStart ||
        host.plan.stack.guestRSP>=host.stack.guestStart+host.stack.guestBytes)
        return 20;

    std::fprintf(stderr,
        "KERNIX_G2C_STAGE=real_x86_PIE_DT_NEEDED_and_PT_INTERP_metadata__direct_entry_bypasses_loader\n");
    std::fprintf(stderr,
        "KERNIX_G2C_STAGE=host_main_RX_interpreter_RO_guest_stack_RO_guards_NONE\n");
    FEXCore::Config::Initialize();
    FEXCore::Config::Load();
    FEXCore::Config::ReloadMetaLayer();
    // Critical G1 fix: reload clears ad-hoc config; 64-bit mode must be SET AFTER.
    FEXCore::Config::Set(FEXCore::Config::CONFIG_IS64BIT_MODE,"1");
    if (!FEXCore::Config::GetConv<bool>(
          FEXCore::Config::CONFIG_IS64BIT_MODE).value_or(false))return 21;

    FEXCore::HostFeatures features{};
    features.DCacheLineLog2=4;
    features.ProcessFeatures.HostType=FEXCore::HostFeatures::HostTypeEnum::Linux;
    features.ProcessFeatures.Is64BitMode=1;
    features.ProcessPID=static_cast<uint32_t>(getpid());
    features.CPUMIDRs.push_back(0);
    auto context=FEXCore::Context::Context::CreateNewContext(features);
    if (!context) return 22;
    FEXCore::SignalDelegator signals{};
    RejectAllGuestSyscalls noSyscalls{text,textSize};
    context->SetSignalDelegator(&signals);
    context->SetSyscallHandler(&noSyscalls);
    context->EnableExitOnHLT();
    if (!context->InitCore())return 23;
    auto* thread=context->CreateThread();
    if (!thread || !thread->CurrentFrame)return 24;

    FEXCore::Core::CPUState::gdt_segment gdt[32]{};
    auto& state=thread->CurrentFrame->State;
    state.segment_arrays[FEXCore::Core::CPUState::SEGMENT_ARRAY_INDEX_GDT]=gdt;
    state.segment_arrays[FEXCore::Core::CPUState::SEGMENT_ARRAY_INDEX_LDT]=gdt;
    state.cs_idx=FEXCore::Core::CPUState::DEFAULT_USER_CS<<3;
    auto* segment=FEXCore::Core::CPUState::GetSegmentFromIndex(state,state.cs_idx);
    FEXCore::Core::CPUState::SetGDTBase(segment,0);
    FEXCore::Core::CPUState::SetGDTLimit(segment,0xFFFFF);
    segment->L=1;
    segment->D=0;
    state.cs_cached=0;
    state.gregs[FEXCore::X86State::REG_RSP]=host.plan.stack.guestRSP;
    state.gregs[FEXCore::X86State::REG_RAX]=0;
    state.rip=host.plan.guestMainEntry; // deliberately NOT ld-linux interpreter entry

    context->ExecuteThread(thread);
    const uint64_t got=
        thread->CurrentFrame->State.gregs[FEXCore::X86State::REG_RAX];
    std::fprintf(stderr,"KERNIX_G2C_FEX_RETURNED_RAX=0x%016llx\n",
                 static_cast<unsigned long long>(got));
    if (got!=kExpectedRax)return 25;
    std::puts(kPass);
    std::fflush(stdout);
    // CI run uses disposable child; VM and FEX JIT lifetime ends here.
    return 0;
}
} // namespace
#if defined(KERNIX_G2C_ANDROID_BIONIC_BUILD_ONLY)
// This ELF is compiled and linked for Android/Bionic ABI auditing only.
// It is NEVER packaged, signed for the user, or executed by an Android app.
// Preserve a compiled and link-checked reference to the full original FEX
// guest launch implementation, but block accidental Android execution.
extern "C" __attribute__((used, visibility("default")))
int kernix_g2c_android_build_only_link_check(const char* rootfs) {
    if (rootfs == nullptr) return 126;
    return ExecuteBoundedFixedGuest(rootfs);
}
int main(int, char**) {
    std::fputs("KERNIX_G2C_ANDROID_BIONIC_BUILD_ONLY_NOT_DEVICE_EXECUTED\n", stderr);
    return 126;
}
#else
int main(int argc,char** argv) {
    if (argc!=2 || !argv[1] || argv[1][0]!='/')return 2;
    return ExecuteBoundedFixedGuest(argv[1]);
}
#endif
