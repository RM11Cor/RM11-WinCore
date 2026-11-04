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
#include "kernix_g2c_snapshot_elf_source.h"
#include "kernix_g2c_snapshot_dependency_closure.h"
#include "kernix_g2c_fixed_android_candidate_gate.h"
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
  #if (defined(KERNIX_G2C_ANDROID_BIONIC_BUILD_ONLY) == defined(KERNIX_G2C_ANDROID_DEVICE_CANDIDATE_CI)) || defined(KERNIX_G2C_NATIVE_ARM64_CI)
    #error Android G2-C requires exactly one blocked or candidate CI policy
  #endif
#else
  #if !defined(KERNIX_G2C_NATIVE_ARM64_CI) || defined(KERNIX_G2C_ANDROID_BIONIC_BUILD_ONLY) || defined(KERNIX_G2C_ANDROID_DEVICE_CANDIDATE_CI)
    #error Linux G2-C limited to original ARM64 JIT CI
  #endif
#endif

namespace {
constexpr uint64_t kExpectedRax = 0x4b45524e49584732ULL;
constexpr const char* kPath = "/bin/kernix-dynamic-app";
constexpr const char* kMitPath = "/bin/kernix-mit-dynamic-app";
constexpr const char* kMitPass =
    "KERNIX_G2C_ORIGINAL_FEX_ARM64_MIT_ONLY_DYNAMIC_PIE_DIRECT_ENTRY_PASS_NO_GLIBC";
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

__attribute__((used)) int ExecuteBoundedFixedGuest(
    const char* trustedRootfs, const char* appPrivateDir = nullptr,
    const char* selectedGuestPath = kPath) {
    const bool useSnapshots=appPrivateDir!=nullptr;
    const bool mitGuest=std::strcmp(selectedGuestPath,kMitPath)==0;
    if (mitGuest && useSnapshots) return 10; // existing pinned 4-ELF snapshot is glibc-only
    if (!mitGuest && std::strcmp(selectedGuestPath,kPath)!=0) return 10;
    // Snapshot mode NEVER opens the disk guest rootfs path here. The
    // independent fixed-file O_NOFOLLOW + SHA-256 source resolver owns
    // every byte used by the dependency closure, host VA plan, ELF PT_LOAD,
    // runtime PHDR metadata and the Linux x86_64 initial stack.
    const int rootfd=useSnapshots ? -1 :
        open(trustedRootfs,O_PATH|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if (!useSnapshots && rootfd<0) return 11;
    kernix::g2c::FixedGuestSnapshots source;
    kernix::g2c::VerifiedSnapshotElfImages frozen;
    std::string why;
    if (useSnapshots &&
        !kernix::g2c::PinAndCaptureFixedGuest(appPrivateDir,source,why)) {
        std::fprintf(stderr,"KERNIX_G2C_SNAPSHOT_INPUT_REJECTED %s\n",why.c_str());
        return 11;
    }
    std::array<uint8_t,16> random{};
    for(unsigned i=0;i<random.size();++i)
        random[i]=static_cast<uint8_t>(i+1); // fixed TEST fixture, not production entropy
    kernix::g2b::X86HostReservedGuestLaunch host;
    const bool planOkay=useSnapshots
       ? kernix::g2b::ReserveAndValidateX86HostGuestWindowsFromResolver(
             kernix::g2c::FixedGuestSnapshotResolver(source),
             selectedGuestPath,4096,65536,random,
             {selectedGuestPath,"--bounded"},{"LANG=C"},host,why)
       : kernix::g2b::ReserveAndValidateX86HostGuestWindows(
             rootfd,selectedGuestPath,4096,65536,random,
             {selectedGuestPath,"--bounded"},{"LANG=C"},host,why);
    if (!planOkay) {
        std::fprintf(stderr,"KERNIX_G2C_BOUNDED_GUEST_PLAN_REJECTED %s\n",why.c_str());
        close(rootfd); return 12;
    }
    // Plan, DT_NEEDED closure and AUXV are now sourced from the same
    // verified anonymous guest bytes that supply the final FEX text PT_LOAD.
    // Android main() stays a hard 126 exit; no phone execution is enabled.
    if (useSnapshots &&
        !kernix::g2c::StageFixedMainAndInterpreterFromSnapshots(
              source,frozen,why)) {
        std::fprintf(stderr,"KERNIX_G2C_SNAPSHOT_INPUT_REJECTED %s\n",why.c_str());
        close(rootfd);return 13;
    }
    const bool hostStaged=useSnapshots
       ? kernix::g2b::StageX86ReadonlyHostBytesFromImages(
             host,frozen.main,frozen.interpreter,why)
       : kernix::g2b::StageX86ReadonlyHostBytes(rootfd,host,why);
    if (!hostStaged) {
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
    kernix::g2b::GuestReadonlyImage pathImage;
    if (!useSnapshots && !kernix::g2b::StageReadOnlyGuestELFImage(
            rootfd,selectedGuestPath,pathImage,why,true)) {
        close(rootfd);return 15;
    }
    close(rootfd);
    const auto& image=useSnapshots ? frozen.main : pathImage;

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
    if (useSnapshots) {
        std::fputs("KERNIX_G2C_STAGE=RX_PTLOAD_FROM_VERIFIED_ANONYMOUS_SNAPSHOTS_NO_PATH_REOPEN\n",stderr);
        std::fputs("KERNIX_G2C_STAGE=PT_INTERP_TRANSITIVE_NEEDED_PHDR_AUXV_FROM_SNAPSHOT_ONLY\n",stderr);
    }
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
#if defined(KERNIX_G2C_ANDROID_DEVICE_CANDIDATE_CI)
    std::fputs("KERNIX_G2C_ANDROID_FEX_DIRECT_PIE_ENTRY_PASS_NOT_GLIBC_V1\n"
               "GUEST_RAX=0x4b45524e49584732\n",stdout);
#else
    std::puts(mitGuest ? kMitPass : kPass);
#endif
    std::fflush(stdout);
    // CI run uses disposable child; VM and FEX JIT lifetime ends here.
    return 0;
}
} // namespace
#if defined(KERNIX_G2C_ANDROID_BIONIC_BUILD_ONLY)
// This ELF is compiled and linked for Android/Bionic ABI auditing only.
// It is NEVER packaged, signed for the user, or executed by an Android app.
// Retain compilation of full FEX guest code using [[gnu::used]] above,
// but NEVER export a callable entry that can run it on unqualified Android.
// The previous build-only witness accepted a non-null rootfs and executed
// guest code despite the intended gate: eliminate that bypass entirely.
extern "C" __attribute__((used, visibility("default")))
int kernix_g2c_android_build_only_link_check(const char* rootfs) {
    (void)rootfs;
    return 126;
}
int main(int, char**) {
    std::fputs("KERNIX_G2C_ANDROID_BIONIC_BUILD_ONLY_NOT_DEVICE_EXECUTED\n", stderr);
    return 126;
}
#elif defined(KERNIX_G2C_ANDROID_DEVICE_CANDIDATE_CI)
// Signed-APK-only FUTURE fixed candidate, compiled for build auditing.
// Never shipped or executed by this workflow. Only one strict flag,
// and exact native four-file pinned SHA-256 source before any guest JIT.
int main(int argc,char** argv) {
    const std::array<const char*,3> args{
        argc>0?argv[0]:nullptr,argc>1?argv[1]:nullptr,
        argc>2?argv[2]:nullptr
    };
    if (!kernix::g2c::IsFixedDeviceCandidateInvocation(argc,args.data())) {
        std::fputs("KERNIX_G2C_ANDROID_CANDIDATE_FIXED_ARGS_REJECTED\n",stderr);
        return 126;
    }
    // Main x86 _start directly, bypass ld-linux and glibc.
    return ExecuteBoundedFixedGuest(nullptr,argv[2]);
}
#else
int main(int argc,char** argv) {
    // This wholly MIT-only fixture bypasses Ubuntu libc's distribution
    // blocker while proving the SAME original FEX PT_INTERP / DT_NEEDED
    // launch layout. It still enters main _start, never the test interpreter.
    if (argc==3 && argv[1] && argv[1][0]=='/' &&
        argv[2] && std::strcmp(argv[2],"--mit-no-glibc")==0)
        return ExecuteBoundedFixedGuest(argv[1],nullptr,kMitPath);
    if ((argc!=2 && argc!=3) || !argv[1] || argv[1][0]!='/' ||
        (argc==3 && (!argv[2] || argv[2][0]!='/')))return 2;
    return ExecuteBoundedFixedGuest(argv[1],argc==3?argv[2]:nullptr);
}
#endif
