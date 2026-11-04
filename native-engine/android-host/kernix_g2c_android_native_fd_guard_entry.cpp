// Build-only Android/Bionic ABI entry for the G2-C fixed x86 guest bytes.
// Does NOT open FEXCore, execute guest x86 instructions, or produce an APK.
#include "kernix_g2c_snapshot_elf_source.h"
#include "kernix_g2c_snapshot_dependency_closure.h"
#include "kernix_g2b_guest_launch_plan.h"
#if !defined(__aarch64__) || !defined(__ANDROID__)
#error The G2-C native FD guard ABI proof requires Android AArch64/Bionic
#endif
extern "C" __attribute__((visibility("default")))
int kernix_g2c_bionic_pin_fixed_x86_files_build_only(const char* appFilesDir) {
    kernix::g2c::FixedGuestFileSet verified;
    std::string reason;
    return kernix::g2c::PinAndVerifyFixedGuest(appFilesDir,verified,reason)
           && verified.descriptorsPinned && verified.sha256Verified
           && !verified.guestCodeExecuted && !verified.executableGuestPagesMapped
           ? 0 : 126;
}

extern "C" __attribute__((visibility("default")))
int kernix_g2c_bionic_capture_fixed_x86_snapshots_build_only(
    const char* appFilesDir) {
    kernix::g2c::FixedGuestSnapshots image;
    std::string reason;
    if(!kernix::g2c::PinAndCaptureFixedGuest(appFilesDir,image,reason))
        return 126;
    if(!image.allHashesVerified || image.handedToFEX ||
       image.guestExecuted || image.interpreterExecuted || image.wineTested)
        return 127;
    for(const auto& part : image.files) {
        if(!part.readOnlySnapshot() || !part.bytes() || !part.size())return 128;
    }
    return 0; // DATA-ONLY native memory capture, NOT running FEX/loader
}

extern "C" __attribute__((visibility("default")))
int kernix_g2c_bionic_stage_fixed_x86_elf_from_snapshots_build_only(
    const char* appFilesDir) {
    kernix::g2c::FixedGuestSnapshots source;
    std::string reason;
    if (!kernix::g2c::PinAndCaptureFixedGuest(appFilesDir,source,reason))
        return 126;
    kernix::g2c::VerifiedSnapshotElfImages staged;
    if (!kernix::g2c::StageFixedMainAndInterpreterFromSnapshots(
            source,staged,reason))
        return 127;
    return staged.mainFromVerifiedSnapshot &&
           staged.interpreterFromVerifiedSnapshot &&
           !staged.sourcePathReopened &&
           !staged.installedInFEX && !staged.guestCodeExecuted &&
           !staged.glibcLoaderExecuted && !staged.wineTested ? 0 : 128;
}

extern "C" __attribute__((visibility("default")))
int kernix_g2c_bionic_audit_snapshot_elf_closure_build_only(
    const char* appFilesDir) {
    kernix::g2c::FixedGuestSnapshots fixed;
    std::string reason;
    if (!kernix::g2c::PinAndCaptureFixedGuest(appFilesDir,fixed,reason))
        return 126;
    kernix::g2b::GuestDependencyClosure closure;
    if (!kernix::g2c::AuditFixedGuestDependencyClosure(fixed,closure,reason))
        return 127;
    return closure.allDirectAndTransitiveFilesPresent &&
           closure.guestInterpreter=="/lib64/ld-linux-x86-64.so.2" &&
           !closure.guestCodeExecuted && !closure.relocationsApplied &&
           !closure.symbolVersionsResolved && !closure.androidWineTested
            ? 0 : 128; // Never execute x86 or ld-linux
}

extern "C" __attribute__((visibility("default")))
int kernix_g2c_bionic_plan_x86_auxv_from_snapshots_build_only(
    const char* appFilesDir,uint64_t mainStart,uint64_t interpreterStart,
    uint64_t stackStart) {
    kernix::g2c::FixedGuestSnapshots fixed;
    std::string why;
    if (!kernix::g2c::PinAndCaptureFixedGuest(appFilesDir,fixed,why))
        return 126;
    kernix::g2b::X86GuestProcessAddresses addresses{};
    addresses.mainImageStart=mainStart;
    addresses.interpreterImageStart=interpreterStart;
    addresses.stackBottom=stackStart;
    addresses.stackBytes=65536;
    addresses.guestPageBytes=4096;
    addresses.uid=static_cast<uint32_t>(getuid());
    addresses.euid=static_cast<uint32_t>(geteuid());
    addresses.gid=static_cast<uint32_t>(getgid());
    addresses.egid=static_cast<uint32_t>(getegid());
    for (size_t i=0;i<addresses.randomBytes.size();++i)
        addresses.randomBytes[i]=static_cast<uint8_t>(i+1);
    addresses.argv={"/bin/kernix-dynamic-app","--bounded"};
    addresses.environment={"LANG=C"};
    kernix::g2b::X86GuestProcessLaunchPlan plan;
    if (!kernix::g2b::PrepareX86DynamicGuestLaunchPlanFromResolver(
          kernix::g2c::FixedGuestSnapshotResolver(fixed),
          "/bin/kernix-dynamic-app",addresses,plan,why))
        return 127;
    return plan.stackAndAuxvConsistent &&
           plan.guestVirtualAddressesValidated && !plan.guestCodeExecuted &&
           !plan.dynamicLinkerExecuted && !plan.androidWineTested ? 0 : 128;
}
