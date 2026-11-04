// Build-only Android/Bionic ABI entry for the G2-C fixed x86 guest bytes.
// Does NOT open FEXCore, execute guest x86 instructions, or produce an APK.
#include "kernix_g2c_snapshot_elf_source.h"
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
