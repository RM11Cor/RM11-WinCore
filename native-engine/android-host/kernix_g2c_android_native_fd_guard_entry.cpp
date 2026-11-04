// Build-only Android/Bionic ABI entry for the G2-C fixed x86 guest bytes.
// Does NOT open FEXCore, execute guest x86 instructions, or produce an APK.
#include "kernix_g2c_native_fixed_guest_fd_guard.h"
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
