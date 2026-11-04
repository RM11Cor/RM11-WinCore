// Android/Bionic ARM64 process-entry smoke gate for the original x86 G2-C
// fixture. Independently executable ELF, but NO FEX, JIT, guest ld-linux,
// guest instruction, W+X page, Wine or Windows game execution.
// Linux host CI may run it; the Android cross-build is NOT device-proven.
// SPDX-License-Identifier: MIT
#include "kernix_g2b_readonly_host_install.h"
#include "kernix_g2c_snapshot_elf_source.h"
#include "kernix_g2c_snapshot_dependency_closure.h"
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <unistd.h>

int main(int argc,char** argv) {
    if (argc!=3 || !argv[1] || !argv[2] ||
        std::strcmp(argv[1],"--fixed-data-only-preflight")!=0 ||
        argv[2][0]!='/' || std::strlen(argv[2])>4096) {
        std::fputs("KERNIX_G2C_DATA_ONLY_CHILD_ARGUMENTS_REJECTED\n",stderr);
        return 126;
    }
    std::string why;
    kernix::g2c::FixedGuestSnapshots source;
    if (!kernix::g2c::PinAndCaptureFixedGuest(argv[2],source,why)) {
        std::fprintf(stderr,"KERNIX_G2C_DATA_ONLY_CHILD_SOURCE_REJECTED:%s\n",why.c_str());
        return 127;
    }
    auto bytes=kernix::g2c::FixedGuestSnapshotResolver(source);
    kernix::g2c::VerifiedSnapshotElfImages staged;
    if (!kernix::g2c::StageFixedMainAndInterpreterFromSnapshots(
            source,staged,why)) {
        std::fprintf(stderr,"KERNIX_G2C_DATA_ONLY_CHILD_ELF_REJECTED:%s\n",why.c_str());
        return 127;
    }
    std::array<uint8_t,16> random{};
    for (size_t i=0;i<random.size();++i)
        random[i]=static_cast<uint8_t>(i+1); // CI fixture only, not production ASLR
    kernix::g2b::X86HostReservedGuestLaunch reserved;
    if (!kernix::g2b::ReserveAndValidateX86HostGuestWindowsFromResolver(
            bytes,"/bin/kernix-dynamic-app",4096,65536,random,
            {"/bin/kernix-dynamic-app","--bounded"},{"LANG=C"},
            reserved,why)) {
        std::fprintf(stderr,"KERNIX_G2C_DATA_ONLY_CHILD_PLAN_REJECTED:%s\n",why.c_str());
        return 127;
    }
    if (!kernix::g2b::StageX86ReadonlyHostBytesFromImages(
            reserved,staged.main,staged.interpreter,why)) {
        std::fprintf(stderr,"KERNIX_G2C_DATA_ONLY_CHILD_STAGE_REJECTED:%s\n",why.c_str());
        return 127;
    }
    // No mprotect PROT_EXEC, no FEX Core::Run and no imported guest code.
    if (!source.allHashesVerified || !staged.mainFromVerifiedSnapshot ||
        !staged.interpreterFromVerifiedSnapshot ||
        !reserved.hostImageBytesStagedReadonly ||
        !reserved.hostStackBytesStagedReadonly ||
        !reserved.plan.stackAndAuxvConsistent ||
        !reserved.plan.guestVirtualAddressesValidated ||
        reserved.executableGuestPagesMapped || reserved.guestCodeExecuted ||
        reserved.plan.dynamicLinkerExecuted || reserved.androidWineTested ||
        staged.installedInFEX || staged.guestCodeExecuted ||
        staged.executablePagesEnabled || staged.glibcLoaderExecuted) {
        std::fputs("KERNIX_G2C_DATA_ONLY_CHILD_UNSUPPORTED_CLAIM_REJECTED\n",stderr);
        return 127;
    }
    std::fputs("KERNIX_G2C_NATIVE_CHILD_GUEST_BYTES_SHA256_PTLOAD_AUXV_DATA_ONLY_PASS\n",stdout);
    std::fputs("KERNIX_G2C_NATIVE_CHILD_NO_FEX_NO_GUEST_EXECUTION_NOT_ANDROID_DEVICE_PROOF\n",stderr);
    return 0;
}
