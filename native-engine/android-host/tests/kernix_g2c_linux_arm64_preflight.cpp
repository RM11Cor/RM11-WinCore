// KERNIX G2-C real Ubuntu ARM64 ELF guest stage preflight.
// Must pass before building FEX. NEVER executes guest machine code.
// SPDX-License-Identifier: MIT
#include "kernix_g2b_readonly_host_install.h"
#include <array>
#include <cstdio>
#include <fcntl.h>
#include <string>
#include <unistd.h>

#if !defined(__aarch64__)
#error G2-C staging preflight must run on actual native ARM64 Linux
#endif

int main(int argc,char** argv) {
    if (argc!=2 || !argv[1] || argv[1][0]!='/') return 2;
    int root=open(argv[1],O_DIRECTORY|O_PATH|O_NOFOLLOW|O_CLOEXEC);
    if (root<0) return 3;
    std::array<uint8_t,16> random{};
    for(size_t i=0;i<random.size();++i)random[i]=static_cast<uint8_t>(i+1);
    kernix::g2b::X86HostReservedGuestLaunch launch;
    std::string reason;
    if(!kernix::g2b::ReserveAndValidateX86HostGuestWindows(
        root,"/bin/kernix-dynamic-app",4096,65536,random,
        {"/bin/kernix-dynamic-app","--bounded"},{"LANG=C"},launch,reason)){
        std::fprintf(stderr,"KERNIX_G2C_ARM64_ELF_STAGING_PRECHECK_REJECTED=%s\n",
                     reason.c_str());
        close(root);return 4;
    }
    if(!kernix::g2b::StageX86ReadonlyHostBytes(root,launch,reason)) {
        std::fprintf(stderr,"KERNIX_G2C_ARM64_ELF_READONLY_INSTALL_REJECTED=%s\n",
                     reason.c_str());
        close(root);return 5;
    }
    close(root);
    if (!launch.hostImageBytesStagedReadonly ||
        !launch.hostStackBytesStagedReadonly ||
        launch.guestVAsInstalledInFEX ||
        launch.guestCodeExecuted ||
        launch.executableGuestPagesMapped)
        return 6;
    std::puts("KERNIX_G2C_LINUX_ARM64_REAL_ELF_GUARDED_STACK_STAGED_RO_PASS_NOT_FEX");
    return 0;
}
