// KERNIX G2-C MIT-only genuinely dynamically linked x86 ELF on host.
// Reads + validates actual PT_INTERP / DT_NEEDED / PHDR / AUXV / anonymous
// PT_LOAD, but NEVER executes x86 guest, any loader, FEX or Wine.
// SPDX-License-Identifier: MIT
#include "kernix_g2b_readonly_host_install.h"
#include <array>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <unistd.h>

static constexpr const char* kMITMain = "/bin/kernix-mit-dynamic-app";
static constexpr const char* kMITInterpreter =
    "/lib64/ld-kernix-g2c-mit-placeholder.so.1";
static constexpr const char* kMITNeeded =
    "/lib/x86_64-linux-gnu/libkernix-g2c-mit-placeholder.so.1";

int main(int argc,char** argv) {
    if ((argc!=2 && argc!=3) || !argv[1] || argv[1][0]!='/')
        return 2;
    const bool expectReject=argc==3 && argv[2] &&
        std::strcmp(argv[2],"--expected-missing-dependency")==0;
    if(argc==3 && !expectReject)return 2;
    const int fd=open(argv[1],O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
    if(fd<0) return 3;
    kernix::g2b::GuestDependencyClosure closure;
    std::string why;
    const bool audited=kernix::g2b::AuditGuestELFDependencyClosure(
        fd,kMITMain,closure,why);
    if(expectReject){
        close(fd);
        if(audited){
            std::fputs("KERNIX_G2C_MIT_CLOSURE_UNSAFE_MISSING_DSO_ACCEPTED\n",stderr);
            return 4;
        }
        std::puts("KERNIX_G2C_MIT_ONLY_MISSING_DSO_REJECTED_NOT_GUEST_EXECUTED");
        return 0;
    }
    if(!audited || !closure.allDirectAndTransitiveFilesPresent ||
       closure.guestInterpreter!=kMITInterpreter ||
       closure.nodes.size()!=3 || closure.resolvedEdges!=1 ||
       closure.nodes[0].needed.size()!=1 ||
       closure.nodes[0].needed[0]!="libkernix-g2c-mit-placeholder.so.1" ||
       closure.nodes[0].resolvedDirectLibraries.size()!=1 ||
       closure.nodes[0].resolvedDirectLibraries[0]!=kMITNeeded ||
       closure.guestCodeExecuted || closure.relocationsApplied ||
       closure.symbolVersionsResolved || closure.androidWineTested){
        std::fprintf(stderr,"KERNIX_G2C_MIT_CLOSURE_REJECTED: %s\n",why.c_str());
        close(fd);return 5;
    }
    std::array<uint8_t,16> random{};
    for(size_t i=0;i<random.size();++i)random[i]=static_cast<uint8_t>(i+1);
    kernix::g2b::X86HostReservedGuestLaunch host;
    if (!kernix::g2b::ReserveAndValidateX86HostGuestWindows(
            fd,kMITMain,4096,65536,random,
            {kMITMain,"--bounded"},{"LANG=C"},host,why) ||
        !host.plan.stackAndAuxvConsistent ||
        !host.plan.guestVirtualAddressesValidated ||
        host.plan.guestInterpreter!=kMITInterpreter ||
        !kernix::g2b::StageX86ReadonlyHostBytes(fd,host,why) ||
        !host.hostImageBytesStagedReadonly ||
        !host.hostStackBytesStagedReadonly ||
        host.executableGuestPagesMapped || host.guestCodeExecuted ||
        host.guestVAsInstalledInFEX || host.androidWineTested ||
        host.plan.dynamicLinkerExecuted){
        std::fprintf(stderr,"KERNIX_G2C_MIT_HOST_STAGE_REJECTED: %s\n",why.c_str());
        close(fd);return 6;
    }
    close(fd);
    std::puts("KERNIX_G2C_MIT_ONLY_THREE_ELF_REAL_PT_INTERP_NEEDED_PHDR_AUXV_PTLOAD_HOST_PASS_NO_FEX");
    return 0;
}
