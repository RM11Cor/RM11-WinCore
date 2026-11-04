// G2-C: process PT_INTERP, transitive DT_NEEDED, AT_PHDR/AT_ENTRY/AT_BASE,
// argv/envp and complete x86 stack bytes from only verified guest snapshots.
// No FEX guest execution, loader, Wine, or Android phone runtime.
#include "kernix_g2b_guest_host_reservations.h"
#include "kernix_g2c_snapshot_dependency_closure.h"
#include <cassert>
#include <cstdio>
#include <fcntl.h>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

static void SamePlan(const kernix::g2b::X86GuestProcessLaunchPlan& a,
                     const kernix::g2b::X86GuestProcessLaunchPlan& b) {
    assert(a.guestExecutable==b.guestExecutable);
    assert(a.guestInterpreter==b.guestInterpreter);
    assert(a.mainLoadBias==b.mainLoadBias);
    assert(a.interpreterLoadBias==b.interpreterLoadBias);
    assert(a.guestMainEntry==b.guestMainEntry);
    assert(a.guestMainPHDR==b.guestMainPHDR);
    assert(a.guestInterpreterEntry==b.guestInterpreterEntry);
    assert(a.mainPHNUM==b.mainPHNUM);
    assert(a.dependencyObjectsChecked==b.dependencyObjectsChecked);
    assert(a.regions.size()==b.regions.size());
    for (size_t i=0;i<a.regions.size();++i) {
        const auto& x=a.regions[i];
        const auto& y=b.regions[i];
        assert(x.first==y.first && x.pastLast==y.pastLast &&
               x.originalElfFlags==y.originalElfFlags &&
               x.isGuestStack==y.isGuestStack);
    }
    assert(a.stack.bytes==b.stack.bytes &&
           a.stack.guestBottom==b.stack.guestBottom &&
           a.stack.guestRSP==b.stack.guestRSP &&
           a.stack.guestTop==b.stack.guestTop &&
           a.stack.guestRandomPointer==b.stack.guestRandomPointer &&
           a.stack.guestExecFnPointer==b.stack.guestExecFnPointer &&
           a.stack.auxEntryCount==b.stack.auxEntryCount);
    assert(a.stackAndAuxvConsistent && b.stackAndAuxvConsistent);
    assert(a.guestVirtualAddressesValidated && b.guestVirtualAddressesValidated);
    assert(!b.guestMemoryMapped && !b.guestCodeExecuted &&
           !b.dynamicLinkerExecuted && !b.androidWineTested);
}

int main(int argc,char** argv) {
    if(argc!=2 || !argv[1] || argv[1][0]!='/')return 2;
    const std::string app(argv[1]);
    const std::string root=app+
      "/kernix/runtime-v1/guest-rootfs/g2c-fixed-v1";
    const int rootfd=open(root.c_str(),O_PATH|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    assert(rootfd>=0);
    std::array<uint8_t,16> random{};
    for(size_t i=0;i<random.size();++i)random[i]=static_cast<uint8_t>(i+1);
    kernix::g2b::X86HostReservedGuestLaunch host;
    std::string why;
    assert(kernix::g2b::ReserveAndValidateX86HostGuestWindows(
       rootfd,"/bin/kernix-dynamic-app",4096,65536,random,
       {"/bin/kernix-dynamic-app","--bounded"},{"LANG=C"},host,why));
    kernix::g2c::FixedGuestSnapshots snapshots;
    assert(kernix::g2c::PinAndCaptureFixedGuest(app.c_str(),snapshots,why));
    const auto fetch=kernix::g2c::FixedGuestSnapshotResolver(snapshots);
    kernix::g2b::X86GuestProcessAddresses input{};
    input.mainImageStart=host.main.guestStart;
    input.interpreterImageStart=host.interpreter.guestStart;
    input.stackBottom=host.stack.guestStart;
    input.stackBytes=65536;
    input.guestPageBytes=4096;
    input.uid=static_cast<uint32_t>(getuid());
    input.euid=static_cast<uint32_t>(geteuid());
    input.gid=static_cast<uint32_t>(getgid());
    input.egid=static_cast<uint32_t>(getegid());
    input.randomBytes=random;
    input.argv={"/bin/kernix-dynamic-app","--bounded"};
    input.environment={"LANG=C"};
    kernix::g2b::X86GuestProcessLaunchPlan snapshotPlan;
    assert(kernix::g2b::PrepareX86DynamicGuestLaunchPlanFromResolver(
        fetch,"/bin/kernix-dynamic-app",input,snapshotPlan,why));
    SamePlan(host.plan,snapshotPlan);

    const std::string libc=root+"/lib/x86_64-linux-gnu/libc.so.6";
    assert(unlink(libc.c_str())==0);
    kernix::g2b::X86GuestProcessLaunchPlan afterUnlink;
    assert(kernix::g2b::PrepareX86DynamicGuestLaunchPlanFromResolver(
        fetch,"/bin/kernix-dynamic-app",input,afterUnlink,why));
    SamePlan(snapshotPlan,afterUnlink);

    kernix::g2b::X86GuestProcessLaunchPlan diskAfterUnlink;
    assert(!kernix::g2b::PrepareX86DynamicGuestLaunchPlan(
        rootfd,"/bin/kernix-dynamic-app",input,diskAfterUnlink,why));
    assert(diskAfterUnlink.stack.bytes.empty());

    kernix::g2b::GuestELFBytesResolver unknown=[](
        std::string_view, std::vector<unsigned char>& data) {
        data.clear();return false;
    };
    kernix::g2b::X86GuestProcessLaunchPlan rejected;
    assert(!kernix::g2b::PrepareX86DynamicGuestLaunchPlanFromResolver(
        unknown,"/bin/kernix-dynamic-app",input,rejected,why));
    assert(rejected.regions.empty() && rejected.stack.bytes.empty());
    snapshots.reset();
    assert(!kernix::g2b::PrepareX86DynamicGuestLaunchPlanFromResolver(
        fetch,"/bin/kernix-dynamic-app",input,rejected,why));
    close(rootfd);
    std::puts("KERNIX_G2C_PATHLESS_PT_INTERP_DEPENDENCIES_PHDR_AUXV_STACK_MATCH_PASS_NOT_FEX_DEVICE");
    return 0;
}
