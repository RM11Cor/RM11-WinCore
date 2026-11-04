// Linux host-only non-executing integration: original x86 process metadata,
// real guarded VA windows and PT_LOAD memory bytes FROM verified snapshots.
// No FEX execution, no guest dynamic-loader execution, no Android device.
#include "kernix_g2b_readonly_host_install.h"
#include "kernix_g2c_snapshot_elf_source.h"
#include "kernix_g2c_snapshot_dependency_closure.h"
#include <array>
#include <cassert>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <unistd.h>
using kernix::g2b::X86HostReservedGuestLaunch;
using kernix::g2c::FixedGuestSnapshots;
using kernix::g2c::VerifiedSnapshotElfImages;

static void Compare(const kernix::g2b::GuestReadonlyImage& image,
                    const kernix::g2b::X86HostNoAccessReservation& window,
                    const kernix::g2c::ReadonlyGuestSnapshot& source) {
    for(const auto& s:image.segments) {
        assert(s.guestVaddr >= image.guestPageAlignedBase);
        uint64_t relative=s.guestVaddr-image.guestPageAlignedBase;
        assert(relative <= window.guestBytes &&
               s.fileBytes <= window.guestBytes-relative);
        const uint8_t* installed=
            reinterpret_cast<const uint8_t*>(window.guestStart+relative);
        assert(std::memcmp(installed,source.bytes()+s.fileOffset,s.fileBytes)==0);
    }
}

int main(int argc,char** argv) {
    if(argc!=2 || !argv[1] || argv[1][0]!='/')return 2;
    const std::string app(argv[1]);
    const std::string rootPath=app+
        "/kernix/runtime-v1/guest-rootfs/g2c-fixed-v1";
    const int root=open(rootPath.c_str(),O_PATH|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    assert(root>=0);
    std::array<uint8_t,16> random{};
    for(size_t i=0;i<16;++i)random[i]=static_cast<uint8_t>(i+1);
    X86HostReservedGuestLaunch launch;
    std::string reason;
    assert(kernix::g2b::ReserveAndValidateX86HostGuestWindows(
        root,"/bin/kernix-dynamic-app",4096,65536,random,
        {"/bin/kernix-dynamic-app","--bounded"},{"LANG=C"},launch,reason));
    close(root);
    FixedGuestSnapshots snapshots;
    assert(kernix::g2c::PinAndCaptureFixedGuest(app.c_str(),snapshots,reason));
    VerifiedSnapshotElfImages staged;
    assert(kernix::g2c::StageFixedMainAndInterpreterFromSnapshots(
        snapshots,staged,reason));
    assert(kernix::g2b::StageX86ReadonlyHostBytesFromImages(
        launch,staged.main,staged.interpreter,reason));
    assert(launch.hostImageBytesStagedReadonly &&
           launch.hostStackBytesStagedReadonly &&
           !launch.guestVAsInstalledInFEX && !launch.executableGuestPagesMapped &&
           !launch.guestCodeExecuted && !launch.androidWineTested &&
           !staged.installedInFEX && !staged.guestCodeExecuted);
    Compare(staged.main,launch.main,snapshots.files[0]);
    Compare(staged.interpreter,launch.interpreter,snapshots.files[3]);
    assert(launch.plan.stack.guestRSP>=launch.stack.guestStart &&
           launch.plan.stack.guestRSP<launch.stack.guestStart+launch.stack.guestBytes);

    // The staged guest main ELF bytes survive later removal of its source.
    const std::string appExe=rootPath+"/bin/kernix-dynamic-app";
    assert(unlink(appExe.c_str())==0);
    Compare(staged.main,launch.main,snapshots.files[0]);
    assert(!launch.guestCodeExecuted && !launch.executableGuestPagesMapped);
    // Stronger independent source proof: after unlinking the original ELF,
    // reserve a NEW live guest VA layout, derive closure + PHDR + AUXV from
    // the snapshot-only resolver, and stage BOTH interpreter/main PT_LOADs.
    kernix::g2b::X86HostReservedGuestLaunch immutableLaunch;
    assert(kernix::g2b::ReserveAndValidateX86HostGuestWindowsFromResolver(
        kernix::g2c::FixedGuestSnapshotResolver(snapshots),
        "/bin/kernix-dynamic-app",4096,65536,random,
        {"/bin/kernix-dynamic-app","--bounded"},{"LANG=C"},
        immutableLaunch,reason));
    assert(immutableLaunch.hostVAsReservedPROT_NONE &&
           immutableLaunch.plan.stackAndAuxvConsistent &&
           immutableLaunch.plan.guestVirtualAddressesValidated);
    assert(kernix::g2b::StageX86ReadonlyHostBytesFromImages(
        immutableLaunch,staged.main,staged.interpreter,reason));
    Compare(staged.main,immutableLaunch.main,snapshots.files[0]);
    Compare(staged.interpreter,immutableLaunch.interpreter,snapshots.files[3]);
    assert(!immutableLaunch.guestCodeExecuted &&
           !immutableLaunch.executableGuestPagesMapped &&
           !immutableLaunch.plan.dynamicLinkerExecuted &&
           !immutableLaunch.androidWineTested);
    std::puts("KERNIX_G2C_PATHLESS_FULL_VA_CLOSURE_AUXV_PTLOAD_AFTER_UNLINK_PASS_NO_FEX");
    std::puts("KERNIX_G2C_GUARDED_GUEST_VA_AND_PTLOAD_INSTALLED_FROM_ATTESTED_SNAPSHOT_PASS_NO_FEX");
    return 0;
}
