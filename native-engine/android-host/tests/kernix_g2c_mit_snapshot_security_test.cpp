// No guest execution. Real original three-ELF MIT snapshot in guarded
// host VM, with source corruption and symlink rejection adversarial cases.
// SPDX-License-Identifier: MIT
#include "kernix_g2c_mit_owned_guest_snapshots.h"
#include <array>
#include <cassert>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>
#include <sys/stat.h>
#include <vector>

namespace fs=std::filesystem;

int main(int argc,char** argv) {
    if(argc!=2 || !argv[1] || argv[1][0]!='/')return 2;
    const fs::path app=fs::path(argv[1]);
    const fs::path root=app/"kernix/runtime-v1/guest-rootfs/g2c-mit-v1";
    kernix::g2c::MitGuestSnapshots snapshots;
    std::string reason;
    assert(kernix::g2c::PinAndCaptureMITGuest(argv[1],snapshots,reason));
    assert(snapshots.allSha256Verified && !snapshots.guestExecuted &&
           !snapshots.loaderExecuted && !snapshots.wineExecuted);
    auto resolver=kernix::g2c::MITGuestSnapshotResolver(snapshots);
    std::vector<unsigned char> bytes;
    assert(resolver(kernix::g2c::kMITMain,bytes));
    assert(bytes.size()==kernix::g2c::kMITBytes[0]);
    assert(!resolver("/lib/x86_64-linux-gnu/libc.so.6",bytes));
    assert(bytes.empty());
    kernix::g2b::GuestDependencyClosure closure;
    assert(kernix::g2b::AuditGuestELFDependencyClosureFromResolver(
               resolver,kernix::g2c::kMITMain,closure,reason));
    assert(closure.guestInterpreter==kernix::g2c::kMITInterpreter &&
           closure.nodes.size()==3 && closure.resolvedEdges==1 &&
           closure.allDirectAndTransitiveFilesPresent &&
           !closure.guestCodeExecuted && !closure.relocationsApplied);
    kernix::g2b::GuestReadonlyImage main,loader;
    assert(kernix::g2c::StageMITMainAndInterpreter(
               snapshots,main,loader,reason));
    assert(main.hostViewReadOnly && loader.hostViewReadOnly &&
           !main.hostViewExecutable && !loader.hostViewExecutable);
    std::array<uint8_t,16> random{};
    for(size_t i=0;i<random.size();++i)
        random[i]=static_cast<uint8_t>(i+1);
    kernix::g2b::X86HostReservedGuestLaunch host;
    assert(kernix::g2b::ReserveAndValidateX86HostGuestWindowsFromResolver(
        resolver,kernix::g2c::kMITMain,4096,65536,random,
        {kernix::g2c::kMITMain,"--bounded"},{"LANG=C"},host,reason));
    assert(host.plan.stackAndAuxvConsistent &&
           host.plan.guestVirtualAddressesValidated &&
           !host.executableGuestPagesMapped);
    assert(kernix::g2b::StageX86ReadonlyHostBytesFromImages(
        host,main,loader,reason));
    assert(host.hostImageBytesStagedReadonly &&
           host.hostStackBytesStagedReadonly && !host.guestCodeExecuted &&
           !host.guestVAsInstalledInFEX && !host.plan.dynamicLinkerExecuted);

    // Change the SOURCE ELF after successfully sealing the anonymous bytes;
    // the snapshot-only full dependency closure and host PT_LOAD MUST still
    // use the original verified bytes, never reopen disk path.
    const fs::path diskMain=root/"bin/kernix-mit-dynamic-app";
    assert(chmod(diskMain.c_str(),0600)==0);
    {
        std::fstream change(diskMain,std::ios::binary|std::ios::in|std::ios::out);
        assert(change.good());
        change.seekp(100);const char bad=static_cast<char>(0xff);
        change.write(&bad,1);
        assert(change.good());
    }
    kernix::g2c::MitGuestSnapshots rejected;
    assert(!kernix::g2c::PinAndCaptureMITGuest(
        argv[1],rejected,reason));
    assert(resolver(kernix::g2c::kMITMain,bytes));
    kernix::g2c::Sha256 sha;
    sha.Update(bytes.data(),bytes.size());
    assert(sha.FinishHex()==kernix::g2c::kMITSha256[0]);
    assert(kernix::g2b::AuditGuestELFDependencyClosureFromResolver(
         resolver,kernix::g2c::kMITMain,closure,reason));
    kernix::g2b::X86HostReservedGuestLaunch again;
    assert(kernix::g2b::ReserveAndValidateX86HostGuestWindowsFromResolver(
        resolver,kernix::g2c::kMITMain,4096,65536,random,
        {kernix::g2c::kMITMain,"--bounded"},{"LANG=C"},again,reason));
    assert(kernix::g2b::StageX86ReadonlyHostBytesFromImages(
        again,main,loader,reason));
    // Replacing fixed guest directory with a symlink MUST be rejected even
    // though the old in-memory snapshots remain trusted and unchanged.
    const fs::path backup=root.parent_path()/"g2c-mit-backup";
    assert(::rename(root.c_str(),backup.c_str())==0);
    assert(::symlink(backup.c_str(),root.c_str())==0);
    kernix::g2c::MitGuestSnapshots symlinked;
    assert(!kernix::g2c::PinAndCaptureMITGuest(argv[1],symlinked,reason));
    assert(resolver(kernix::g2c::kMITInterpreter,bytes));
    assert(bytes.size()==kernix::g2c::kMITBytes[2]);
    std::puts("KERNIX_G2C_MIT_ONLY_THREE_SHA256_PINNED_SNAPSHOTS_HOST_PTLOAD_AUXV_AFTER_TAMPER_PASS_NO_FEX");
    return 0;
}
