// Real MIT-only x86 GNU JUMP_SLOT import host proof.
// Exact 3-ELF SHA256 anon snapshots, guarded windows, ONE GOT relocation.
// Deliberately does NOT execute FEX, x86, a guest interpreter or Wine.
// SPDX-License-Identifier: MIT
#include "kernix_g2d_mit_import_linker.h"
#include <cassert>
#include <array>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <sys/stat.h>
#include <vector>

namespace fs=std::filesystem;
int main(int argc,char** argv) {
    if(argc!=2 || !argv[1] || argv[1][0]!='/')return 2;
    const fs::path privateRoot=argv[1];
    const fs::path fixed=privateRoot/"kernix/runtime-v1/guest-rootfs/g2d-import-v1";
    kernix::g2d::PinnedImportELFs source;
    std::string why;
    assert(kernix::g2d::PinFixedImportELFs(argv[1],source,why));
    kernix::g2d::FixedImportPlan link{};
    assert(kernix::g2d::AuditFixedImport(source,link,why));
    assert(link.exactOneJumpSlot && link.mainGotVaddr==0xc000 &&
           link.exportedFunctionVaddr==0x4000);
    auto resolver=kernix::g2d::Resolver(source);
    kernix::g2b::GuestDependencyClosure deps;
    assert(kernix::g2b::AuditGuestELFDependencyClosureFromResolver(
        resolver,kernix::g2d::kMain,deps,why));
    assert(deps.guestInterpreter==kernix::g2d::kInterp &&
           deps.nodes.size()==3 && deps.resolvedEdges==1 &&
           deps.allDirectAndTransitiveFilesPresent &&
           !deps.guestCodeExecuted && !deps.relocationsApplied);
    std::array<uint8_t,16> random{};
    for(size_t i=0;i<16;i++)random[i]=static_cast<uint8_t>(i+1);
    kernix::g2b::X86HostReservedGuestLaunch host;
    assert(kernix::g2b::ReserveAndValidateX86HostGuestWindowsFromResolver(
        resolver,kernix::g2d::kMain,4096,65536,random,
        {kernix::g2d::kMain},{"LANG=C"},host,why));
    kernix::g2b::GuestReadonlyImage main,interpreter,provider;
    assert(kernix::g2b::StageReadOnlyGuestELFImageFromBytes(
        std::span<const unsigned char>(source.files[0].bytes(),
                                        source.files[0].size()),main,why,true));
    assert(kernix::g2b::StageReadOnlyGuestELFImageFromBytes(
        std::span<const unsigned char>(source.files[2].bytes(),
                                        source.files[2].size()),interpreter,why,false));
    assert(kernix::g2b::StageReadOnlyGuestELFImageFromBytes(
        std::span<const unsigned char>(source.files[1].bytes(),
                                        source.files[1].size()),provider,why,false));
    assert(kernix::g2b::StageX86ReadonlyHostBytesFromImages(
        host,main,interpreter,why));
    kernix::g2b::X86HostNoAccessReservation providerWindow;
    assert(kernix::g2b::ReserveX86NoAccessHostWindow(
        provider.hostViewBytes,4096,providerWindow,why));
    void* mapped=reinterpret_cast<void*>(
         static_cast<uintptr_t>(providerWindow.guestStart));
    assert(mprotect(mapped,provider.hostViewBytes,PROT_READ|PROT_WRITE)==0);
    std::memcpy(mapped,provider.hostView,provider.hostViewBytes);
    assert(mprotect(mapped,provider.hostViewBytes,PROT_READ)==0);
    assert(std::memcmp(mapped,provider.hostView,provider.hostViewBytes)==0);
    assert(host.plan.mainLoadBias<=UINT64_MAX-link.mainGotVaddr);
    const uint64_t providerBias=providerWindow.guestStart-
                                provider.guestPageAlignedBase;
    assert(kernix::g2d::WriteOneVerifiedGuestJumpSlot(
        link,host.plan.mainLoadBias,providerBias,
        host.main,providerWindow,why));
    const uint64_t addr=host.plan.mainLoadBias+link.mainGotVaddr;
    uint64_t resolved=0;
    std::memcpy(&resolved,reinterpret_cast<void*>(
        static_cast<uintptr_t>(addr)),8);
    assert(resolved==providerBias+link.exportedFunctionVaddr);

    // An attacker mutating the source file after all three anonymous
    // snapshots are frozen cannot alter the import closure or GOT plan.
    fs::path original=fixed/"bin/kernix-g2d-import-app";
    assert(chmod(original.c_str(),0600)==0);
    {
       std::fstream file(original,std::ios::in|std::ios::out|std::ios::binary);
       assert(file.good());
       file.seekp(220);
       const char poison=static_cast<char>(0xf7);
       file.write(&poison,1);
       assert(file.good());
    }
    kernix::g2d::PinnedImportELFs rejected;
    assert(!kernix::g2d::PinFixedImportELFs(argv[1],rejected,why));
    kernix::g2d::FixedImportPlan unchanged;
    assert(kernix::g2d::AuditFixedImport(source,unchanged,why));
    assert(unchanged.mainGotVaddr==link.mainGotVaddr &&
           unchanged.exportedFunctionVaddr==link.exportedFunctionVaddr);
    const fs::path backup=fixed.parent_path()/"g2d-import-backup";
    assert(::rename(fixed.c_str(),backup.c_str())==0);
    assert(::symlink(backup.c_str(),fixed.c_str())==0);
    assert(!kernix::g2d::PinFixedImportELFs(argv[1],rejected,why));
    assert(kernix::g2d::AuditFixedImport(source,unchanged,why));
    assert(host.hostStackBytesStagedReadonly &&
           host.hostImageBytesStagedReadonly &&
           !host.guestCodeExecuted &&
           !host.plan.dynamicLinkerExecuted);
    std::puts("KERNIX_G2D_SHA256_PINNED_ONE_REAL_JUMP_SLOT_GOT_DSO_HOST_APPLIED_RO_NO_FEX_PASS");
    return 0;
}
