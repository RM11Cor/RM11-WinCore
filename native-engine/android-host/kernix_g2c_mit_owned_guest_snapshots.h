#pragma once
// KERNIX G2-C MIT-only guest: EXACT three x86 ELF byte snapshots from a
// pinned app-private, no-symlink root. NO distro glibc, no file path reopen
// by a guest resolver, no guest FEX execution in this header.
// SPDX-License-Identifier: MIT
#include "kernix_g2c_native_readonly_guest_snapshots.h"
#include "kernix_g2b_readonly_host_install.h"
#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

namespace kernix::g2c {

struct MitGuestSnapshots {
    std::array<ReadonlyGuestSnapshot,3> files;
    bool allSha256Verified=false;
    bool guestExecuted=false;
    bool loaderExecuted=false;
    bool wineExecuted=false;
    void reset() noexcept {
        for(auto& file:files)file.reset();
        allSha256Verified=false;
        guestExecuted=false;
        loaderExecuted=false;
        wineExecuted=false;
    }
};

inline constexpr const char* kMITMain="/bin/kernix-mit-dynamic-app";
inline constexpr const char* kMITDep=
    "/lib/x86_64-linux-gnu/libkernix-g2c-mit-placeholder.so.1";
inline constexpr const char* kMITInterpreter=
    "/lib64/ld-kernix-g2c-mit-placeholder.so.1";

inline constexpr std::array<uint64_t,3> kMITBytes{{13320,13184,13160}};
inline constexpr std::array<const char*,3> kMITSha256{{
    "ce7ed73417d68459fab6ea08d0f0c807c1ff04615727a724fadf3863f12b2e61",
    "aa8cf455237ee28a14c145cbe26cf5d690b8838cf8f8d01e4d1cf609ff268aee",
    "16c1f89492ad15637017e8e652443de6554df50ea7e2b172abe27232c514c058"
}};

inline bool PinAndCaptureMITGuest(const char* appPrivateFiles,
                                 MitGuestSnapshots& output,
                                 std::string& reason) {
    output.reset();
    if (!appPrivateFiles || appPrivateFiles[0]!='/' ||
        std::strlen(appPrivateFiles)>1024) {
        reason="MIT_PRIVATE_FILES_DIR_INVALID";return false;
    }
    OwnedFd app(open(appPrivateFiles,O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW));
    struct stat appStat{};
    if(app.get()<0 || fstat(app.get(),&appStat)!=0 ||
       appStat.st_uid!=getuid()) {
        reason="MIT_APP_PRIVATE_ROOT_UNOWNED_OR_MISSING";return false;
    }
    OwnedFd kernix(OpenDirectory(app.get(),"kernix"));
    OwnedFd runtime(OpenDirectory(kernix.get(),"runtime-v1"));
    OwnedFd guest(OpenDirectory(runtime.get(),"guest-rootfs"));
    OwnedFd root(OpenDirectory(guest.get(),"g2c-mit-v1"));
    OwnedFd bin(OpenDirectory(root.get(),"bin"));
    OwnedFd lib(OpenDirectory(root.get(),"lib"));
    OwnedFd libx(OpenDirectory(lib.get(),"x86_64-linux-gnu"));
    OwnedFd lib64(OpenDirectory(root.get(),"lib64"));
    if(root.get()<0 || bin.get()<0 || libx.get()<0 || lib64.get()<0){
        reason="MIT_FIXED_GUEST_ROOT_MISSING_OR_SYMLINK";return false;
    }
    const std::array<int,3> dirs{{bin.get(),libx.get(),lib64.get()}};
    const std::array<const char*,3> names{{
        "kernix-mit-dynamic-app","libkernix-g2c-mit-placeholder.so.1",
        "ld-kernix-g2c-mit-placeholder.so.1"
    }};
    for(size_t i=0;i<dirs.size();++i) {
        OwnedFd fd(openat(dirs[i],names[i],
                          O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK));
        if(!VerifyFile(fd.get(),kMITBytes[i],kMITSha256[i]) ||
           !output.files[i].Capture(fd.get(),
                   static_cast<size_t>(kMITBytes[i]),kMITSha256[i],reason)) {
            output.reset();
            reason="MIT_FIXED_GUEST_SHA256_SIZE_MODE_OR_SNAPSHOT_REJECTED";
            return false;
        }
    }
    output.allSha256Verified=true;
    reason="none";
    return true;
}

// Resolver can ONLY serve byte-for-byte checked frozen content. It never
// follows files/symlinks or consults the host's /usr/lib after capture.
inline bool ResolveMITGuestBytes(
    const MitGuestSnapshots& source,std::string_view path,
    std::vector<unsigned char>& result) {
    result.clear();
    if(!source.allSha256Verified || source.guestExecuted ||
       source.loaderExecuted || source.wineExecuted)return false;
    constexpr std::array<std::string_view,3> names{{
        kMITMain,kMITDep,kMITInterpreter
    }};
    for(size_t i=0;i<names.size();++i){
        if(path!=names[i])continue;
        const auto& file=source.files[i];
        if(!file.readOnlySnapshot() || file.size()!=kMITBytes[i])return false;
        result.assign(file.bytes(),file.bytes()+file.size());
        return true;
    }
    return false;
}

inline kernix::g2b::GuestELFBytesResolver MITGuestSnapshotResolver(
    const MitGuestSnapshots& source) {
    return [&source](std::string_view name,std::vector<unsigned char>& bytes){
        return ResolveMITGuestBytes(source,name,bytes);
    };
}

inline bool StageMITMainAndInterpreter(
    const MitGuestSnapshots& source,kernix::g2b::GuestReadonlyImage& main,
    kernix::g2b::GuestReadonlyImage& interpreter,std::string& reason) {
    main.release();interpreter.release();
    if(!source.allSha256Verified || !source.files[0].readOnlySnapshot() ||
       !source.files[2].readOnlySnapshot() ||
       !kernix::g2b::StageReadOnlyGuestELFImageFromBytes(
           std::span<const unsigned char>(
              source.files[0].bytes(),source.files[0].size()),main,reason,true) ||
       !kernix::g2b::StageReadOnlyGuestELFImageFromBytes(
           std::span<const unsigned char>(
              source.files[2].bytes(),source.files[2].size()),interpreter,
              reason,false) ||
       !main.hostViewReadOnly || !interpreter.hostViewReadOnly ||
       main.hostViewExecutable || interpreter.hostViewExecutable ||
       main.guestCodeExecuted || interpreter.guestCodeExecuted) {
        main.release();interpreter.release();
        reason="MIT_DYNAMIC_ELF_SNAPSHOT_PTLOAD_REJECTED";
        return false;
    }
    reason="none";
    return true;
}
} // namespace kernix::g2c
