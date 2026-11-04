#pragma once
// KERNIX G2-E/A: exact Linux x86-64 guest + glibc + ld-linux data handoff.
// Linux ARM64 already ran this guest under the *full* FEX Linux runtime.
// On Android this header is read-only preflight, NEVER a guest ELF launcher.
// No libc is loaded into Bionic, no W+X pages, no Wine, no guest execution.
// SPDX-License-Identifier: MIT
#include "kernix_g2c_native_readonly_guest_snapshots.h"
#include "kernix_guest_elf64_dependency_closure.h"
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

namespace kernix::g2e {
struct GuestSpec {
    const char* path;
    uint64_t bytes;
    const char* sha256;
};
// Original cross-sysroot bytes from passed Linux ARM64 CI 41842294261.
// On a distro update this must FAIL CLOSED; do not silently repin.
inline constexpr std::array<GuestSpec, 3> kGuest{{
    {"/bin/kernix-g2e-dynamic-guest",15976,
     "9fb072db2732c7c6a1b2a53bd946d54904feaac5980e0d79b39f7ce300784412"},
    {"/lib64/ld-linux-x86-64.so.2",235408,
     "cff2a563ca82b90beb5c43db38b84efe0c610a9a0e3394083882abcf8431fbae"},
    {"/lib/x86_64-linux-gnu/libc.so.6",2118168,
     "7e262ac92a454f36664b9c95a8927ecc4fb0f0f007206c2613b1e9ce14e76906"}
}};

struct GuestPreflight {
    std::array<kernix::g2c::ReadonlyGuestSnapshot,3> snapshots;
    bool exactSha256Matched=false;
    bool readOnlyAnonymousSnapshots=false;
    bool exactInterpreterAndGlibcClosure=false;
    bool guestCodeExecuted=false;
    bool dynamicLinkerExecuted=false;
    bool fexAttached=false;
    bool wineExecuted=false;
};

// Reject all symlinks *including intermediate components*. This is stricter
// than the general G2-B scoped-link reader, specifically for three immutable
// app-owned, source-attested guest files.
inline int OpenExactNoLink(int rootfd, std::string_view path) {
    if(rootfd<0) return -1;
    int at=fcntl(rootfd,F_DUPFD_CLOEXEC,0);
    if(at<0)return -1;
    const char* const* dirs=nullptr;
    const char* file=nullptr;
    const char* bin[]={"bin",nullptr};
    const char* lib64[]={"lib64",nullptr};
    const char* libc[]={"lib","x86_64-linux-gnu",nullptr};
    if(path==kGuest[0].path){dirs=bin;file="kernix-g2e-dynamic-guest";}
    else if(path==kGuest[1].path){dirs=lib64;file="ld-linux-x86-64.so.2";}
    else if(path==kGuest[2].path){dirs=libc;file="libc.so.6";}
    else {close(at);return -1;}
    struct stat s{};
    if(fstat(at,&s)!=0 || !S_ISDIR(s.st_mode) || s.st_uid!=getuid()){
        close(at);return -1;
    }
    for(const char* const* d=dirs;*d;++d){
        int next=openat(at,*d,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
        close(at);
        if(next<0)return -1;
        at=next;
        if(fstat(at,&s)!=0 || !S_ISDIR(s.st_mode) ||
           s.st_uid!=getuid() ||
           (s.st_mode&(S_IWGRP|S_IWOTH))) {
            close(at);return -1;
        }
    }
    int fd=openat(at,file,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
    close(at);
    return fd;
}

inline bool Validate(int privateRootFd, GuestPreflight& result,
                     std::string& reason) {
    result=GuestPreflight{};
    if(privateRootFd<0){reason="G2E_BAD_PRIVATE_ROOT";return false;}
    std::array<kernix::g2c::OwnedFd,3> owned;
    for(size_t i=0;i<kGuest.size();++i){
        int fd=OpenExactNoLink(privateRootFd,kGuest[i].path);
        if(fd<0){
            reason="G2E_EXACT_GUEST_FILE_OR_DIRECTORY_REJECTED";
            return false;
        }
        owned[i].reset(fd);
        if(!kernix::g2c::VerifyFile(fd,kGuest[i].bytes,kGuest[i].sha256)){
            reason="G2E_PINNED_GUEST_SHA256_SIZE_OWNER_OR_MODE_REJECTED";
            return false;
        }
        if(!result.snapshots[i].Capture(
             fd,static_cast<size_t>(kGuest[i].bytes),kGuest[i].sha256,reason)){
            return false;
        }
    }
    result.exactSha256Matched=true;
    result.readOnlyAnonymousSnapshots=true;
    // Disallow disk reopens and native Android /system ELF fallback.
    const auto fetch=[&result](std::string_view path,
                             std::vector<unsigned char>& bytes)->bool {
        bytes.clear();
        for(size_t i=0;i<kGuest.size();++i){
            if(path!=kGuest[i].path) continue;
            const auto& snap=result.snapshots[i];
            if(!snap.readOnlySnapshot() ||
               !snap.bytes() || snap.size()!=kGuest[i].bytes)
                return false;
            bytes.assign(snap.bytes(),snap.bytes()+snap.size());
            return true;
        }
        return false;
    };
    kernix::g2b::GuestDependencyClosure closure;
    std::string failure;
    if(!kernix::g2b::AuditGuestELFDependencyClosureFromResolver(
        fetch,kGuest[0].path,closure,failure) ||
       !closure.allDirectAndTransitiveFilesPresent ||
       closure.guestInterpreter!=kGuest[1].path ||
       closure.nodes.size()!=3 || closure.resolvedEdges!=1 ||
       closure.symbolVersionsResolved || closure.relocationsApplied ||
       closure.guestCodeExecuted || closure.androidWineTested) {
        reason="G2E_EXACT_GLIBC_LOADER_CLOSURE_REJECTED:"+failure;
        return false;
    }
    // Precise graph: main -> libc.so.6, main PT_INTERP -> ld-linux.
    if(closure.nodes[0].path!=kGuest[0].path ||
       closure.nodes[0].needed.size()!=1 ||
       closure.nodes[0].needed[0]!="libc.so.6" ||
       closure.nodes[0].resolvedDirectLibraries.size()!=1 ||
       closure.nodes[0].resolvedDirectLibraries[0]!=kGuest[2].path){
        reason="G2E_GUEST_PIE_IMPORT_GRAPH_MISMATCH";return false;
    }
    result.exactInterpreterAndGlibcClosure=true;
    reason="none";
    return true;
}
} // namespace kernix::g2e
