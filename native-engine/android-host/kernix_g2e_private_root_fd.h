#pragma once
// KERNIX G2-E/C: secure, fixed-path, app-UID-owned rootfd traversal.
// Android's framework-managed getFilesDir may legitimately be group writable;
// KERNIX-owned directories are NEVER allowed group/other writable.
// No traversal, arbitrary path selection, guest execution, or mutable rootfs.
// SPDX-License-Identifier: MIT
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

namespace kernix::g2e {
enum class PrivateRootReject {
    None,
    AppPath,
    AppOpen,
    AppOwnerOrUnsafe,
    KernixOpenOrMode,
    RuntimeOpenOrMode,
    GuestRootOpenOrMode,
    GlibcRootOpenOrMode,
};
inline const char* PrivateRootReason(PrivateRootReject r) noexcept {
    switch(r){
        case PrivateRootReject::None: return "NONE";
        case PrivateRootReject::AppPath: return "APP_PATH";
        case PrivateRootReject::AppOpen: return "APP_OPEN";
        case PrivateRootReject::AppOwnerOrUnsafe: return "APP_OWNER_OR_UNSAFE";
        case PrivateRootReject::KernixOpenOrMode: return "KERNIX_DIR";
        case PrivateRootReject::RuntimeOpenOrMode: return "RUNTIME_DIR";
        case PrivateRootReject::GuestRootOpenOrMode: return "GUEST_ROOT_DIR";
        case PrivateRootReject::GlibcRootOpenOrMode: return "GLIBC_ROOT_DIR";
    }
    return "UNKNOWN";
}
inline int OpenPrivateRoot(const char* appFiles, PrivateRootReject& reason) noexcept {
    reason=PrivateRootReject::AppPath;
    if(!appFiles || appFiles[0]!='/' || std::strlen(appFiles)>4096)return -1;
    int root=open(appFiles,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(root<0){reason=PrivateRootReject::AppOpen;return -1;}
    struct stat st{};
    // Android owns getFilesDir: allow group-write only at this boundary,
    // but reject other-write and wrong UID. Every app-created child must
    // be owner-only, including execute/traversal bits.
    if(fstat(root,&st)!=0 || !S_ISDIR(st.st_mode) ||
       st.st_uid!=getuid() || (st.st_mode&S_IWOTH)){
        reason=PrivateRootReject::AppOwnerOrUnsafe;
        close(root);
        return -1;
    }
    const char* const parts[]={"kernix","runtime-v1","guest-rootfs","g2e-glibc-v1"};
    const PrivateRootReject errors[]={
        PrivateRootReject::KernixOpenOrMode,
        PrivateRootReject::RuntimeOpenOrMode,
        PrivateRootReject::GuestRootOpenOrMode,
        PrivateRootReject::GlibcRootOpenOrMode,
    };
    for(size_t i=0;i<4;++i){
        int next=openat(root,parts[i],O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
        close(root);
        root=next;
        if(root<0){reason=errors[i];return -1;}
        if(fstat(root,&st)!=0 || !S_ISDIR(st.st_mode) ||
           st.st_uid!=getuid() || (st.st_mode&(S_IWGRP|S_IWOTH))){
            reason=errors[i];
            close(root);
            return -1;
        }
    }
    reason=PrivateRootReject::None;
    return root;
}
} // namespace kernix::g2e
