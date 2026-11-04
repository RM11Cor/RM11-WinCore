#pragma once
// KERNIX G2-C: exact fixed child CLI allowlist. This header has NO FEX
// dependency so the device-runner admission policy can be audited on a
// Linux host before enabling a separately linked Android guest candidate.
// SPDX-License-Identifier: MIT
#include <cstring>
#include <cstddef>

namespace kernix::g2c {
inline constexpr const char* kFixedDeviceRunFlag =
    "--kernix-g2c-execute-fixed-snapshot-direct-entry-v1";

inline bool IsFixedDeviceCandidateInvocation(
    int argc, const char* const* argv) noexcept {
    if (argc!=3 || argv==nullptr || argv[0]==nullptr ||
        argv[1]==nullptr || argv[2]==nullptr ||
        std::strcmp(argv[1],kFixedDeviceRunFlag)!=0)
        return false;
    const char* path=argv[2];
    const size_t count=std::strlen(path);
    if (count<2 || count>1024 || path[0]!='/' ||
        path[count-1]=='/' || std::strstr(path,"//")!=nullptr)
        return false;
    // Production KERNIX package only. No /sdcard, /tmp, /system,
    // arbitrary mounted volumes or cross-package writable sources.
    constexpr const char* suffix="/org.kernix.host/files";
    constexpr size_t suffixBytes=sizeof("/org.kernix.host/files")-1;
    if (count<=suffixBytes ||
        std::strcmp(path+count-suffixBytes,suffix)!=0)
        return false;
    const bool dataAlias=std::strcmp(path,"/data/data/org.kernix.host/files")==0;
    const bool credentialStore=
        std::strncmp(path,"/data/user/",sizeof("/data/user/")-1)==0;
    const bool deviceStore=
        std::strncmp(path,"/data/user_de/",sizeof("/data/user_de/")-1)==0;
    if (!dataAlias && !credentialStore && !deviceStore)
        return false;
    if (!dataAlias) {
        const char* start=path+(credentialStore?
            sizeof("/data/user/")-1:sizeof("/data/user_de/")-1);
        const char* end=path+count-suffixBytes;
        if (start>=end || (start[0]=='0' && start+1!=end))
            return false;
        for (const char* at=start;at<end;++at)
            if (*at<'0' || *at>'9') return false;
    }
    // No relative, dot, dot-dot, or symlink-like traversal of the app
    // private root. The native pinned FD verifier then enforces the
    // absolute allowlisted guest files and SHA-256 content.
    const char* cursor=path+1;
    while (*cursor) {
        const char* next=std::strchr(cursor,'/');
        const size_t length=next?static_cast<size_t>(next-cursor):
                                 std::strlen(cursor);
        if(length==0 || (length==1 && cursor[0]=='.') ||
           (length==2 && cursor[0]=='.' && cursor[1]=='.'))
            return false;
        if(!next)break;
        cursor=next+1;
    }
    return true;
}
} // namespace kernix::g2c
