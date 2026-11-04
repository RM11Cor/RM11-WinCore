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
