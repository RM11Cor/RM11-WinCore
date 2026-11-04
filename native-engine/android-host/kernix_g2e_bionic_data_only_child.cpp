// KERNIX G2-E/B: bounded signed Android/Bionic data attestation child.
// Only copies SHA-pinned original x86 Linux ELF+ld-linux+libc into anonymous
// read-only host buffers and audits the exact two-edge DT_NEEDED graph.
// It does NOT enter FEX, execute Linux guest code, or load glibc with dlopen.
// SPDX-License-Identifier: MIT
#include "kernix_g2e_pinned_glibc_preflight.h"
#include "kernix_g2e_private_root_fd.h"
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#if !defined(__ANDROID__) || !defined(__aarch64__)
#error G2-E/B signed data-only child must use genuine Android Bionic ARM64
#endif

namespace {
constexpr const char* kFlag="--kernix-g2e-pinned-glibc-data-only-v1";
}

int main(int argc,char** argv) {
    // Java/native positional contract: runner, app-files-dir, exact flag.
    if(argc!=3 || !argv[1] || !argv[2] ||
       std::strcmp(argv[2],kFlag)!=0){
        std::fputs("KERNIX_G2E_BAD_FIXED_CLI\n",stderr);
        return 126;
    }
    kernix::g2e::PrivateRootReject rootError{};
    const int dir=kernix::g2e::OpenPrivateRoot(argv[1],rootError);
    if(dir<0){
        // Fixed, non-sensitive reason tags only. No absolute path or errno.
        std::fprintf(stderr,"KERNIX_G2E_PRIVATE_ROOT_REJECTED:%s\n",
                     kernix::g2e::PrivateRootReason(rootError));
        return 20;
    }
    kernix::g2e::GuestPreflight proof;
    std::string reason;
    const bool ok=kernix::g2e::Validate(dir,proof,reason);
    close(dir);
    if(!ok || !proof.exactSha256Matched ||
       !proof.readOnlyAnonymousSnapshots ||
       !proof.exactInterpreterAndGlibcClosure ||
       proof.guestCodeExecuted || proof.dynamicLinkerExecuted ||
       proof.fexAttached || proof.wineExecuted){
        std::fprintf(stderr,"KERNIX_G2E_GUEST_DATA_REJECTED:%s\n",
                     reason.c_str());
        return 21;
    }
    // Exact stdout/stderr required by the Android supervisor along with
    // process exit 0. Importantly: never claim x86 guest execution.
    std::fputs(
        "KERNIX_G2E_ANDROID_PINNED_GLIBC_SNAPSHOT_CLOSURE_DATA_ONLY_PASS_V1\n",
        stdout);
    std::fputs(
        "GUEST_EXECUTED=0\n"
        "DYNAMIC_LINKER_EXECUTED=0\n"
        "FEX_EXECUTED=0\n"
        "WINE_EXECUTED=0\n",
        stderr);
    std::fflush(stdout);
    std::fflush(stderr);
    return 0;
}
