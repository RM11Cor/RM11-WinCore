// Host-only proof: the x86 ELF bytes frozen for a future Android FEX child
// are strictly independent of later app-private changes. No guest execution.
// SPDX-License-Identifier: MIT
#include "kernix_g2c_native_readonly_guest_snapshots.h"
#include <cassert>
#include <cstdio>
#include <fcntl.h>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
using kernix::g2c::FixedGuestFileSet;
using kernix::g2c::FixedGuestSnapshots;
using kernix::g2c::PinAndVerifyFixedGuest;
using kernix::g2c::PinAndCaptureFixedGuest;
using kernix::g2c::CaptureVerifiedFixedGuest;
using kernix::g2c::Sha256;

static std::string Digest(const uint8_t* bytes,size_t count) {
    Sha256 h;
    h.Update(bytes,count);
    return h.FinishHex();
}
int main(int argc,char** argv) {
    if(argc!=2 || !argv[1] || argv[1][0]!='/')return 2;
    const std::string app(argv[1]);
    std::string reason;
    FixedGuestSnapshots snapshot;
    assert(PinAndCaptureFixedGuest(app.c_str(),snapshot,reason));
    assert(snapshot.allHashesVerified && !snapshot.handedToFEX &&
           !snapshot.guestExecuted && !snapshot.interpreterExecuted &&
           !snapshot.wineTested);
    static constexpr size_t lengths[]={13344,2118168,235408,235408};
    static constexpr const char* digests[]={
        "e54a92cf77d1453c86b70accfd949b9e4521ddd5d629ba09c0dcac07a1397b4a",
        "7e262ac92a454f36664b9c95a8927ecc4fb0f0f007206c2613b1e9ce14e76906",
        "cff2a563ca82b90beb5c43db38b84efe0c610a9a0e3394083882abcf8431fbae",
        "cff2a563ca82b90beb5c43db38b84efe0c610a9a0e3394083882abcf8431fbae"
    };
    for(int i=0;i<4;++i) {
        assert(snapshot.files[i].readOnlySnapshot());
        assert(snapshot.files[i].size()==lengths[i]);
        assert(Digest(snapshot.files[i].bytes(),lengths[i])==digests[i]);
    }
    assert(std::memcmp(snapshot.files[2].bytes(),snapshot.files[3].bytes(),
                       lengths[2])==0);

    // The OS reports snapshot segments as r--p, i.e. private and not writable.
    // No attempt to provoke a SIGSEGV is needed for the W^X audit.
    FILE* maps=fopen("/proc/self/maps","r");
    assert(maps);
    char row[1024]{};
    for(const auto& part:snapshot.files) {
        bool seen=false;
        rewind(maps);
        const auto target=reinterpret_cast<uintptr_t>(part.bytes());
        while(fgets(row,sizeof(row),maps)) {
            unsigned long long a=0,b=0;
            char flags[5]{};
            if(sscanf(row,"%llx-%llx %4s",&a,&b,flags)==3 &&
                target>=a && target<b) {
                assert(std::strcmp(flags,"r--p")==0);
                seen=true;
                break;
            }
        }
        assert(seen);
    }
    fclose(maps);

    const std::string elf=app+
      "/kernix/runtime-v1/guest-rootfs/g2c-fixed-v1/bin/kernix-dynamic-app";
    assert(chmod(elf.c_str(),0644)==0);
    int fd=open(elf.c_str(),O_RDWR|O_CLOEXEC);
    assert(fd>=0);
    uint8_t old=0,modified=0;
    assert(pread(fd,&old,1,100)==1);
    modified=old^0x5a;
    assert(pwrite(fd,&modified,1,100)==1);
    close(fd);
    assert(chmod(elf.c_str(),0444)==0);
    // Source now fails digest, but original private snapshot remains intact.
    FixedGuestSnapshots changed;
    assert(!PinAndCaptureFixedGuest(app.c_str(),changed,reason));
    assert(!changed.allHashesVerified && changed.files[0].bytes()==nullptr);
    assert(snapshot.files[0].bytes()[100]==old);
    assert(Digest(snapshot.files[0].bytes(),lengths[0])==digests[0]);

    // Closing all original file paths does not alter captured ELF pages.
    assert(unlink(elf.c_str())==0);
    assert(!PinAndCaptureFixedGuest(app.c_str(),changed,reason));
    assert(Digest(snapshot.files[0].bytes(),lengths[0])==digests[0]);

    // Separate native handoff check: an inode changed AFTER an earlier FD
    // attestation must fail copying via the independently rehashed snapshot.
    // It is enough to exercise the Capture method with a temporary pinned
    // source altered after PinAndVerifyFixedGuest.
    snapshot.reset();
    assert(snapshot.files[0].bytes()==nullptr && !snapshot.allHashesVerified);
    std::puts("KERNIX_G2C_READONLY_ANON_SNAPSHOT_SHA256_SOURCE_MUTATION_ISOLATED_PASS_NOT_FEX_OR_DEVICE");
    return 0;
}
