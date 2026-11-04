// Host-side fixed guest FD identity negative checks; NO guest execution.
// Usage: TEST appFilesDir with staged read-only x86 bundle already inside it.
// SPDX-License-Identifier: MIT
#include "kernix_g2c_native_fixed_guest_fd_guard.h"
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

using kernix::g2c::FixedGuestFileSet;
using kernix::g2c::PinAndVerifyFixedGuest;
using kernix::g2c::Sha256;

static bool Attest(const std::string& app) {
    FixedGuestFileSet pinned;
    std::string reason;
    bool ok = PinAndVerifyFixedGuest(app.c_str(),pinned,reason);
    if (ok && (!pinned.descriptorsPinned || !pinned.sha256Verified ||
               pinned.guestCodeExecuted || pinned.executableGuestPagesMapped ||
               pinned.wineTested)) {
        std::fprintf(stderr,"NATIVE_G2C_FD_INVALID_CLAIM\n");
        std::abort();
    }
    return ok;
}

static void DigestTest(const char* data, size_t len, const char* expected) {
    Sha256 h;
    h.Update(reinterpret_cast<const uint8_t*>(data),len);
    assert(h.FinishHex()==expected);
}

int main(int argc,char** argv) {
    if (argc != 2 || !argv[1] || argv[1][0]!='/') return 2;
    DigestTest("",0,
       "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    DigestTest("abc",3,
       "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    Sha256 million;
    const std::string chunk(1000,'a');
    for(int i=0;i<1000;++i)
        million.Update(reinterpret_cast<const uint8_t*>(chunk.data()),chunk.size());
    assert(million.FinishHex()==
       "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");

    const std::string app=argv[1];
    if (!Attest(app)) {
        std::fprintf(stderr,"NATIVE_G2C_SHA256_PINNING_EXPECTED_PASS_FAILED\n");
        return 3;
    }
    assert(!Attest(app+"/../other-invalid-app-dir"));
    const std::string prefix=app+"/kernix/runtime-v1/guest-rootfs/g2c-fixed-v1/";
    const std::string guest=prefix+"bin/kernix-dynamic-app";
    const std::string alias=prefix+"lib64/ld-linux-x86-64.so.2";
    struct stat original{};
    assert(stat(guest.c_str(),&original)==0);
    // Only disposable fixture is edited; original upstream artifact untouched.
    assert(chmod(guest.c_str(),0644)==0);
    assert(!Attest(app)); // reject writable file even before digest
    int fd=open(guest.c_str(),O_RDWR|O_CLOEXEC);
    assert(fd>=0);
    unsigned char originalByte=0;
    assert(pread(fd,&originalByte,1,100)==1);
    const unsigned char damaged=static_cast<unsigned char>(originalByte ^ 1U);
    assert(pwrite(fd,&damaged,1,100)==1);
    close(fd);
    assert(chmod(guest.c_str(),0444)==0);
    assert(!Attest(app)); // digest rejects deliberate corruption
    assert(chmod(guest.c_str(),0644)==0);
    fd=open(guest.c_str(),O_RDWR|O_CLOEXEC);
    assert(fd>=0 && pwrite(fd,&originalByte,1,100)==1);
    close(fd);
    assert(chmod(guest.c_str(),original.st_mode & 0777)==0);
    assert(Attest(app));

    const std::string backup=alias+".temporary";
    assert(rename(alias.c_str(),backup.c_str())==0);
    assert(!Attest(app)); // absent fixed interpreter
    assert(symlink(backup.c_str(),alias.c_str())==0);
    assert(!Attest(app)); // symlink cannot bypass O_NOFOLLOW
    assert(unlink(alias.c_str())==0);
    assert(rename(backup.c_str(),alias.c_str())==0);
    assert(Attest(app));
    std::puts("KERNIX_G2C_NATIVE_FD_PIN_SHA256_NOSYMLINK_TAMPER_GATE_PASS_NOT_DEVICE_EXEC");
    return 0;
}
