// Linux-host test of the EXACT Android G2-E/C source-level private root policy.
// No guest ELF executed, no FEX, no Android process, no root privileges.
// SPDX-License-Identifier: MIT
#include "kernix_g2e_private_root_fd.h"
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

static void Mk(const std::string& path,mode_t mode=0700){
    assert(mkdir(path.c_str(),mode)==0);
    assert(chmod(path.c_str(),mode)==0);
}
static void Expect(const std::string& path,bool accept,
                   kernix::g2e::PrivateRootReject expected){
    kernix::g2e::PrivateRootReject why{};
    const int fd=kernix::g2e::OpenPrivateRoot(path.c_str(),why);
    if(accept){
        assert(fd>=0);
        assert(why==kernix::g2e::PrivateRootReject::None);
        close(fd);
    }else{
        assert(fd<0);
        assert(why==expected);
    }
}
int main(){
    using R=kernix::g2e::PrivateRootReject;
    char templ[]="/tmp/kernix-g2e-root-test-XXXXXX";
    char* dir=mkdtemp(templ);assert(dir);
    const std::string base(dir),app=base+"/files",
       kernix=app+"/kernix",runtime=kernix+"/runtime-v1",
       guest=runtime+"/guest-rootfs",glibc=guest+"/g2e-glibc-v1";
    Mk(app,0770); // Android platform may allow same-group updates
    Mk(kernix);Mk(runtime);Mk(guest);Mk(glibc);
    Expect(app,true,R::None); // no relaxation for KERNIX directories
    assert(chmod(guest.c_str(),0770)==0);
    Expect(app,false,R::GuestRootOpenOrMode);
    assert(chmod(guest.c_str(),0700)==0);
    Expect(app,true,R::None);
    assert(chmod(kernix.c_str(),0770)==0);
    Expect(app,false,R::KernixOpenOrMode);
    assert(chmod(kernix.c_str(),0700)==0);
    assert(chmod(app.c_str(),0777)==0);
    Expect(app,false,R::AppOwnerOrUnsafe);
    assert(chmod(app.c_str(),0770)==0);
    assert(rename(glibc.c_str(),(guest+"/real-glibc").c_str())==0);
    assert(symlink("real-glibc",glibc.c_str())==0);
    Expect(app,false,R::GlibcRootOpenOrMode);
    assert(unlink(glibc.c_str())==0);
    assert(rename((guest+"/real-glibc").c_str(),glibc.c_str())==0);
    Expect(app,true,R::None);
    Expect("relative/path",false,R::AppPath);
    assert(rmdir(glibc.c_str())==0);
    assert(rmdir(guest.c_str())==0);
    assert(rmdir(runtime.c_str())==0);
    assert(rmdir(kernix.c_str())==0);
    assert(rmdir(app.c_str())==0);
    assert(rmdir(base.c_str())==0);
    std::puts("KERNIX_G2E_V027_APP_ROOT_ANDROID_GROUP_MODE_SUPPORTED_ONLY_OWN_ROOTFS_0700_AND_SYMLINK_NEGATIVES_PASS");
    return 0;
}
