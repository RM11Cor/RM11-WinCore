// KERNIX G2-E: real Linux ELF + ld-linux + glibc from source-attested G2-E CI.
// Negative tests target tamper, no-libc and path/symlink redirects.
// On Linux this test does NOT execute guest code or FEX.
// SPDX-License-Identifier: MIT
#include "kernix_g2e_pinned_glibc_preflight.h"
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

static void Dir(const std::string& dir) {
    assert(mkdir(dir.c_str(),0700)==0);
}
static void Copy(const char* original,const std::string& dest) {
    int in=open(original,O_RDONLY|O_CLOEXEC);
    assert(in>=0);
    int out=open(dest.c_str(),O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);
    assert(out>=0);
    char buffer[16384];
    ssize_t n;
    while((n=read(in,buffer,sizeof buffer))>0){
        for(ssize_t at=0;at<n;){
            ssize_t done=write(out,buffer+at,n-at);
            assert(done>0);
            at+=done;
        }
    }
    assert(n==0);
    assert(fsync(out)==0);
    assert(fchmod(out,0400)==0);
    assert(close(in)==0);
    assert(close(out)==0);
}
static bool Valid(int root) {
    kernix::g2e::GuestPreflight proof;
    std::string error;
    const bool passed=kernix::g2e::Validate(root,proof,error);
    if(passed) {
        assert(error=="none");
        assert(proof.exactSha256Matched &&
               proof.readOnlyAnonymousSnapshots &&
               proof.exactInterpreterAndGlibcClosure);
        assert(!proof.guestCodeExecuted && !proof.dynamicLinkerExecuted &&
               !proof.fexAttached && !proof.wineExecuted);
    }
    return passed;
}
int main(int argc,char** argv) {
    if(argc!=4)return 2;
    char path[]="/tmp/kernix-g2e-android-private-XXXXXX";
    char* base=mkdtemp(path);
    assert(base);
    const std::string root(base);
    Dir(root+"/bin"); Dir(root+"/lib"); Dir(root+"/lib64");
    Dir(root+"/lib/x86_64-linux-gnu");
    const std::string main=root+"/bin/kernix-g2e-dynamic-guest";
    const std::string ld=root+"/lib64/ld-linux-x86-64.so.2";
    const std::string libc=root+"/lib/x86_64-linux-gnu/libc.so.6";
    Copy(argv[1],main);Copy(argv[2],ld);Copy(argv[3],libc);
    int fd=open(root.c_str(),O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    assert(fd>=0);
    assert(Valid(fd)); // genuine pinned bits, accurate 3-node dependency graph

    // Original anonymous copy cannot change if its disk source changes.
    kernix::g2e::GuestPreflight previous;
    std::string why;
    assert(kernix::g2e::Validate(fd,previous,why));
    assert(chmod(main.c_str(),0600)==0);
    int change=open(main.c_str(),O_RDWR|O_NOFOLLOW);
    assert(change>=0);
    const unsigned char wrong=0;
    assert(pwrite(change,&wrong,1,18)==1); // ELF e_machine no longer x86-64
    close(change);
    assert(chmod(main.c_str(),0400)==0);
    assert(!Valid(fd)); // bytes + digest reject replacement
    kernix::g2c::Sha256 snapshot;
    snapshot.Update(previous.snapshots[0].bytes(),previous.snapshots[0].size());
    assert(snapshot.FinishHex()==kernix::g2e::kGuest[0].sha256);

    // Restore and reject guest libc omission without Android host fallback.
    assert(unlink(main.c_str())==0);
    Copy(argv[1],main);
    assert(unlink(libc.c_str())==0);
    assert(!Valid(fd));
    // Symlinking any needed file to a host resource is never permitted.
    assert(symlink("/etc/hosts",libc.c_str())==0);
    assert(!Valid(fd));
    assert(unlink(libc.c_str())==0);
    Copy(argv[3],libc);
    assert(Valid(fd));

    // Intermediate symlink redirect likewise fails, even if target is in root.
    assert(rename((root+"/lib64").c_str(),(root+"/loader-private").c_str())==0);
    assert(symlink("loader-private",(root+"/lib64").c_str())==0);
    assert(!Valid(fd));
    assert(unlink((root+"/lib64").c_str())==0);
    assert(rename((root+"/loader-private").c_str(),(root+"/lib64").c_str())==0);
    assert(Valid(fd));

    // Fail-closed fixed path policy.
    assert(kernix::g2e::OpenExactNoLink(fd,"/../../etc/passwd")<0);
    assert(kernix::g2e::OpenExactNoLink(fd,"/bin/other")<0);
    assert(close(fd)==0);
    assert(unlink(main.c_str())==0);
    assert(unlink(ld.c_str())==0);
    assert(unlink(libc.c_str())==0);
    assert(rmdir((root+"/bin").c_str())==0);
    assert(rmdir((root+"/lib64").c_str())==0);
    assert(rmdir((root+"/lib/x86_64-linux-gnu").c_str())==0);
    assert(rmdir((root+"/lib").c_str())==0);
    assert(rmdir(root.c_str())==0);
    std::puts("KERNIX_G2E_ANDROID_PINNED_GLIBC_THREE_ELF_READONLY_SNAPSHOT_CLOSURE_AND_NEGATIVES_PASS_NO_FEX");
    return 0;
}
