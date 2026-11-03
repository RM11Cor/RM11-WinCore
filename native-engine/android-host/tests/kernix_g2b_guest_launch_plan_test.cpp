#include "kernix_g2b_guest_launch_plan.h"
#include <algorithm>
#include <array>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <unistd.h>

using kernix::g2b::X86GuestProcessAddresses;
using kernix::g2b::X86GuestProcessLaunchPlan;

static void CopyFile(const char* source, const std::string& to) {
    int from=open(source,O_RDONLY|O_CLOEXEC);
    assert(from>=0);
    int dest=open(to.c_str(),O_CREAT|O_EXCL|O_WRONLY|O_CLOEXEC,0600);
    assert(dest>=0);
    char buffer[32768];
    ssize_t n=0;
    while((n=read(from,buffer,sizeof(buffer)))>0) {
        ssize_t done=0;
        while(done<n) {
            const ssize_t w=write(dest,buffer+done,n-done);
            assert(w>0);done+=w;
        }
    }
    assert(n==0);
    close(from);
    close(dest);
}
static uint64_t Word(const X86GuestProcessLaunchPlan& p,uint64_t address) {
    assert(address>=p.stack.guestBottom &&
           address<p.stack.guestTop &&
           8<=p.stack.guestTop-address);
    uint64_t n=0;
    for(unsigned i=0;i<8;i++)
        n|=static_cast<uint64_t>(
            p.stack.bytes[static_cast<size_t>(address-p.stack.guestBottom+i)])
            <<(i*8);
    return n;
}
static uint64_t Aux(const X86GuestProcessLaunchPlan& p,uint64_t key,
                    size_t argCount,size_t envCount) {
    uint64_t pos=p.stack.guestRSP+8+
        (argCount+1)*8+(envCount+1)*8;
    for(size_t i=0;i<p.stack.auxEntryCount;i++,pos+=16)
        if(Word(p,pos)==key) return Word(p,pos+8);
    assert(false && "Expected AUXV key missing");
    return 0;
}
static void Reject(int root,const X86GuestProcessAddresses& in) {
    X86GuestProcessLaunchPlan plan;
    std::string reason;
    assert(!kernix::g2b::PrepareX86DynamicGuestLaunchPlan(
        root,"/bin/kernix-dynamic-app",in,plan,reason));
    assert(reason!="none" && !reason.empty());
    assert(!plan.guestVirtualAddressesValidated);
    assert(!plan.stackAndAuxvConsistent);
    assert(plan.stack.bytes.empty());
    assert(!plan.guestAddressSpaceReserved && !plan.guestMemoryMapped &&
           !plan.fexEntryPointAssigned && !plan.guestCodeExecuted &&
           !plan.androidWineTested);
}
int main(int argc,char** argv) {
    if(argc!=6) return 2;
    char temp[]="/tmp/kernix-g2b-real-launch-plan-XXXXXX";
    char* dir=mkdtemp(temp);
    assert(dir);
    const std::string root(dir);
    for(const char* d:{"/bin","/lib","/lib64","/lib/x86_64-linux-gnu"})
        assert(mkdir((root+d).c_str(),0700)==0);
    const std::string app=root+"/bin/kernix-dynamic-app";
    const std::string interp=root+"/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2";
    const std::string libc=root+"/lib/x86_64-linux-gnu/libc.so.6";
    const std::string mid=root+"/lib/x86_64-linux-gnu/libkernix_mid.so";
    const std::string leaf=root+"/lib/x86_64-linux-gnu/libkernix_leaf.so";
    const std::string interpLink=root+"/lib64/ld-linux-x86-64.so.2";
    CopyFile(argv[1],app);
    CopyFile(argv[2],interp);
    CopyFile(argv[3],libc);
    CopyFile(argv[4],mid);
    CopyFile(argv[5],leaf);
    assert(symlink("/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
                   interpLink.c_str())==0);
    int fd=open(root.c_str(),O_PATH|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
    assert(fd>=0);
    X86GuestProcessAddresses input{};
    input.mainImageStart=0x0000555500000000ULL;
    input.interpreterImageStart=0x0000711100000000ULL;
    input.stackBottom=0x00007fff10000000ULL;
    input.stackBytes=65536;
    input.guestPageBytes=4096;
    input.uid=1234;input.euid=1234;
    input.gid=5678;input.egid=5678;
    for(size_t i=0;i<input.randomBytes.size();i++)
        input.randomBytes[i]=static_cast<uint8_t>(i+1);
    input.argv={"/bin/kernix-dynamic-app","--bounded"};
    input.environment={"LANG=C","KERNIX_PROOF=1"};
    X86GuestProcessLaunchPlan plan;
    std::string reason;
    const bool pass=kernix::g2b::PrepareX86DynamicGuestLaunchPlan(
        fd,"/bin/kernix-dynamic-app",input,plan,reason);
    if(!pass) fprintf(stderr,"real ELF launch plan failure: %s\n",
                      reason.c_str());
    assert(pass);
    assert(reason=="none");
    assert(plan.dependencyObjectsChecked>=5);
    assert(plan.guestInterpreter=="/lib64/ld-linux-x86-64.so.2");
    assert(plan.guestVirtualAddressesValidated &&
           plan.stackAndAuxvConsistent &&
           plan.stack.initialStackLayoutValidated);
    assert(!plan.guestAddressSpaceReserved && !plan.guestMemoryMapped &&
           !plan.fexEntryPointAssigned && !plan.dynamicLinkerExecuted &&
           !plan.guestCodeExecuted && !plan.androidWineTested);
    assert(plan.stack.guestRSP%16==0 && plan.mainPHNUM>0);
    assert(plan.mainLoadBias==input.mainImageStart);
    assert(plan.interpreterLoadBias==input.interpreterImageStart);
    assert(Aux(plan,3,input.argv.size(),input.environment.size())==
           plan.guestMainPHDR);
    assert(Aux(plan,4,input.argv.size(),input.environment.size())==
           sizeof(Elf64_Phdr));
    assert(Aux(plan,5,input.argv.size(),input.environment.size())==
           plan.mainPHNUM);
    assert(Aux(plan,6,input.argv.size(),input.environment.size())==4096);
    assert(Aux(plan,7,input.argv.size(),input.environment.size())==
           plan.interpreterLoadBias);
    assert(Aux(plan,9,input.argv.size(),input.environment.size())==
           plan.guestMainEntry);
    assert(Aux(plan,25,input.argv.size(),input.environment.size())==
           plan.stack.guestRandomPointer);
    assert(plan.guestInterpreterEntry>=input.interpreterImageStart);
    assert(plan.guestMainEntry>=input.mainImageStart);
    assert(Word(plan,plan.stack.guestRSP)==2);
    for(size_t i=0;i<plan.regions.size();i++) {
        assert(plan.regions[i].first>=0x10000);
        assert(plan.regions[i].pastLast<kernix::g2b::kLinuxGuestUserLimit);
        for(size_t j=i+1;j<plan.regions.size();j++)
            assert(kernix::g2b::X86GuestNonOverlap(
                plan.regions[i],plan.regions[j]));
    }

    X86GuestProcessAddresses bad=input;
    bad.interpreterImageStart=bad.mainImageStart;
    Reject(fd,bad);
    bad=input;bad.stackBottom=bad.mainImageStart;Reject(fd,bad);
    bad=input;bad.mainImageStart=0;Reject(fd,bad);
    bad=input;bad.interpreterImageStart=0x00007ffffffff000ULL;Reject(fd,bad);
    bad=input;bad.guestPageBytes=123;Reject(fd,bad);
    bad=input;bad.stackBytes=0;Reject(fd,bad);
    bad=input;bad.argv.clear();Reject(fd,bad);
    bad=input;bad.randomBytes.fill(0);Reject(fd,bad);
    // Missing transitive leaf must fail before any ABI plan is accepted.
    assert(rename(leaf.c_str(),(leaf+".missing").c_str())==0);
    Reject(fd,input);
    assert(rename((leaf+".missing").c_str(),leaf.c_str())==0);
    assert(fcntl(fd,F_GETFD)>=0);close(fd);
    for(const std::string& f:{app,interp,libc,mid,leaf,interpLink})
        assert(unlink(f.c_str())==0);
    for(const char* d:{"/bin","/lib64","/lib/x86_64-linux-gnu","/lib"})
        assert(rmdir((root+d).c_str())==0);
    assert(rmdir(root.c_str())==0);
    puts("KERNIX_G2B_REAL_ELF_INTERP_LOADBIAS_STACK_AUXV_COHERENT_PASS_NOT_ANDROID_FEX_EXECUTION");
}
