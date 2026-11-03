#include "kernix_g2b_readonly_host_install.h"
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <unistd.h>

using kernix::g2b::X86HostReservedGuestLaunch;
using kernix::g2b::X86HostNoAccessReservation;

static void Copy(const char* src,const std::string& dst) {
    int in=open(src,O_RDONLY|O_CLOEXEC);
    assert(in>=0);
    int out=open(dst.c_str(),O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);
    assert(out>=0);
    char buffer[16384];
    ssize_t n;
    while((n=read(in,buffer,sizeof(buffer)))>0) {
        ssize_t done=0;
        while(done<n){
            ssize_t w=write(out,buffer+done,static_cast<size_t>(n-done));
            assert(w>0);done+=w;
        }
    }
    assert(n==0);
    close(in);close(out);
}
static bool HasMappingPermissions(uint64_t guestVA, const char* expected) {
    FILE* fp=fopen("/proc/self/maps","r");
    assert(fp);
    char line[4096];
    bool noAccess=false;
    while(fgets(line,sizeof(line),fp)) {
        unsigned long long first=0,last=0;
        char perms[8]={0};
        if(sscanf(line,"%llx-%llx %7s",&first,&last,perms)!=3)
            continue;
        if(guestVA>=first && guestVA<last){
            noAccess=(strcmp(perms,expected)==0);
            break;
        }
    }
    fclose(fp);
    return noAccess;
}
static void Failure(int fd, uint64_t guestPage, uint64_t stackBytes,
                    const std::array<uint8_t,16>& random,
                    std::vector<std::string> argv,
                    std::vector<std::string> env) {
    X86HostReservedGuestLaunch out;
    std::string error;
    assert(!kernix::g2b::ReserveAndValidateX86HostGuestWindows(
        fd,"/bin/kernix-dynamic-app",guestPage,stackBytes,random,
        argv,env,out,error));
    assert(!error.empty() && error!="none");
    assert(!out.main.hostMapping && !out.interpreter.hostMapping &&
           !out.stack.hostMapping && !out.hostVAsReservedPROT_NONE);
    assert(!out.guestVAsInstalledInFEX && !out.guestCodeExecuted);
}
int main(int argc,char** argv) {
    if(argc!=6) return 2;
    char tmp[]="/tmp/kernix-g2b-host-vm-XXXXXX";
    char* rootname=mkdtemp(tmp);
    assert(rootname);
    std::string root(rootname);
    for(const char* dir:{"/bin","/lib","/lib64","/lib/x86_64-linux-gnu"})
        assert(mkdir((root+dir).c_str(),0700)==0);
    const std::string executable=root+"/bin/kernix-dynamic-app";
    const std::string loader=root+"/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2";
    const std::string libc=root+"/lib/x86_64-linux-gnu/libc.so.6";
    const std::string mid=root+"/lib/x86_64-linux-gnu/libkernix_mid.so";
    const std::string leaf=root+"/lib/x86_64-linux-gnu/libkernix_leaf.so";
    const std::string link=root+"/lib64/ld-linux-x86-64.so.2";
    Copy(argv[1],executable);
    Copy(argv[2],loader);
    Copy(argv[3],libc);
    Copy(argv[4],mid);
    Copy(argv[5],leaf);
    assert(symlink("/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",link.c_str())==0);
    int fd=open(root.c_str(),O_PATH|O_NOFOLLOW|O_DIRECTORY|O_CLOEXEC);
    assert(fd>=0);
    std::array<uint8_t,16> random{};
    for(size_t i=0;i<random.size();++i)
        random[i]=static_cast<uint8_t>(i+1);
    std::vector<std::string> args={"/bin/kernix-dynamic-app","--test"};
    std::vector<std::string> env={"LANG=C","KERNIX_G2B=1"};
    X86HostReservedGuestLaunch result;
    std::string reason;
    bool pass=kernix::g2b::ReserveAndValidateX86HostGuestWindows(
        fd,"/bin/kernix-dynamic-app",4096,65536,
        random,args,env,result,reason);
    if(!pass) fprintf(stderr,"G2-B host VA reservations failed: %s\n",reason.c_str());
    assert(pass);
    assert(reason=="none" && result.hostVAsReservedPROT_NONE);
    assert(result.main.hostMapping && result.interpreter.hostMapping &&
           result.stack.hostMapping);
    assert(result.main.guestStart%4096==0 &&
           result.interpreter.guestStart%4096==0 &&
           result.stack.guestStart%4096==0);
    assert(result.main.guestBytes>=4096 &&
           result.interpreter.guestBytes>=4096 &&
           result.stack.guestBytes==65536);
    assert(HasMappingPermissions(result.main.guestStart,"---p"));
    assert(HasMappingPermissions(result.interpreter.guestStart,"---p"));
    assert(HasMappingPermissions(result.stack.guestStart,"---p"));
    assert(result.plan.dependencyObjectsChecked>=5);
    assert(result.plan.stackAndAuxvConsistent &&
           result.plan.guestVirtualAddressesValidated &&
           result.plan.stack.guestRSP%16==0);
    assert(result.plan.stack.guestBottom==result.stack.guestStart);
    assert(result.plan.guestMainEntry>=result.main.guestStart);
    assert(result.plan.guestInterpreterEntry>=result.interpreter.guestStart);
    assert(!result.plan.guestAddressSpaceReserved &&
           !result.plan.guestMemoryMapped &&
           !result.plan.fexEntryPointAssigned &&
           !result.guestVAsInstalledInFEX &&
           !result.executableGuestPagesMapped &&
           !result.guestCodeExecuted &&
           !result.androidWineTested);
    for(size_t i=0;i<result.plan.regions.size();++i) {
        for(size_t j=i+1;j<result.plan.regions.size();++j)
            assert(kernix::g2b::X86GuestNonOverlap(
                result.plan.regions[i],result.plan.regions[j]));
    }
    // Install exact ELF and stack bytes into the kernel-selected,
    // already-owned host windows. They remain READ-ONLY, never executable.
    assert(kernix::g2b::StageX86ReadonlyHostBytes(fd,result,reason));
    assert(result.hostImageBytesStagedReadonly &&
           result.hostStackBytesStagedReadonly);
    assert(HasMappingPermissions(result.main.guestStart,"r--p"));
    assert(HasMappingPermissions(result.interpreter.guestStart,"r--p"));
    assert(HasMappingPermissions(result.stack.guestStart,"r--p"));
    // The guard portions of the same mmap stay PROT_NONE.
    const uint64_t hostPage=static_cast<uint64_t>(sysconf(_SC_PAGESIZE));
    assert(HasMappingPermissions(result.main.guestStart-hostPage,"---p"));
    assert(HasMappingPermissions(result.interpreter.guestStart-hostPage,"---p"));
    assert(HasMappingPermissions(result.stack.guestStart-hostPage,"---p"));
    assert(HasMappingPermissions(result.main.guestStart+result.main.guestBytes,"---p"));
    assert(HasMappingPermissions(result.interpreter.guestStart+result.interpreter.guestBytes,"---p"));
    assert(HasMappingPermissions(result.stack.guestStart+result.stack.guestBytes,"---p"));
    kernix::g2b::GuestReadonlyImage checkMain,checkInterpreter;
    std::string checkReason;
    assert(kernix::g2b::StageReadOnlyGuestELFImage(
        fd,"/bin/kernix-dynamic-app",checkMain,checkReason,true));
    assert(kernix::g2b::StageReadOnlyGuestELFImage(
        fd,"/lib64/ld-linux-x86-64.so.2",checkInterpreter,checkReason,false));
    assert(std::memcmp(reinterpret_cast<const void*>(
        static_cast<uintptr_t>(result.main.guestStart)),checkMain.hostView,
        checkMain.hostViewBytes)==0);
    assert(std::memcmp(reinterpret_cast<const void*>(
        static_cast<uintptr_t>(result.interpreter.guestStart)),checkInterpreter.hostView,
        checkInterpreter.hostViewBytes)==0);
    assert(std::memcmp(reinterpret_cast<const void*>(
        static_cast<uintptr_t>(result.stack.guestStart)),
        result.plan.stack.bytes.data(),result.plan.stack.bytes.size())==0);
    assert(!result.guestVAsInstalledInFEX &&
           !result.executableGuestPagesMapped &&
           !result.guestCodeExecuted && !result.androidWineTested);
    result.release();
    assert(!result.hostImageBytesStagedReadonly &&
           !result.hostStackBytesStagedReadonly);
    assert(result.plan.stack.bytes.empty() && !result.main.hostMapping &&
           !result.interpreter.hostMapping && !result.stack.hostMapping &&
           !result.hostVAsReservedPROT_NONE);
    Failure(fd,123,65536,random,args,env);
    Failure(fd,4096,1024,random,args,env);
    random.fill(0);Failure(fd,4096,65536,random,args,env);
    random[0]=10;
    Failure(fd,4096,65536,random,{},env);
    Failure(fd,4096,65536,random,args,{"UNSAFE"});
    X86HostNoAccessReservation single;
    assert(!kernix::g2b::ReserveX86NoAccessHostWindow(
        0,4096,single,reason));
    assert(!single.hostMapping);
    assert(!kernix::g2b::ReserveX86NoAccessHostWindow(
        4096,7,single,reason));
    assert(!single.hostMapping);
    assert(!kernix::g2b::ReserveX86NoAccessHostWindow(
        4097,4096,single,reason));
    assert(!single.hostMapping);
    assert(rename(leaf.c_str(),(leaf+".hidden").c_str())==0);
    Failure(fd,4096,65536,random,args,env);
    assert(rename((leaf+".hidden").c_str(),leaf.c_str())==0);
    assert(fcntl(fd,F_GETFD)>=0);
    close(fd);
    for(const auto& name:{executable,loader,libc,mid,leaf,link})
        assert(unlink(name.c_str())==0);
    for(const char* dir:{"/bin","/lib64","/lib/x86_64-linux-gnu","/lib"})
        assert(rmdir((root+dir).c_str())==0);
    assert(rmdir(root.c_str())==0);
    puts("KERNIX_G2B_REAL_MMAP_PROT_NONE_GUEST_HOST_VA_RESERVATIONS_PASS_NOT_FEX_MEMORY");
}
