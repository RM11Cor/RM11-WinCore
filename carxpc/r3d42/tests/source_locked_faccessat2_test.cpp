#include "carxpc/r3d42/native/source_locked_faccessat2.hpp"
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

static void d(const std::string& p){assert(::mkdir(p.c_str(),0700)==0);}
static void link(const std::string& p,const std::string&t){
 assert(::symlink(t.c_str(),p.c_str())==0);
}
int main() {
 using namespace carx_r3d42;
 char tmp[]="/tmp/carx-r3d42-faccessXXXXXX";
 const char* rp=::mkdtemp(tmp);assert(rp);
 std::string root=rp;
 d(root+"/usr");d(root+"/usr/lib");
 d(root+"/usr/lib/x86_64-linux-gnu");
 int fd=::open((root+"/usr/lib/x86_64-linux-gnu/libunwind.so.8.0.1").c_str(),
      O_CREAT|O_WRONLY|O_EXCL,0200);
 assert(fd>=0);assert(::write(fd,"OK",2)==2);assert(::close(fd)==0);
 assert(::chmod((root+"/usr/lib/x86_64-linux-gnu/libunwind.so.8.0.1").c_str(),0000)==0);
 link(root+"/usr/lib/x86_64-linux-gnu/libunwind.so.8","libunwind.so.8.0.1");
 link(root+"/lib","usr/lib");
 link(root+"/usr/lib/host-absolute","/etc/passwd");
 link(root+"/usr/lib/loop-a","loop-b");
 link(root+"/usr/lib/loop-b","loop-a");
 fd=::open(root.c_str(),O_RDONLY|O_DIRECTORY|O_CLOEXEC);
 assert(fd>=0);
 char path[256]{};
 const uint64_t guest=reinterpret_cast<uintptr_t>(path);
 const auto owned=[&](uint64_t p,uint64_t n)->bool{
    return p>=guest && p-guest<sizeof(path) &&
      n>0 && n<=sizeof(path)-(p-guest);
 };
 const auto probe=[&](const char* str,uint64_t mode=0,
                      uint64_t flags=kAtEaccess,uint64_t dirfd=uint32_t(-100)){
   std::memset(path,0,sizeof(path));
   std::strncpy(path,str,sizeof(path)-1);
   return source_verified_faccessat2(kX64Faccessat2,
      dirfd,guest,mode,flags,fd,owned);
 };
 const auto target=probe("/lib/x86_64-linux-gnu/libunwind.so.8");
 assert(target.handled && target.value==0 && target.hops==2);
 assert(target.reason==Reason::Ok);
 char marker[144]{};
 path_hex_marker(target.path,marker);
 assert(std::strncmp(marker,"N65_R3D42_FACCESSAT2_GUEST_PATH_HEX_",37)==0);
 assert(std::strstr(marker,"2F6C6962")!=nullptr);
 auto abs=probe("/usr/lib/x86_64-linux-gnu/libunwind.so.8");
 assert(abs.handled && abs.value==0 && abs.hops==1);
 auto rootPath=probe("/");
 assert(rootPath.handled && rootPath.value==0);
 auto missing=probe("/etc/ld.so.preload");
 assert(missing.handled && missing.value==-ENOENT);
 assert(missing.reason==Reason::NoFile);
 auto hostEscape=probe("/usr/lib/host-absolute");
 assert(hostEscape.handled && hostEscape.value==-ENOENT);
 auto noDir=probe("/usr/lib/x86_64-linux-gnu/libunwind.so.8/foo");
 assert(noDir.handled && noDir.value==-ENOTDIR);
 auto relative=probe("usr/lib/x86_64-linux-gnu/libunwind.so.8");
 assert(!relative.handled && relative.reason==Reason::RelativeCwdUnproven);
 auto parentEscape=probe("/usr/../../../etc/passwd");
 assert(!parentEscape.handled && parentEscape.reason==Reason::UnsafePath);
 auto loop=probe("/usr/lib/loop-a");
 assert(!loop.handled && loop.reason==Reason::SymlinkLoop);
 auto flags=probe("/etc/ld.so.preload",0,0x100);
 assert(!flags.handled && flags.reason==Reason::UnknownFlags);
 auto mode=probe("/etc/ld.so.preload",R_OK,kAtEaccess);
 assert(!mode.handled && mode.reason==Reason::UnknownMode);
 auto dirfdWrong=probe("/etc/ld.so.preload",0,kAtEaccess,1);
 assert(!dirfdWrong.handled && dirfdWrong.reason==Reason::UnknownDirfd);
 auto alternate=probe("/etc/ld.so.preload",0,0);
 assert(alternate.handled && alternate.value==-ENOENT);
 const auto deniedRead=[&](uint64_t, uint64_t){return false;};
 auto invalid=source_verified_faccessat2(kX64Faccessat2,
      uint32_t(-100),guest,0,kAtEaccess,fd,deniedRead);
 assert(!invalid.handled && invalid.reason==Reason::InvalidSource);
 auto unknown=source_verified_faccessat2(432,
      uint32_t(-100),guest,0,kAtEaccess,fd,owned);
 assert(!unknown.handled);
 auto badRoot=source_verified_faccessat2(kX64Faccessat2,
      uint32_t(-100),guest,0,kAtEaccess,-1,owned);
 assert(!badRoot.handled && badRoot.reason==Reason::SourceRootInvalid);
 assert(::close(fd)==0);
 std::puts("R3D42_FACCESSAT2_SOURCE_LOCKED_F_OK_AT_EACCESS_JAILED_PATH_TEST_PASS");
}
