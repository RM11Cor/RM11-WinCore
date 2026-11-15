#include "carxpc/r3d30/native/batch_preflight.hpp"
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <string>
#include <vector>
#include <initializer_list>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/mman.h>
int main() {
 using namespace carx_r3d30;
 char dir[]="/tmp/r3d30rootXXXXXX";const char* root=::mkdtemp(dir);
 assert(root);
 auto mkdirp=[&](const char* p){
   assert(::mkdir((std::string(root)+p).c_str(),0700)==0);
 };
 for(const char* p:{"/usr","/usr/lib","/usr/lib/wine","/usr/share",
                    "/usr/share/wine","/tmp"})mkdirp(p);
 for(const char* p:{"/usr/lib/wine/wine64","/usr/share/wine/wine.inf",
                    "/tmp/kernix-real-win32-smoke.exe"}){
   int fd=::open((std::string(root)+p).c_str(),O_CREAT|O_EXCL|O_WRONLY,0600);
   assert(fd>=0);::close(fd);
 }
 assert(::symlink("usr/lib",(std::string(root)+"/lib").c_str())==0);
 int rootFd=::open(root,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
 assert(rootFd>=0);
 auto* data=static_cast<char*>(::mmap(nullptr,65536,PROT_READ|PROT_WRITE,
                     MAP_PRIVATE|MAP_ANONYMOUS,-1,0));
 assert(data!=MAP_FAILED);
 const uint64_t low=reinterpret_cast<uintptr_t>(data),high=low+65536;
 auto* dst=data+65536-1024;std::memset(dst,'Z',1024);
 auto read=[&](const char* p,uint64_t count=1023){
   return resolve_readlink(rootFd,p,reinterpret_cast<uintptr_t>(dst),
                           count,low,high);
 };
 for(const char* p:{"/","/usr","/usr/lib","/usr/lib/wine","/usr/lib/wine/wine64"}){
   auto v=read(p);
   assert(v.status==Status::Resolved&&v.value==-EINVAL&&dst[0]=='Z');
 }
 auto v=read("/lib");
 assert(v.status==Status::Resolved&&v.value==7);
 assert(std::memcmp(dst,"usr/lib",7)==0&&dst[7]=='Z');
 v=read("/lib/x86_64-linux-gnu/libc.so.6");
 assert(v.status==Status::IntermediateSymlink);
 v=read("/missing");assert(v.status==Status::Resolved&&v.value==-ENOENT);
 v=read("/usr/lib/wine/wine64/nope");
 assert(v.status==Status::Resolved&&v.value==-ENOTDIR);
 v=read("/usr/../../etc");
 assert(v.status==Status::InvalidGuestPath);
 v=read("/usr",0);assert(v.status==Status::InvalidGuestOutput);
 std::vector<std::string> lines;
 auto rep=run_matrix(rootFd,[&](const char* x){lines.emplace_back(x);});
 assert(rep.scenarios==40&&rep.requiredFailures==0&&rep.ready());
 assert(lines.size()==41);
 assert(::unlink((std::string(root)+"/usr/lib/wine/wine64").c_str())==0);
 lines.clear();rep=run_matrix(rootFd,[&](const char* x){lines.emplace_back(x);});
 assert(rep.scenarios==40&&rep.requiredFailures==1&&!rep.ready());
 assert(lines.size()==41);
 assert(::munmap(data,65536)==0);::close(rootFd);
 for(const char* p:{"/usr/share/wine/wine.inf","/tmp/kernix-real-win32-smoke.exe",
                     "/lib"})assert(::unlink((std::string(root)+p).c_str())==0);
 for(const char* p:{"/usr/lib/wine","/usr/lib","/usr/share/wine",
                    "/usr/share","/usr","/tmp"})
   assert(::rmdir((std::string(root)+p).c_str())==0);
 assert(::rmdir(root)==0);
 std::puts("R3D30_ROOTFS_VFS_AND_40_CASE_INDEPENDENT_BATCH_PREFLIGHT_PASS");
}
