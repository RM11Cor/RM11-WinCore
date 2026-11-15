#include "carxpc/r3d41/native/confined_symlink_walker.hpp"
#include <cassert>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
static void dir(const std::string& p){assert(::mkdir(p.c_str(),0700)==0);}
static void reg(const std::string&p){
 int fd=::open(p.c_str(),O_CREAT|O_WRONLY|O_TRUNC,0600);
 assert(fd>=0);assert(::write(fd,"okay",4)==4);assert(::close(fd)==0);
}
static void link(const std::string&p,const std::string&t){
 assert(::symlink(t.c_str(),p.c_str())==0);
}
int main(){
 char tmp[]="/tmp/carx-r3d41-rootXXXXXX";
 const char* r=::mkdtemp(tmp);assert(r);
 const std::string base=r;
 dir(base+"/usr");dir(base+"/usr/lib");
 dir(base+"/usr/lib/x86_64-linux-gnu");
 reg(base+"/usr/lib/x86_64-linux-gnu/libunwind.so.8.0.1");
 link(base+"/usr/lib/x86_64-linux-gnu/libunwind.so.8","libunwind.so.8.0.1");
 link(base+"/lib","usr/lib");
 int rootfd=::open(base.c_str(),O_RDONLY|O_DIRECTORY|O_CLOEXEC);
 assert(rootfd>=0);
 const auto check=[&](const char*path,bool accepted){
   auto x=carx_r3d41::open_guest_readonly(rootfd,path);
   assert((x.fd>=0)==accepted);
   if(x.fd>=0){
     char data[5]{};
     assert(::read(x.fd,data,4)==4);
     assert(std::strcmp(data,"okay")==0);
     assert(::close(x.fd)==0);
   }
   return x;
 };
 auto a=check("/usr/lib/x86_64-linux-gnu/libunwind.so.8",true);
 assert(a.symlinks==1);
 auto b=check("/lib/x86_64-linux-gnu/libunwind.so.8",true);
 assert(b.symlinks==2);
 link(base+"/usr/lib/absolute.so","/usr/lib/x86_64-linux-gnu/libunwind.so.8");
 auto c=check("/usr/lib/absolute.so",true);assert(c.symlinks==2);
 dir(base+"/usr/lib/wine");
 auto d=check("/usr/lib/wine/../x86_64-linux-gnu/libunwind.so.8",true);
 assert(d.symlinks==1);
 reg(base+"/usr/lib/regular");
 auto e=check("/usr/lib/regular/foo",false);
 assert(e.negativeErrno==-ENOTDIR);
 link(base+"/usr/lib/escape","../../../etc/passwd");
 auto f=check("/usr/lib/escape",false);
 assert(f.status==carx_r3d41::Status::Unsafe);
 link(base+"/usr/lib/hostescape","/etc/passwd");
 auto g=check("/usr/lib/hostescape",false);
 assert(g.negativeErrno==-ENOENT);
 link(base+"/usr/lib/loop1","loop2");
 link(base+"/usr/lib/loop2","loop1");
 auto h=check("/usr/lib/loop1",false);
 assert(h.negativeErrno==-ELOOP);
 auto i=check("/usr/lib/missing",false);
 assert(i.negativeErrno==-ENOENT);
 auto j=check("/../../etc/passwd",false);
 assert(j.status==carx_r3d41::Status::Unsafe);
 assert(::close(rootfd)==0);
 std::puts("R3D41_CONFINED_SYMLINK_GUEST_ROOTFD_HOST_TEST_PASS");
}
