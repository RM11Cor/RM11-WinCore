#define CARX_R3D41_CONFINED_GUEST_SYMLINKS 1
#include "carxpc/r3d33/native/owned_guest_path_and_vfs.hpp"
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
int main(){
 using namespace carx_r3d33;
 char tmp[]="/tmp/carx-r3d41-vfs-XXXXXX";
 const char *root=::mkdtemp(tmp);assert(root);
 std::string base=root;
 assert(::mkdir((base+"/usr").c_str(),0700)==0);
 assert(::mkdir((base+"/usr/lib").c_str(),0700)==0);
 assert(::mkdir((base+"/usr/lib/x86_64-linux-gnu").c_str(),0700)==0);
 const std::string actual=base+"/usr/lib/x86_64-linux-gnu/libunwind.so.8.0.1";
 int file=::open(actual.c_str(),O_CREAT|O_WRONLY|O_EXCL,0600);
 assert(file>=0);assert(::write(file,"real",4)==4);assert(::close(file)==0);
 assert(::symlink("libunwind.so.8.0.1",(base+"/usr/lib/x86_64-linux-gnu/libunwind.so.8").c_str())==0);
 assert(::symlink("usr/lib",(base+"/lib").c_str())==0);
 const int dirfd=::open(base.c_str(),O_RDONLY|O_DIRECTORY|O_NOFOLLOW);
 assert(dirfd>=0);
 ReadOnlyFiles files{};
 auto first=files.open_guest_file(dirfd,"/lib/x86_64-linux-gnu/libunwind.so.8");
 assert(first.state==OpenState::Resolved && first.value==101 && first.symlinkCount==2);
 char buffer[4096]{};
 const uint64_t guest=reinterpret_cast<uintptr_t>(buffer);
 const auto writable=[&](uint64_t p,uint64_t len) {
   return len>0 && p>=guest && p-guest<sizeof(buffer) &&
          len<=sizeof(buffer)-(p-guest);
 };
 assert(files.read_guest(101,guest,4,writable)==4);
 assert(std::memcmp(buffer,"real",4)==0);
 assert(files.close_guest(101)==0);
 auto second=files.open_guest_file(dirfd,"/usr/lib/x86_64-linux-gnu/libunwind.so.8");
 assert(second.state==OpenState::Resolved && second.value==101 && second.symlinkCount==1);
 assert(files.close_guest(101)==0);
 auto missing=files.open_guest_file(dirfd,"/usr/lib/x86_64-linux-gnu/nope.so");
 assert(missing.state==OpenState::Resolved && missing.value==-ENOENT);
 auto escape=files.open_guest_file(dirfd,"/usr/../../../etc/passwd");
 assert(escape.state==OpenState::UnsafePath);
 assert(::close(dirfd)==0);
 std::puts("R3D41_REAL_READONLY_GUEST_VFS_FD101_SYMLINK_INTEGRATION_PASS");
}
