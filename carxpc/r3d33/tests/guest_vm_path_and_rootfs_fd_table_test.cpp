#include "carxpc/r3d33/native/preflight24_guest_vm_paths.hpp"
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
int main(){
 using namespace carx_r3d33;
 std::vector<std::string> records;
 auto batch=run_preflight24([&](const char* line){records.emplace_back(line);});
 assert(batch.total==24&&batch.passed==24&&batch.failed==0);
 assert(records.size()==25);
 assert(records.back()=="N53_GUEST_VM_PATH_PREFLIGHT_TOTAL_24_PASS_24_FAIL_0");
 char tmp[]="/tmp/carx-r3d33-rootXXXXXX";
 const char* root=::mkdtemp(tmp);assert(root);
 const std::string name=root;
 assert(::mkdir((name+"/usr").c_str(),0700)==0);
 assert(::mkdir((name+"/usr/lib").c_str(),0700)==0);
 assert(::mkdir((name+"/usr/lib/wine").c_str(),0700)==0);
 int fd=::open((name+"/usr/lib/wine/wine64").c_str(),
                O_WRONLY|O_CREAT|O_EXCL,0600);
 assert(fd>=0);
 const char data[]="WINE-ELF-Test";
 assert(::write(fd,data,sizeof(data)-1)==static_cast<ssize_t>(sizeof(data)-1));
 assert(::close(fd)==0);
 assert(::symlink("usr/lib",(name+"/lib").c_str())==0);
 int rootfd=::open(root,O_RDONLY|O_DIRECTORY|O_NOFOLLOW);assert(rootfd>=0);
 ReadOnlyFiles files{};
 auto missing=files.open_guest_file(rootfd,"/no-file");
 assert(missing.state==OpenState::Resolved&&missing.value==-ENOENT);
 auto invalid=files.open_guest_file(rootfd,"/../../etc/passwd");
 assert(invalid.state==OpenState::UnsafePath);
 auto missingIntermediate=files.open_guest_file(rootfd,
   "/usr/lib/no-such-dir/../wine/wine64");
 assert(missingIntermediate.state==OpenState::Resolved &&
        missingIntermediate.value==-ENOENT);
 auto sourceGuestPath=files.open_guest_file(rootfd,
   "/usr/lib/wine/../x86_64-linux-gnu/wine/x86_64-unix/ntdll.so");
 assert(sourceGuestPath.state==OpenState::Resolved &&
        sourceGuestPath.value==-ENOENT);
 auto linked=files.open_guest_file(rootfd,"/lib/wine/wine64");
 assert(linked.state==OpenState::UnresolvedSymlink ||
        (linked.state==OpenState::Resolved && linked.value==-ENOTDIR));
 auto opened=files.open_guest_file(rootfd,"/usr/lib/wine/wine64");
 assert(opened.state==OpenState::Resolved && opened.value==101);
 auto dotdot=files.open_guest_file(rootfd,"/usr/lib/wine/../wine/wine64");
 assert(dotdot.state==OpenState::Resolved && dotdot.value==102);
 assert(files.close_guest(102)==0);
 char* const buffer=static_cast<char*>(::mmap(nullptr,4096,
   PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0));
 assert(buffer!=MAP_FAILED);
 const auto base=reinterpret_cast<uintptr_t>(buffer);
 const auto write=[&](uint64_t p,uint64_t n){
   return p>=base&&p<base+4096&&n>0&&n<=4096-(p-base);
 };
 assert(files.read_guest(101,base,4,write)==4);
 assert(std::memcmp(buffer,"WINE",4)==0);
 assert(files.pread_guest(101,base+20,3,5,write)==3);
 assert(std::memcmp(buffer+20,"ELF",3)==0);
 assert(files.lseek_guest(101,0,0)==0);
 assert(files.read_guest(101,base+100,4,write)==4);
 assert(std::memcmp(buffer+100,"WINE",4)==0);
 assert(files.fstat_guest(101,base+256,write)==0);
 carx_r3d19::LinuxX64Stat st{};
 std::memcpy(&st,buffer+256,sizeof(st));
 assert(st.size==static_cast<int64_t>(sizeof(data)-1));
 assert(files.read_guest(101,base+4090,16,write)==-EFAULT);
 assert(files.close_guest(101)==0);
 assert(!files.owns(101));
 assert(files.read_guest(101,base,4,write)==-EBADF);
 assert(::munmap(buffer,4096)==0);
 ::close(rootfd);
 assert(::unlink((name+"/usr/lib/wine/wine64").c_str())==0);
 assert(::unlink((name+"/lib").c_str())==0);
 assert(::rmdir((name+"/usr/lib/wine").c_str())==0);
 assert(::rmdir((name+"/usr/lib").c_str())==0);
 assert(::rmdir((name+"/usr").c_str())==0);
 assert(::rmdir(root)==0);
 std::puts("R3D33_24_GUEST_BRK_MMAP_STACK_PATH_AND_ROOTFS_FD_TABLE_PASS");
}
