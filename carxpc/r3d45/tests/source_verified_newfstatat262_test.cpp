#include "carxpc/r3d45/native/source_verified_newfstatat262.hpp"
#include <cassert>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
int main() {
 using namespace carx_r3d45;
 char scratch[]="/tmp/carx-r3d45-fstatat-XXXXXX";
 assert(::mkdtemp(scratch));
 const std::string root=scratch;
 assert(::mkdir((root+"/etc").c_str(),0700)==0);
 const int file=::open((root+"/etc/nsswitch.conf").c_str(),
   O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0644);
 assert(file>=0);
 constexpr char bytes[]="passwd: files\n";
 assert(::write(file,bytes,sizeof(bytes)-1)==ssize_t(sizeof(bytes)-1));
 assert(::close(file)==0);
 assert(::symlink("nsswitch.conf",(root+"/etc/alias.conf").c_str())==0);
 const int rootfd=::open(root.c_str(),O_RDONLY|O_DIRECTORY|O_CLOEXEC);
 assert(rootfd>=0);
 char guestPath[256]{};
 carx_r3d19::LinuxX64Stat guestOut{};
 const uint64_t guestPathAddr=reinterpret_cast<uintptr_t>(guestPath);
 const uint64_t guestOutAddr=reinterpret_cast<uintptr_t>(&guestOut);
 auto ownedRead=[&](uint64_t addr,uint64_t len) {
   return len==1 && addr>=guestPathAddr &&
          addr-guestPathAddr<sizeof(guestPath);
 };
 auto ownedWrite=[&](uint64_t addr,uint64_t len) {
   return addr==guestOutAddr && len==144;
 };
 auto invoke=[&](uint64_t num,uint64_t dirfd,uint64_t flags,int fd,
                  auto&& read,auto&& write){
  return source_verified_newfstatat(num,dirfd,guestPathAddr,
         guestOutAddr,flags,fd,read,write);
 };
 std::strcpy(guestPath,"/etc/nsswitch.conf");
 auto r=invoke(262,kAtFdcwdZeroExtended,0,rootfd,ownedRead,ownedWrite);
 assert(r.handled&&r.value==0&&r.reason==Reason::Success);
 assert(r.guestPath.size==std::strlen("/etc/nsswitch.conf"));
 assert(guestOut.size==ssize_t(sizeof(bytes)-1));
 assert((guestOut.mode&S_IFMT)==S_IFREG && guestOut.nlink>=1);
 char pathMark[166]{};
 path_hex_marker(r.guestPath,pathMark);
 assert(std::strstr(pathMark,"2F6574632F6E737377697463682E636F6E66"));
 std::strcpy(guestPath,"/etc/alias.conf");
 r=invoke(262,kAtFdcwdZeroExtended,0,rootfd,ownedRead,ownedWrite);
 assert(r.handled&&r.value==0&&r.symlinkHops==1);
 assert(guestOut.size==ssize_t(sizeof(bytes)-1));
 std::strcpy(guestPath,"/etc/does-not-exist");
 guestOut.size=999999;
 r=invoke(262,kAtFdcwdZeroExtended,0,rootfd,ownedRead,ownedWrite);
 assert(r.handled&&r.value==-ENOENT&&r.reason==Reason::GuestFileNotFound);
 assert(guestOut.size==999999); // negative syscall must not write statbuf
 std::strcpy(guestPath,"/etc/nsswitch.conf");
 r=invoke(262,kAtFdcwdZeroExtended,0,rootfd,ownedRead,
    [&](uint64_t,uint64_t){return false;});
 assert(!r.handled&&r.reason==Reason::UnownedGuestStatDestination);
 r=invoke(262,kAtFdcwdZeroExtended,0,rootfd,
    [&](uint64_t,uint64_t){return false;},ownedWrite);
 assert(!r.handled&&r.reason==Reason::UnownedOrInvalidGuestPath);
 r=invoke(262,77,0,rootfd,ownedRead,ownedWrite);
 assert(!r.handled&&r.reason==Reason::UnsupportedDirfd);
 r=invoke(262,kAtFdcwdZeroExtended,0x100,rootfd,ownedRead,ownedWrite);
 assert(!r.handled&&r.reason==Reason::UnsupportedFlags);
 r=invoke(263,kAtFdcwdZeroExtended,0,rootfd,ownedRead,ownedWrite);
 assert(!r.handled&&r.reason==Reason::NotNewfstatat);
 r=invoke(262,kAtFdcwdZeroExtended,0,-1,ownedRead,ownedWrite);
 assert(!r.handled&&r.reason==Reason::UntrustedRoot);
 std::strcpy(guestPath,"../etc/nsswitch.conf");
 r=invoke(262,kAtFdcwdZeroExtended,0,rootfd,ownedRead,ownedWrite);
 assert(!r.handled&&r.reason==Reason::RelativeGuestPath);
 std::strcpy(guestPath,"/../../etc/nsswitch.conf");
 r=invoke(262,kAtFdcwdSignExtended,0,rootfd,ownedRead,ownedWrite);
 assert(!r.handled&&r.reason==Reason::UnsafeRootfs);
 std::strcpy(guestPath,"/");
 r=invoke(262,kAtFdcwdZeroExtended,0,rootfd,ownedRead,ownedWrite);
 assert(r.handled&&r.value==0&&((guestOut.mode&S_IFMT)==S_IFDIR));
 assert(::close(rootfd)==0);
 assert(::unlink((root+"/etc/alias.conf").c_str())==0);
 assert(::unlink((root+"/etc/nsswitch.conf").c_str())==0);
 assert(::rmdir((root+"/etc").c_str())==0);
 assert(::rmdir(root.c_str())==0);
 std::puts("R3D45_REAL_SOURCE_OWNED_X86_NEWFSTATAT262_ROOTFS_144BYTE_STAT_TEST_PASS");
}
