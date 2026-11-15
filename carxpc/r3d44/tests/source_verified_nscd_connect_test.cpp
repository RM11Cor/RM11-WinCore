#include "carxpc/r3d44/native/source_verified_nscd_connect.hpp"
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
 using namespace carx_r3d44;
 char tmp[]="/tmp/carx-r3d44-nscd-XXXXXX";
 const char* rp=::mkdtemp(tmp);assert(rp);
 const std::string root=rp;
 assert(::mkdir((root+"/var").c_str(),0700)==0);
 assert(::mkdir((root+"/run").c_str(),0700)==0);
 assert(::mkdir((root+"/run/nscd").c_str(),0700)==0);
 assert(::symlink("../run",(root+"/var/run").c_str())==0);
 const int rootfd=::open(root.c_str(),O_RDONLY|O_DIRECTORY|O_CLOEXEC);
 assert(rootfd>=0);
 carx_r3d43::OwnedUnixSockets sockets{};
 const auto newSocket=sockets.dispatch(41,1,0x80801,0);
 assert(newSocket.handled&&newSocket.value==117);
 unsigned char addr[110]{};
 const uint64_t gp=reinterpret_cast<uintptr_t>(addr);
 const auto owned=[&](uint64_t p,uint64_t n){
  return p==gp && n==110;
 };
 const auto setpath=[&](const char* p){
  std::memset(addr,0,sizeof(addr));
  addr[0]=1;addr[1]=0;
  assert(std::strlen(p)<108);
  std::memcpy(addr+2,p,std::strlen(p)+1);
 };
 setpath("/var/run/nscd/socket");
 auto result=source_verified_nscd_connect(42,117,gp,110,rootfd,sockets,owned);
 assert(result.handled&&result.value==-ENOENT);
 assert(result.reason==Reason::HandledNscdAbsent);
 assert(result.symlinkHops==1);
 assert(result.pathLength==std::strlen("/var/run/nscd/socket"));
 char mark[190]{};
 path_hex_marker(result,mark);
 assert(std::strstr(mark,"2F7661722F72756E")!=nullptr);
 setpath("/run/nscd/socket");
 result=source_verified_nscd_connect(42,117,gp,110,rootfd,sockets,owned);
 assert(result.handled && result.value==-ENOENT && result.symlinkHops==0);
 setpath("/tmp/unauthorized.sock");
 result=source_verified_nscd_connect(42,117,gp,110,rootfd,sockets,owned);
 assert(!result.handled&&result.reason==Reason::UnexpectedPath);
 setpath("socket");
 result=source_verified_nscd_connect(42,117,gp,110,rootfd,sockets,owned);
 assert(!result.handled&&result.reason==Reason::UnexpectedPath);
 setpath("/var/run/nscd/socket");
 result=source_verified_nscd_connect(42,116,gp,110,rootfd,sockets,owned);
 assert(!result.handled&&result.reason==Reason::UnknownGuestSocket);
 result=source_verified_nscd_connect(42,117,gp,111,rootfd,sockets,owned);
 assert(!result.handled&&result.reason==Reason::InvalidSize);
 result=source_verified_nscd_connect(42,117,gp,1,rootfd,sockets,owned);
 assert(!result.handled&&result.reason==Reason::InvalidSize);
 result=source_verified_nscd_connect(42,117,gp,110,rootfd,sockets,
       [&](uint64_t,uint64_t){return false;});
 assert(!result.handled&&result.reason==Reason::UnownedGuestMemory);
 addr[0]=2;
 result=source_verified_nscd_connect(42,117,gp,110,rootfd,sockets,owned);
 assert(!result.handled&&result.reason==Reason::NotUnixFamily);
 addr[0]=1;addr[2]=0;
 result=source_verified_nscd_connect(42,117,gp,110,rootfd,sockets,owned);
 assert(!result.handled&&result.reason==Reason::AbstractSocket);
 std::memset(addr+2,'x',108);
 result=source_verified_nscd_connect(42,117,gp,110,rootfd,sockets,owned);
 assert(!result.handled&&result.reason==Reason::UnterminatedPath);
 setpath("/var/run/nscd/socket");addr[7]=0x0a;
 result=source_verified_nscd_connect(42,117,gp,110,rootfd,sockets,owned);
 assert(!result.handled&&result.reason==Reason::UnsafePathBytes);
 setpath("/var/run/nscd/socket");
 result=source_verified_nscd_connect(43,117,gp,110,rootfd,sockets,owned);
 assert(!result.handled&&result.reason==Reason::NotConnect);
 const int file=::open((root+"/run/nscd/socket").c_str(),
                      O_CREAT|O_WRONLY|O_EXCL,0600);
 assert(file>=0&&::close(file)==0);
 result=source_verified_nscd_connect(42,117,gp,110,rootfd,sockets,owned);
 assert(!result.handled&&result.reason==Reason::RootfsPathPresent);
 assert(::unlink((root+"/run/nscd/socket").c_str())==0);
 result=source_verified_nscd_connect(42,117,gp,110,-1,sockets,owned);
 assert(!result.handled&&result.reason==Reason::UnsafeRootfs);
 assert(sockets.owns(117)); // connect errors must not steal/discard guest fd
 assert(sockets.dispatch(3,117,0,0).value==0);
 result=source_verified_nscd_connect(42,117,gp,110,rootfd,sockets,owned);
 assert(!result.handled&&result.reason==Reason::UnknownGuestSocket);
 assert(::close(rootfd)==0);
 std::puts("R3D44_SOURCE_VERIFIED_LIBC_NSCD_CONNECT42_REAL_ROOTFS_ABSENT_ENOENT_TEST_PASS");
}
