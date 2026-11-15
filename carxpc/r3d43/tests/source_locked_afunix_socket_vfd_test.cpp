#include "carxpc/r3d43/native/source_locked_afunix_socket_vfd.hpp"
#include <cassert>
#include <cerrno>
#include <cstdio>
#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>
int main(){
 using namespace carx_r3d43;
 OwnedUnixSockets s;
 // Real R3D42 phone observation: socket(1,0x80801,0), source libc.
 const auto first=s.dispatch(41,1,0x80801,0);
 assert(first.handled && first.value==117 && first.reason==Reason::Accepted);
 assert(s.owns(117)&&!s.owns(101)&&!s.owns(116)&&!s.owns(125));
 int native=s.native_fd_for_verification(117);
 assert(native>=0 && native!=117);
 assert((::fcntl(native,F_GETFL)&O_NONBLOCK)!=0);
 assert((::fcntl(native,F_GETFD)&FD_CLOEXEC)!=0);
 int type=0;socklen_t typeSize=sizeof(type);
 assert(::getsockopt(native,SOL_SOCKET,SO_TYPE,&type,&typeSize)==0);
 assert(type==SOCK_STREAM);
 const auto invalidFamily=s.dispatch(41,2,0x80801,0);
 assert(!invalidFamily.handled && invalidFamily.reason==Reason::InvalidFamily);
 const auto invalidType=s.dispatch(41,1,0x80802,0);
 assert(!invalidType.handled && invalidType.reason==Reason::InvalidType);
 const auto invalidFlag=s.dispatch(41,1,0x20000001,0);
 assert(!invalidFlag.handled && invalidFlag.reason==Reason::InvalidType);
 const auto invalidProtocol=s.dispatch(41,1,0x80801,6);
 assert(!invalidProtocol.handled && invalidProtocol.reason==Reason::InvalidProtocol);
 const auto unhandled=s.dispatch(42,117,0,0);
 assert(!unhandled.handled && unhandled.reason==Reason::UnsupportedSyscall);
 const auto notGuest=s.dispatch(3,101,0,0);
 assert(!notGuest.handled && notGuest.reason==Reason::InvalidGuestFd);
 // Allocate all eight slots without leaking or colliding with VFS fd101..116.
 for(int fd=118;fd<=124;fd++){
   auto next=s.dispatch(41,1,1,0);
   assert(next.handled && next.value==fd);
   assert(s.owns(fd));
 }
 assert(s.dispatch(41,1,1,0).value==-EMFILE);
 const auto closed=s.dispatch(3,117,0,0);
 assert(closed.handled&&closed.value==0&&!s.owns(117));
 assert(::fcntl(native,F_GETFD)==-1&&errno==EBADF);
 assert(!s.dispatch(3,117,0,0).handled);
 auto reused=s.dispatch(41,1,0x80801,0);
 assert(reused.handled&&reused.value==117&&s.owns(117));
 for(int fd=117;fd<=124;fd++){
   auto result=s.dispatch(3,fd,0,0);
   assert(result.handled&&result.value==0&&!s.owns(fd));
 }
 // Empty table, unsupported connect must stay blocked (not passed to host).
 assert(!s.dispatch(42,117,0,0).handled);
 std::puts("R3D43_REAL_AF_UNIX_SOCKET41_GUEST_VFD117_NATIVE_FLAGS_AND_CLOSE_HOST_TEST_PASS");
}
