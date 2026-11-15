#include "carxpc/r3d30/native/source_locked_guest_identity.hpp"
#include <cassert>
#include <cstdio>
int main(){
 const carx_r3d30::GuestIdentity id{2744,2776,10234,10234};
 using carx_r3d30::handle_identity;
 assert(handle_identity(39,id).value==2744);
 assert(handle_identity(186,id).value==2776);
 for(unsigned n:{102U,104U,107U,108U})
   assert(handle_identity(n,id).value==10234);
 for(unsigned n:{3U,0U,89U,257U,9999U})
   assert(!handle_identity(n,id).handled);
 assert(!handle_identity(39,{0,2776,1,1}).handled);
 std::puts("R3D30_GUEST_IDENTITY_SIX_SOURCE_LOCKED_X86_SYSCALLS_PASS");
}
