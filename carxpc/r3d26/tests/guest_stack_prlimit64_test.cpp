#include "carxpc/r3d26/native/guest_stack_prlimit64.hpp"
#include <cassert>
#include <cstdio>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <sys/mman.h>
int main(){
 using namespace carx_r3d26;
 constexpr size_t kGuestStack=65536;
 void* p=::mmap(nullptr,kGuestStack,PROT_READ|PROT_WRITE,
                MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
 assert(p!=MAP_FAILED);
 const uint64_t base=uint64_t(reinterpret_cast<uintptr_t>(p));
 const uint64_t end=base+kGuestStack;
 const uint64_t oldptr=end-64;
 const auto good=query_guest_stack_prlimit64(
      0,3,0,oldptr,base,end);
 assert(good.code==StackLimitCode::Success);
 LinuxRlimit64 observed{};
 std::memcpy(&observed,reinterpret_cast<const void*>(oldptr),
             sizeof(observed));
 assert(observed.cur==good.reported.cur);
 assert(observed.max==good.reported.max);
 assert(observed.cur<=observed.max && observed.max<=kGuestStack);
 assert(observed.max>0);
 // Unknown process, unknown resource, or attempts to modify host limits:
 // explicitly unsupported; no partial writes or false guest success.
 assert(query_guest_stack_prlimit64(1,3,0,oldptr,base,end).code==
        StackLimitCode::UnsupportedShape);
 assert(query_guest_stack_prlimit64(0,4,0,oldptr,base,end).code==
        StackLimitCode::UnsupportedShape);
 assert(query_guest_stack_prlimit64(0,3,base,oldptr,base,end).code==
        StackLimitCode::UnsupportedShape);
 assert(query_guest_stack_prlimit64(0,3,0,0,base,end).code==
        StackLimitCode::UnsupportedShape);
 assert(query_guest_stack_prlimit64(0,3,0,end-8,base,end).code==
        StackLimitCode::OutsideWritableGuestStack);
 assert(query_guest_stack_prlimit64(0,3,0,end-63,base,end).code==
        StackLimitCode::OutsideWritableGuestStack);
 assert(query_guest_stack_prlimit64(0,3,0,base-16,base,end).code==
        StackLimitCode::OutsideWritableGuestStack);
 assert(query_guest_stack_prlimit64(0,3,0,oldptr,0,end).code==
        StackLimitCode::InvalidStackRegion);
 assert(::munmap(p,kGuestStack)==0);
 std::puts("R3D26_SOURCE_LOCKED_LIBC_PRLIMIT64_GUEST_OWNED_STACK_CAP_POLICY_TEST_PASS");
}
