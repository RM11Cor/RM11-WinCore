#include "carxpc/r3d31/native/source_locked_guest_misc_abi.hpp"
#include "carxpc/r3d19/native/unified_guest_libc_abi.hpp"
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <sys/mman.h>
int main(){
 using namespace carx_r3d31;
 carx_r3d19::GuestMappings maps{};
 constexpr uint64_t flags=carx_r3d19::kLinuxMapPrivate|
     carx_r3d19::kLinuxMapAnonymous;
 int64_t guest=maps.map(-1,false,0,4096,PROT_READ|PROT_WRITE,
                       flags,UINT64_MAX,0);
 assert(guest>0);
 const uint64_t ptr=uint64_t(guest)+100;
 auto writable=[&](uint64_t addr,uint64_t count){
   return maps.owned_writable_range(addr,count);
 };
 auto get=[&](uint64_t nr,uint64_t a,uint64_t b,uint64_t c){
   return source_locked_dispatch(nr,a,b,c,writable);
 };
 auto r=get(318,ptr,8,1);  // real /dev/urandom-equivalent host entropy
 assert(r.kind==Kind::Success);
 assert(r.result==8||r.result==-EAGAIN||r.result==-EINTR);
 assert(get(318,ptr+4090,8,1).kind==Kind::ShapeRejected);
 assert(get(318,0,8,1).kind==Kind::ShapeRejected);
 assert(get(318,ptr,257,1).kind==Kind::ShapeRejected);
 assert(get(318,ptr,8,2).kind==Kind::ShapeRejected);
 assert(get(318,0,0,1).kind==Kind::Success);
 assert(get(228,0,ptr,0).kind==Kind::Success);
 LinuxX64Timespec time{};
 std::memcpy(&time,reinterpret_cast<void*>(ptr),sizeof(time));
 assert(time.secs>0&&time.nsecs>=0&&time.nsecs<1000000000);
 assert(get(228,1,ptr,0).kind==Kind::Success);
 assert(get(228,123,ptr,0).kind==Kind::ShapeRejected);
 assert(get(228,0,0,0).kind==Kind::ShapeRejected);
 assert(get(229,0,ptr,0).kind==Kind::Success);
 assert(get(229,0,0,0).kind==Kind::Success);
 assert(get(96,ptr,0,0).kind==Kind::Success);
 LinuxX64Timeval tv{};
 std::memcpy(&tv,reinterpret_cast<void*>(ptr),sizeof(tv));
 assert(tv.secs>0&&tv.usecs>=0&&tv.usecs<1000000);
 assert(get(96,ptr,ptr,0).kind==Kind::ShapeRejected);
 assert(get(201,ptr,0,0).kind==Kind::Success);
 assert(get(24,0,0,0).kind==Kind::Success);
 assert(get(9999,ptr,8,1).kind==Kind::NotMatched);
 // Preserve W^X and guest write rights after memory protection changes.
 assert(maps.protect(uint64_t(guest),4096,PROT_READ)==0);
 assert(!maps.owned_writable_range(ptr,8));
 assert(get(318,ptr,8,1).kind==Kind::ShapeRejected);
 assert(maps.protect(uint64_t(guest),4096,PROT_READ|PROT_WRITE)==0);
 assert(maps.owned_writable_range(ptr,8));
 r=get(318,ptr,8,1);
 assert(r.kind==Kind::Success);
 assert(maps.unmap(uint64_t(guest),4096)==0);
 assert(!maps.owned_writable_range(ptr,8));
 assert(get(318,ptr,8,1).kind==Kind::ShapeRejected);
 std::puts("R3D31_GUEST_GETRANDOM_CLOCK_TIME_SCHED_AND_GUEST_MMAP_WRITE_OWNERSHIP_PASS");
}
