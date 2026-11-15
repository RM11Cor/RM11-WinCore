#include "carxpc/r3d20/native/guest_fs_gs_tls.hpp"
#include <cassert>
#include <cstdio>
#include <cstring>
#include <sys/mman.h>
struct GuestX86State {uint64_t fs_cached{0},gs_cached{0};};
int main(){
 using namespace carx_r3d20;
 carx_r3d19::GuestMappings vm;
 const auto v=vm.map(-1,false,0,8192,PROT_READ|PROT_WRITE,
       carx_r3d19::kLinuxMapPrivate|carx_r3d19::kLinuxMapAnonymous,
       ~uint64_t(0),0);
 assert(v>0);
 const uint64_t tlsptr=uint64_t(v)+0x1100;
 GuestX86State s{};
 const auto owned=[&](uint64_t a,uint64_t n){return vm.owned_range(a,n);};
 auto fs=dispatch_arch_prctl(s,kArchSetFs,tlsptr,owned);
 assert(fs.recognized && fs.returnValue==0 && fs.fsChanged &&
        s.fs_cached==tlsptr && s.gs_cached==0);
 auto gs=dispatch_arch_prctl(s,kArchSetGs,uint64_t(v)+8,owned);
 assert(gs.recognized && gs.returnValue==0 && gs.gsChanged);
 assert(s.gs_cached==uint64_t(v)+8);
 assert(dispatch_arch_prctl(s,kArchSetFs,0,owned).returnValue==-EFAULT);
 assert(dispatch_arch_prctl(s,kArchSetFs,0x12345,owned).returnValue==-EFAULT);
 assert(dispatch_arch_prctl(s,kArchSetGs,0x8000000000000000ULL,owned).returnValue==-EFAULT);
 assert(!dispatch_arch_prctl(s,0x7777,tlsptr,owned).recognized);
 const uint64_t top=carx_r3d16::kStackTop;
 void *stack=::mmap(reinterpret_cast<void*>(top-carx_r3d16::kStackSize),
                     carx_r3d16::kStackSize,PROT_READ|PROT_WRITE,
                     MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0);
 assert(stack==reinterpret_cast<void*>(top-carx_r3d16::kStackSize));
 const uint64_t dest=top-24;
 auto getfs=dispatch_arch_prctl(s,kArchGetFs,dest,owned);
 assert(getfs.recognized && getfs.returnValue==0);
 uint64_t actual=0;
 std::memcpy(&actual,reinterpret_cast<void*>(uintptr_t(dest)),sizeof(actual));
 assert(actual==tlsptr);
 assert(dispatch_arch_prctl(s,kArchGetGs,top-7,owned).returnValue==-EFAULT);
 assert(dispatch_arch_prctl(s,kArchGetGs,0,owned).returnValue==-EFAULT);
 auto getgs=dispatch_arch_prctl(s,kArchGetGs,top-16,owned);
 assert(getgs.returnValue==0);
 std::memcpy(&actual,reinterpret_cast<void*>(uintptr_t(top-16)),sizeof(actual));
 assert(actual==uint64_t(v)+8);
 GuestX86State other{};
 assert(other.fs_cached==0 && other.gs_cached==0);
 assert(::munmap(stack,carx_r3d16::kStackSize)==0);
 assert(vm.unmap(uint64_t(v),8192)==0);
 std::puts("R3D20_FEX_GUEST_FS_GS_BASE_PRIVATELY_UPDATED_WITH_GUEST_TLS_STACK_VALIDATION_PASS");
}
