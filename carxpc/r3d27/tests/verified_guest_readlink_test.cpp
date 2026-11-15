#include "carxpc/r3d27/native/verified_guest_readlink.hpp"
#include <array>
#include <cassert>
#include <cstdio>
#include <cstring>
#include <sys/mman.h>
int main(){
 using namespace carx_r3d27;
 constexpr uint64_t kStackSize=65536;
 void* p=::mmap(nullptr,kStackSize,PROT_READ|PROT_WRITE,
               MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
 assert(p!=MAP_FAILED);
 const uint64_t low=reinterpret_cast<uintptr_t>(p),high=low+kStackSize;
 auto* buf=reinterpret_cast<char*>(low+kStackSize-1024);
 std::memset(buf,0x5a,1024);
 // Native Linux readlink does NOT append NUL; writes count of bytes only.
 auto r=write_source_bound_proc_self_exe(
   "/proc/self/exe",reinterpret_cast<uintptr_t>(buf),
   1023,low,high);
 assert(r.code==Status::Success);
 assert(r.bytes==sizeof(kGuestWineExec)-1);
 assert(std::memcmp(buf,kGuestWineExec,r.bytes)==0);
 assert(buf[r.bytes]=='Z');
 assert(buf[1022]=='Z');
 // Truncation copies only capacity bytes and returns exact byte count.
 std::memset(buf,0x5a,1024);
 r=write_source_bound_proc_self_exe(
   "/proc/self/exe",reinterpret_cast<uintptr_t>(buf),4,low,high);
 assert(r.code==Status::Success && r.bytes==4);
 assert(std::memcmp(buf,"/usr",4)==0 && buf[4]=='Z');
 // All untrusted paths rejected, including host /proc/self/exe aliases.
 assert(write_source_bound_proc_self_exe(
   "/proc/self/fd/1",reinterpret_cast<uintptr_t>(buf),1023,low,high).code
   ==Status::NotVerifiedGuestProcSelfExe);
 assert(write_source_bound_proc_self_exe(
   "/proc/1/exe",reinterpret_cast<uintptr_t>(buf),1023,low,high).code
   ==Status::NotVerifiedGuestProcSelfExe);
 assert(write_source_bound_proc_self_exe(
   "/sdcard/exe",reinterpret_cast<uintptr_t>(buf),1023,low,high).code
   ==Status::NotVerifiedGuestProcSelfExe);
 assert(write_source_bound_proc_self_exe(
   "/proc/self/exe",low-1,1023,low,high).code
   ==Status::InvalidDestination);
 assert(write_source_bound_proc_self_exe(
   "/proc/self/exe",high-10,1023,low,high).code
   ==Status::InvalidDestination);
 assert(write_source_bound_proc_self_exe(
   "/proc/self/exe",low,0,low,high).code
   ==Status::InvalidCount);
 assert(write_source_bound_proc_self_exe(
   "/proc/self/exe",low,4097,low,high).code
   ==Status::InvalidCount);
 assert(::munmap(p,kStackSize)==0);
 std::puts("R3D27_BOUND_X86_GUEST_PROC_SELF_EXE_READLINK_NO_NUL_HOST_FWD_TEST_PASS");
}
