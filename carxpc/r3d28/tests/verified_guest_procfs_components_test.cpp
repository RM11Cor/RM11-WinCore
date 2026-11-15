#include "carxpc/r3d28/native/verified_guest_procfs_components.hpp"
#include <cassert>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cerrno>
#include <sys/mman.h>
int main(){
 using namespace carx_r3d28;
 constexpr uint64_t bytes=65536;
 void* mem=::mmap(nullptr,bytes,PROT_READ|PROT_WRITE,
                  MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
 assert(mem!=MAP_FAILED);
 uint64_t start=static_cast<uint64_t>(reinterpret_cast<uintptr_t>(mem));
 uint64_t end=start+bytes;
 auto* dest=reinterpret_cast<char*>(start+bytes-1024);
 std::memset(dest,'Z',1024);
 const auto guestPid=24643ULL;
 auto result=resolve_known_procfs_component(
   "/proc",reinterpret_cast<uintptr_t>(dest),1023,start,end,guestPid);
 assert(result.kind==Kind::DirectoryNotSymlink &&
        result.guestReturn==-EINVAL);
 assert(dest[0]=='Z');
 result=resolve_known_procfs_component(
   "/proc/",reinterpret_cast<uintptr_t>(dest),1023,start,end,guestPid);
 assert(result.kind==Kind::DirectoryNotSymlink &&
        result.guestReturn==-EINVAL);
 assert(dest[0]=='Z');
 result=resolve_known_procfs_component(
   "/proc/self",reinterpret_cast<uintptr_t>(dest),1023,start,end,guestPid);
 assert(result.kind==Kind::SelfPidSymlink &&
        result.guestReturn==5);
 assert(std::memcmp(dest,"24643",5)==0 && dest[5]=='Z');
 std::memset(dest,'Z',1024);
 result=resolve_known_procfs_component(
   "/proc/24643",reinterpret_cast<uintptr_t>(dest),1023,start,end,guestPid);
 assert(result.kind==Kind::DirectoryNotSymlink &&
        result.guestReturn==-EINVAL && dest[0]=='Z');
 result=resolve_known_procfs_component(
   "/proc/24643/exe",reinterpret_cast<uintptr_t>(dest),
   1023,start,end,guestPid);
 assert(result.kind==Kind::ProcessExeSymlink &&
        result.guestReturn==
          static_cast<int64_t>(std::strlen(carx_r3d27::kGuestWineExec)));
 assert(std::memcmp(dest,carx_r3d27::kGuestWineExec,
                    static_cast<size_t>(result.guestReturn))==0);
 assert(dest[result.guestReturn]=='Z');
 // Truncation reads EXACT size, no trailing null terminator.
 std::memset(dest,'Z',1024);
 result=resolve_known_procfs_component(
   "/proc/self",reinterpret_cast<uintptr_t>(dest),2,start,end,guestPid);
 assert(result.kind==Kind::SelfPidSymlink && result.guestReturn==2);
 assert(dest[0]=='2' && dest[1]=='4' && dest[2]=='Z');
 // Earlier /proc/self/exe handler owns that single existing trusted path.
 assert(resolve_known_procfs_component(
   "/proc/self/exe",reinterpret_cast<uintptr_t>(dest),1023,
   start,end,guestPid).kind==Kind::Unknown);
 // No unverified host path, fd route, arbitrary pid accepted.
 assert(resolve_known_procfs_component(
   "/proc/1",reinterpret_cast<uintptr_t>(dest),1023,
   start,end,guestPid).kind==Kind::Unknown);
 assert(resolve_known_procfs_component(
   "/proc/self/fd/1",reinterpret_cast<uintptr_t>(dest),1023,
   start,end,guestPid).kind==Kind::Unknown);
 assert(resolve_known_procfs_component(
   "/proc/version",reinterpret_cast<uintptr_t>(dest),1023,
   start,end,guestPid).kind==Kind::Unknown);
 assert(resolve_known_procfs_component(
   "/etc/passwd",reinterpret_cast<uintptr_t>(dest),1023,
   start,end,guestPid).kind==Kind::Unknown);
 // Reject unowned output even for a directory with negative result.
 assert(resolve_known_procfs_component(
   "/proc",start-64,1023,start,end,guestPid).kind==
   Kind::InvalidGuestDestination);
 assert(resolve_known_procfs_component(
   "/proc",reinterpret_cast<uintptr_t>(dest),4097,start,end,guestPid).kind==
   Kind::InvalidGuestDestination);
 assert(resolve_known_procfs_component(
   "/proc",reinterpret_cast<uintptr_t>(dest),0,start,end,guestPid).kind==
   Kind::InvalidGuestDestination);
 assert(resolve_known_procfs_component(
   "/proc",reinterpret_cast<uintptr_t>(dest),1023,start,end,0).kind==
   Kind::Unknown);
 assert(::munmap(mem,bytes)==0);
 std::puts("R3D28_SOURCE_VERIFIED_GUEST_PROCFS_COMPONENT_READLINK_ERRNO_PID_EXE_TEST_PASS");
}
