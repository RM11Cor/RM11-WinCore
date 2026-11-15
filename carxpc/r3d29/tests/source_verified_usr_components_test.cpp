#include "carxpc/r3d29/native/source_verified_usr_components.hpp"
#include <cassert>
#include <cerrno>
#include <cstdio>
#include <initializer_list>
#include <cstring>
#include <cstdint>
#include <sys/mman.h>
int main() {
 using namespace carx_r3d29;
 constexpr size_t kStack=65536;
 void* mem=::mmap(nullptr,kStack,PROT_READ|PROT_WRITE,
                 MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
 assert(mem!=MAP_FAILED);
 const uint64_t begin=uint64_t(reinterpret_cast<uintptr_t>(mem));
 const uint64_t end=begin+kStack;
 char* const dest=reinterpret_cast<char*>(end-1024);
 std::memset(dest,0x4d,1024);
 for(const char* path:{"/","/usr","/usr/","/usr/lib","/usr/lib/",
                        "/usr/lib/wine","/usr/lib/wine/"}) {
   const auto r=query_readlink_non_symlink(
     path,reinterpret_cast<uintptr_t>(dest),1023,begin,end,true);
   assert(r.kind==Kind::VerifiedNonSymlinkDirectory);
   assert(r.guestReturn==-EINVAL);
   for(int i=0;i<1024;++i)assert(dest[i]=='M');
 }
 for(const char* path:{"/lib","/usr/share","/usr/lib/wine/wine64",
                       "/proc","/proc/self","/proc/self/exe",
                       "/usr/lib/wine/unknown.so","/usr/bin/../lib","/tmp"}) {
   const auto r=query_readlink_non_symlink(
     path,reinterpret_cast<uintptr_t>(dest),1023,begin,end,true);
   assert(r.kind==Kind::Unknown);
 }
 assert(query_readlink_non_symlink("/usr",reinterpret_cast<uintptr_t>(dest),
         1023,begin,end,false).kind==Kind::MissingOriginalWineEvidence);
 assert(query_readlink_non_symlink("/usr",begin-1,
         1023,begin,end,true).kind==Kind::BadOutputRegion);
 assert(query_readlink_non_symlink("/usr",end-7,
         1023,begin,end,true).kind==Kind::BadOutputRegion);
 assert(query_readlink_non_symlink("/usr",reinterpret_cast<uintptr_t>(dest),
         0,begin,end,true).kind==Kind::BadOutputRegion);
 assert(query_readlink_non_symlink("/usr",reinterpret_cast<uintptr_t>(dest),
         4097,begin,end,true).kind==Kind::BadOutputRegion);
 assert(::munmap(mem,kStack)==0);
 std::puts("R3D29_GUEST_USR_SOURCE_VERIFIED_READLINK_NEG_EINVAL_NO_OUTPUT_WRITE_PASS");
}
