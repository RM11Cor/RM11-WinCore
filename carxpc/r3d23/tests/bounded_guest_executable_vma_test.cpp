#include "carxpc/r3d23/native/bounded_guest_executable_vma.hpp"
#include "carxpc/r3d19/native/unified_guest_libc_abi.hpp"
#include <cassert>
#include <cstdio>
#include <sys/mman.h>
int main(){
 using namespace carx_r3d23;
 BoundedExecVMAs v{};
 assert(!v.replace_permissions(0x1001,4096,true));
 assert(!v.replace_permissions(0x1000,0,true));
 assert(v.find(0x5000).length==0);
 // Host allocates a large reserved anonymous guest span.
 carx_r3d19::GuestMappings mappings{};
 const auto raw=mappings.map(-1,false,0,65536,PROT_NONE,
        carx_r3d19::kLinuxMapPrivate|carx_r3d19::kLinuxMapAnonymous,
        ~uint64_t(0),0);
 assert(raw>0);
 const uint64_t base=uint64_t(raw);
 // Only a subrange receives real host RX permission.
 assert(mappings.protect(base+0x2000,0x4000,PROT_READ|PROT_EXEC)==0);
 assert(v.replace_permissions(base+0x2000,0x4000,true));
 assert(v.find(base+0x1000).length==0);
 assert(v.find(base+0x2000).base==base+0x2000);
 assert(v.find(base+0x5FFF).length==0x4000);
 assert(v.find(base+0x6000).length==0);
 // The FEX executable decoder must not see read/write non-exec mappings.
 assert(mappings.protect(base+0x3000,0x1000,PROT_READ|PROT_WRITE)==0);
 assert(v.replace_permissions(base+0x3000,0x1000,false));
 assert(v.find(base+0x2FFF).length==0x1000);
 assert(v.find(base+0x3000).length==0);
 assert(v.find(base+0x4000).base==base+0x4000);
 // Re-expose only after host kernel mprotect succeeded.
 assert(mappings.protect(base+0x3000,0x1000,PROT_READ|PROT_EXEC)==0);
 assert(v.replace_permissions(base+0x3000,0x1000,true));
 assert(v.find(base+0x3000).length==0x1000);
 assert(mappings.protect(base+0x3000,0x1000,
                         PROT_WRITE|PROT_EXEC)==-EACCES);
 // An unsuccessful map/protect NEVER introduces an FEX RX range.
 assert(v.find(base+0x9000).length==0);
 assert(v.replace_permissions(base+0x2000,0x4000,false));
 assert(v.find(base+0x3000).length==0);
 assert(mappings.unmap(base,65536)==0);
 std::puts("R3D23_FEX_GUEST_RX_VMA_TRACKING_SPLIT_REVOKE_AND_HOST_WX_UNIT_PASS");
}
