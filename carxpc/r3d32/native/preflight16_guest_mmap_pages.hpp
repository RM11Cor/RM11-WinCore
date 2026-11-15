// SPDX-License-Identifier: MIT
// R3D32: additional 16 INDEPENDENT guest memory protection preflights.
// The original Linux loader reserves a large read-only anonymous region
// then MAP_FIXED copies individual RX/RO/RW ELF PT_LOAD pages inside it.
// A region-wide all-writable flag is incorrect: a libc RW data buffer may
// be inside the read-only reservation. R3D31 phone stopped getrandom318
// on this exact case (32 source-verified calls, 31 accepted). R3D32 tracks
// each guest page's last real map/protect rights. These 16 scenarios test
// independent page ownership and W^X; NOT 16 actual x86 syscalls.
#pragma once
#include "carxpc/r3d19/native/unified_guest_libc_abi.hpp"
#include <cstdint>
#include <cstdio>
#include <sys/mman.h>
namespace carx_r3d32 {
struct MmapResult16 {
 unsigned total{0},passed{0},failed{0};
 bool ready() const noexcept {return total==16&&failed==0;}
};
inline bool independent_case(unsigned idx)noexcept {
 using carx_r3d19::GuestMappings;
 constexpr uint64_t pg=4096;
 constexpr uint64_t mapFlags=carx_r3d19::kLinuxMapPrivate|
         carx_r3d19::kLinuxMapAnonymous;
 GuestMappings memory{};
 const int64_t got=memory.map(-1,false,0,8*pg,PROT_READ,mapFlags,
                              UINT64_MAX,0);
 if(got<=0)return false;
 const uint64_t base=static_cast<uint64_t>(got);
 const uint64_t rw=base+3*pg;
 bool good=true;
 const auto checked=[&](uint64_t p,uint64_t count)->bool {
   return memory.owned_writable_range(p,count);
 };
 if(idx==0) good=!checked(rw,8); // reserve is RO
 else {
   const int64_t overlay=memory.map(-1,false,rw,2*pg,
        PROT_READ|PROT_WRITE,
        mapFlags|carx_r3d19::kLinuxMapFixed,UINT64_MAX,0);
   if(overlay!=static_cast<int64_t>(rw))good=false;
   else switch(idx){
     case 1:good=checked(rw+8,8);break;
     case 2:good=checked(rw+pg+8,8);break;
     case 3:good=!checked(rw-8,8);break;
     case 4:good=!checked(rw-4,8);break;
     case 5:good=checked(rw+pg-4,8);break;
     case 6:good=!checked(rw+2*pg-4,8);break;
     case 7:
       good=(memory.protect(rw,pg,PROT_READ)==0 && !checked(rw+8,8));break;
     case 8:
       good=(memory.protect(rw,pg,PROT_READ)==0 &&
             checked(rw+pg+8,8));break;
     case 9:
       good=(memory.protect(rw,pg,PROT_READ)==0 &&
             memory.protect(rw,pg,PROT_READ|PROT_WRITE)==0 &&
             checked(rw+8,8));break;
     case 10:
       good=(memory.map(-1,false,rw,pg,PROT_READ|PROT_EXEC,
          mapFlags|carx_r3d19::kLinuxMapFixed,UINT64_MAX,0)==
          static_cast<int64_t>(rw) && !checked(rw+8,8));break;
     case 11:
       good=(memory.map(-1,false,rw,pg,PROT_READ,
           mapFlags|carx_r3d19::kLinuxMapFixed,UINT64_MAX,0)==
           static_cast<int64_t>(rw) &&
           memory.map(-1,false,rw,pg,PROT_READ|PROT_WRITE,
           mapFlags|carx_r3d19::kLinuxMapFixed,UINT64_MAX,0)==
           static_cast<int64_t>(rw) && checked(rw+8,8));break;
     case 12:good=!checked(base+8*pg,8);break;
     case 13:good=!checked(rw,0);break;
     case 14:
       good=(memory.protect(base,8*pg,PROT_READ|PROT_WRITE)==0 &&
             checked(base+8,8)&&checked(rw,8)&&
             checked(base+8*pg-8,8));break;
     case 15:
       good=(memory.protect(base,8*pg,PROT_READ|PROT_WRITE)==0 &&
             memory.protect(base,8*pg,PROT_READ)==0 &&
             !checked(rw,8));break;
     default:good=false;break;
   }
 }
 const bool unmap=memory.unmap(base,8*pg)==0;
 return good&&unmap&&!checked(rw,8);
}
template<class Logger> MmapResult16 run_preflight16(Logger logger)noexcept{
 MmapResult16 out{};
 for(unsigned i=0;i<16;++i){
   const bool ok=independent_case(i);
   ++out.total;
   if(ok)++out.passed;else ++out.failed;
   char line[116]{};
   std::snprintf(line,sizeof(line),
      "%s_R3D32_PREFLIGHT_MMAP_PAGE_CASE_%02u",
      ok?"N49":"E_R3D32",i);
   logger(line);
 }
 char summary[130]{};
 std::snprintf(summary,sizeof(summary),
    "N49_MMAP_PAGE_PREFLIGHT_TOTAL_%u_PASS_%u_FAIL_%u",
    out.total,out.passed,out.failed);
 logger(summary);
 return out;
}
} // namespace carx_r3d32
