// SPDX-License-Identifier: MIT
// R3D33: add 24 independent source-owned Linux guest path preflight cases.
// 40(rootfs) +24(misc ABI)+16(mmap perms)+24(path/heap)=104 preflights.
// No preflight case pretends to be an executed x86 guest syscall.
#pragma once
#include "carxpc/r3d33/native/owned_guest_path_and_vfs.hpp"
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <sys/mman.h>
namespace carx_r3d33 {
struct PathPreflight24{
 unsigned total{0},passed{0},failed{0};
 bool ready()const noexcept{return total==24&&failed==0;}
};
inline bool independent_path_case(unsigned index) noexcept {
 constexpr size_t kBytes=4096;
 char* const area=static_cast<char*>(::mmap(nullptr,kBytes,
    PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0));
 if(area==MAP_FAILED)return false;
 const uint64_t lo=reinterpret_cast<uintptr_t>(area),hi=lo+kBytes;
 std::memset(area,0,kBytes);
 const auto canRead=[=](uint64_t p,uint64_t n){
   return p>=lo&&p<hi&&n>0&&n<=hi-p;
 };
 auto call=[&](uint64_t ptr){
   return capture_guest_owned_path(ptr,canRead);
 };
 bool okay=false;
 switch(index){
 case 0:
   std::strcpy(area,"/usr");
   okay=call(lo).status==PathStatus::Okay;break;
 case 1:
   std::strcpy(area,"/proc/self/exe");
   okay=std::strcmp(call(lo).path,"/proc/self/exe")==0;break;
 case 2:
   std::strcpy(area,"/usr/lib/wine/wine64");
   okay=call(lo).size==20;break;
 case 3:
   std::strcpy(area,"relative");
   okay=call(lo).status==PathStatus::Okay;break;
 case 4:
   std::strcpy(area,"/usr\nlib");
   okay=call(lo).status==PathStatus::InvalidAscii;break;
 case 5:
   area[0]='a';area[1]=char(0xff);area[2]=0;
   okay=call(lo).status==PathStatus::InvalidAscii;break;
 case 6:
   area[0]=0;
   okay=call(lo).status==PathStatus::InvalidAscii;break;
 case 7:
   std::memset(area,'A',256);
   okay=call(lo).status==PathStatus::TooLong;break;
 case 8:okay=call(0).status==PathStatus::Unowned;break;
 case 9:okay=call(lo-1).status==PathStatus::Unowned;break;
 case 10:
   area[kBytes-1]='x';
   okay=call(hi-1).status==PathStatus::Unowned;break;
 case 11:okay=call(UINT64_MAX-12).status==PathStatus::Unowned;break;
 case 12:
   area[0]='A';area[1]=0;
   okay=call(lo).size==1;break;
 case 13:
   std::strcpy(area,"/lib/../etc");
   okay=call(lo).status==PathStatus::Okay;break;
 case 14:
   std::strcpy(area,"/usr//lib");
   okay=call(lo).size==9;break;
 case 15:
   std::strcpy(area,"/usr/.hidden");
   okay=call(lo).status==PathStatus::Okay;break;
 case 16:okay=brk_readable(lo+100,8,lo,hi);break;
 case 17:okay=!brk_readable(hi-4,8,lo,hi);break;
 case 18:okay=!brk_readable(lo-1,1,lo,hi);break;
 case 19:okay=!brk_readable(lo,0,lo,hi);break;
 case 20:okay=brk_readable(lo,4096,lo,hi);break;
 case 21:okay=!brk_readable(lo,1,0,hi);break;
 case 22:okay=!brk_readable(lo+1,4096,lo,hi);break;
 case 23:
   std::memset(area,'a',255);area[255]=0;
   okay=call(lo).status==PathStatus::Okay&&call(lo).size==255;break;
 default:break;
 }
 ::munmap(area,kBytes);
 return okay;
}
template<class Logger> PathPreflight24 run_preflight24(Logger logger)noexcept{
 PathPreflight24 p{};
 for(unsigned i=0;i<24;++i){
   const bool okay=independent_path_case(i);
   ++p.total;if(okay)++p.passed;else ++p.failed;
   char line[104]{};
   std::snprintf(line,sizeof(line),
       "%s_R3D33_GUEST_VM_PATH_CASE_%02u",okay?"N53":"E_R3D33",i);
   logger(line);
 }
 char summary[108]{};
 std::snprintf(summary,sizeof(summary),
       "N53_GUEST_VM_PATH_PREFLIGHT_TOTAL_%u_PASS_%u_FAIL_%u",
       p.total,p.passed,p.failed);
 logger(summary);return p;
}
} // namespace carx_r3d33
