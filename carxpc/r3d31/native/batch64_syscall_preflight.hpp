// SPDX-License-Identifier: MIT
// R3D31: 24 additional independent syscall ABI preflight cases. Added to
// R3D30's 40 filesystem cases, to collect 64 results in a single launch.
// All 24 cases are LOCAL ABI validation, not executed x86 source witnesses.
// Authentic source-verified FEX syscall sequence remains a separate 512 cap.
#pragma once
#include "carxpc/r3d31/native/source_locked_guest_misc_abi.hpp"
#include <cstdint>
#include <cstdio>
#include <sys/mman.h>
namespace carx_r3d31 {
struct Preflight24{
 unsigned total{0},passed{0},failed{0};
 bool ready()const noexcept{return total==24&&failed==0;}
};
template<class Logger> Preflight24 run_preflight_24(Logger logger)noexcept{
 Preflight24 out{};
 auto* alloc=static_cast<unsigned char*>(::mmap(
    nullptr,4096,PROT_READ|PROT_WRITE,MAP_ANONYMOUS|MAP_PRIVATE,-1,0));
 if(alloc==MAP_FAILED){
   logger("E_R3D31_PREFLIGHT24_MEMORY_ALLOCATION_FAILED");return out;
 }
 const uint64_t low=reinterpret_cast<uintptr_t>(alloc),hi=low+4096;
 const auto writable=[=](uint64_t addr,uint64_t size){
   return size>0&&addr>=low&&addr<hi&&size<=hi-addr;
 };
 const uint64_t ptr=low+2048;
 const auto call=[&](uint64_t nr,uint64_t a,uint64_t bb,uint64_t c){
   return source_locked_dispatch(nr,a,bb,c,writable);
 };
 auto result=[&](bool ok,int expected){
   const auto index=out.total++;
   if(ok)++out.passed;else ++out.failed;
   char line[120]{};
   std::snprintf(line,sizeof(line),
        "%s_R3D31_PREFLIGHT_ABI_CASE_%02u_EXPECT_%d",
        ok?"N45":"E_R3D31",index,expected);
   logger(line);
 };
 auto validRandom=[](Result rr,uint64_t max){
    return rr.kind==Kind::Success&&
          (rr.result>=0&&uint64_t(rr.result)<=max||
           rr.result==-EAGAIN||rr.result==-EINTR);
 };
 result(validRandom(call(318,ptr,8,1),8),318);      // 00
 result(validRandom(call(318,ptr,8,0),8),318);      // 01
 result(call(318,0,0,1).kind==Kind::Success,318);   // 02
 result(call(318,0,8,1).kind==Kind::ShapeRejected,318); // 03
 result(call(318,ptr,257,1).kind==Kind::ShapeRejected,318); // 04
 result(call(318,ptr,8,2).kind==Kind::ShapeRejected,318); // 05
 result(call(318,hi-4,8,1).kind==Kind::ShapeRejected,318); // 06
 result(validRandom(call(318,ptr,256,1),256),318); // 07
 result(validRandom(call(318,ptr,16,1),16),318);   // 08
 result(validRandom(call(318,ptr,32,1),32),318);   // 09
 result(call(228,0,ptr,0).kind==Kind::Success,228); // 10
 result(call(228,1,ptr,0).kind==Kind::Success,228); // 11
 result(call(228,4,ptr,0).kind==Kind::Success,228); // 12
 result(call(228,1234,ptr,0).kind==Kind::ShapeRejected,228); //13
 result(call(228,1,0,0).kind==Kind::ShapeRejected,228); //14
 result(call(229,1,ptr,0).kind==Kind::Success,229); //15
 result(call(229,0,0,0).kind==Kind::Success,229);   //16
 result(call(96,ptr,0,0).kind==Kind::Success,96);   //17
 result(call(96,ptr,ptr,0).kind==Kind::ShapeRejected,96); //18
 result(call(96,0,0,0).kind==Kind::Success,96);     //19
 result(call(201,0,0,0).kind==Kind::Success,201);   //20
 result(call(201,ptr,0,0).kind==Kind::Success,201); //21
 result(call(24,0,0,0).kind==Kind::Success,24);     //22
 result(call(12345,ptr,8,0).kind==Kind::NotMatched,12345);//23
 ::munmap(alloc,4096);
 char text[126]{};
 std::snprintf(text,sizeof(text),
        "N45_PREFLIGHT24_SUMMARY_TOTAL_%u_PASS_%u_FAIL_%u",
        out.total,out.passed,out.failed);
 logger(text);
 return out;
}
} // namespace carx_r3d31
