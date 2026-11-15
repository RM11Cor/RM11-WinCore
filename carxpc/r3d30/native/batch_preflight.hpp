// SPDX-License-Identifier: MIT
// 40 static preflight scenarios, independently logged. NOT 40 executed guest
// syscalls. Mandatory failures do not stop the preflight at first error.
// Only after all 40 are classified may the authenticated FEX guest run.
#pragma once
#include "carxpc/r3d30/native/guest_rootfs_readlink.hpp"
#include <array>
#include <cstdio>
#include <cstring>
#include <sys/mman.h>
namespace carx_r3d30 {
struct Readiness {
 uint32_t scenarios{0},passed{0},requiredFailures{0},optionalUnavailable{0};
 bool ready()const noexcept{return scenarios==40&&requiredFailures==0;}
};
struct PathExpectation{const char* path;bool requiredNonlink;};
inline constexpr PathExpectation kRootfsPaths[24]={
 {"/",true},{"/usr",true},{"/usr/lib",true},
 {"/usr/lib/wine",true},{"/usr/lib/wine/wine64",true},
 {"/usr/share",true},{"/usr/share/wine",true},
 {"/usr/share/wine/wine.inf",true},{"/tmp",true},
 {"/tmp/kernix-real-win32-smoke.exe",true},
 {"/lib",false},{"/lib/x86_64-linux-gnu",false},
 {"/lib/x86_64-linux-gnu/libc.so.6",false},
 {"/usr/lib/x86_64-linux-gnu",false},
 {"/usr/lib/x86_64-linux-gnu/libc.so.6",false},
 {"/etc",false},{"/etc/ld.so.cache",false},
 {"/usr/bin",false},{"/usr/bin/wine",false},
 {"/usr/lib/wine/wineserver",false},
 {"/usr/lib/wine/x86_64-unix",false},
 {"/usr/lib/wine/wineboot",false},
 {"/bin",false},{"/tmp/nonexistent-unverified-optional-test",false}
};
static_assert(sizeof(kRootfsPaths)/sizeof(kRootfsPaths[0])==24);
template<class Logger> Readiness run_matrix(int rootFd,Logger log)noexcept {
 Readiness m{};
 auto* mem=static_cast<char*>(::mmap(nullptr,65536,PROT_READ|PROT_WRITE,
                    MAP_PRIVATE|MAP_ANONYMOUS,-1,0));
 if(mem==MAP_FAILED){log("E_R3D30_PREFLIGHT_LOCAL_BUFFER_ALLOC");return m;}
 const uint64_t lo=reinterpret_cast<uintptr_t>(mem),hi=lo+65536;
 auto* dst=mem+65536-4096;
 const uint64_t addr=reinterpret_cast<uintptr_t>(dst);
 auto record=[&](int index,bool okay,int code,bool required,bool optionalMissing){
   ++m.scenarios;
   if(okay)++m.passed;
   else if(required)++m.requiredFailures;
   else if(optionalMissing)++m.optionalUnavailable;
   char line[112]{};
   std::snprintf(line,sizeof(line),"%s_R3D30_PREFLIGHT_CASE_%02d_CODE_%d",
     okay?"N40":(required?"E":"W40"),index,code);
   log(line);
 };
 for(int i=0;i<24;++i){
   std::memset(dst,'Z',4096);
   const auto r=resolve_readlink(rootFd,kRootfsPaths[i].path,addr,1023,lo,hi);
   const bool required=kRootfsPaths[i].requiredNonlink;
   const bool good=required?
      (r.status==Status::Resolved&&r.value==-EINVAL):
      (r.status!=Status::UntrustedRoot&&r.status!=Status::HostIOError&&
       r.status!=Status::InvalidGuestOutput);
   const bool unchanged=dst[0]=='Z'||(r.status==Status::Resolved&&r.value>=0);
   const bool okay=good&&unchanged;
   record(i,okay,int(r.status),required,!okay&&!required);
 }
 const char* const negatives[10]={"../usr","/../usr","/usr/../bin",
     "/usr//bin","/usr/./bin","usr/lib","//usr",
     "/usr/../../etc","/usr/lib/./wine","/usr/lib/wine/../wine64"};
 for(int j=0;j<10;++j){
   const auto v=resolve_readlink(rootFd,negatives[j],addr,1023,lo,hi);
   record(24+j,v.status==Status::InvalidGuestPath,int(v.status),true,false);
 }
 const uint64_t badOut[6]={0,lo-8,hi-8,hi,lo,addr};
 const uint64_t badSizes[6]={1023,1023,1023,1023,0,4097};
 for(int j=0;j<6;++j){
   const auto v=resolve_readlink(rootFd,"/usr",badOut[j],badSizes[j],lo,hi);
   record(34+j,v.status==Status::InvalidGuestOutput,int(v.status),true,false);
 }
 ::munmap(mem,65536);
 char summary[156]{};
 std::snprintf(summary,sizeof(summary),
   "N40_PREFLIGHT_SUMMARY_TOTAL_%u_PASS_%u_REQUIRED_FAIL_%u_OPTIONAL_UNAVAILABLE_%u",
   m.scenarios,m.passed,m.requiredFailures,m.optionalUnavailable);
 log(summary);
 return m;
}
} // namespace carx_r3d30
