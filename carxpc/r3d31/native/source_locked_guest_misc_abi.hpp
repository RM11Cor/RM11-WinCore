// SPDX-License-Identifier: MIT
// R3D31: proactively prepared source-locked x86_64 Linux guest ABI calls.
//
// Real R3D30 device trace: 40/40 independent preflight, then 31 successful
// original ELF source witnesses; the 32nd original libc syscall is
// getrandom(318, guest_rw_mmap+offset, 8, GRND_NONBLOCK=1).
//
// Implements six *standard* x86-64 Linux calls without synthetic witnesses:
//   getrandom 318, clock_gettime 228, clock_getres 229,
//   gettimeofday 96, time 201, sched_yield 24.
// Each original guest syscall must still pass the existing 0F 05 ELF
// source proof BEFORE reaching this dispatch. For mutable guest output:
// only mapped guest regions that our live mmap registry proves globally
// writable (conservative) or the separately preverified owned guest stack.
// Never forward guest pointers to Android host. No pseudo RNG or fabricated
// entropy. No cross-host ABI pointer sharing. Unknown shapes fail closed.
#pragma once
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cerrno>
#include <cstring>
#include <ctime>
#include <sys/random.h>
#include <sys/time.h>
#include <sched.h>
#include <time.h>
namespace carx_r3d31 {
constexpr uint64_t kLinuxGetrandom=318;
constexpr uint64_t kLinuxClockGettime=228,kLinuxClockGetres=229;
constexpr uint64_t kLinuxGettimeofday=96,kLinuxTime=201,kLinuxSchedYield=24;
constexpr uint64_t kMaxReadEntropy=256,kGrndNonblock=1;
enum class Kind:uint8_t{NotMatched,Success,ShapeRejected};
struct Result{Kind kind{Kind::NotMatched};int64_t result{0};};
struct LinuxX64Timespec{int64_t secs,nsecs;};
struct LinuxX64Timeval{int64_t secs,usecs;};
static_assert(sizeof(LinuxX64Timespec)==16);
static_assert(sizeof(LinuxX64Timeval)==16);
inline bool clock_supported(uint64_t clock)noexcept {
 return clock==0 || clock==1 || clock==4 ||
        clock==5 || clock==6 || clock==7;
}
template<class Writable>
inline Result source_locked_dispatch(uint64_t nr,uint64_t arg0,
            uint64_t arg1,uint64_t arg2,Writable canWrite)noexcept {
 if(nr==kLinuxGetrandom){
   if(arg1>kMaxReadEntropy||arg2>kGrndNonblock)
     return {Kind::ShapeRejected,0};
   if(arg1==0)return {Kind::Success,0};
   if(!canWrite(arg0,arg1))return {Kind::ShapeRejected,0};
   // Host syscall observes an exclusively LOCAL bounded temporary buffer.
   // Linux short reads and negative EAGAIN/EINTR are returned as-is.
   unsigned char entropy[kMaxReadEntropy]{};
   const ssize_t n=::getrandom(entropy,static_cast<size_t>(arg1),
                                static_cast<unsigned>(arg2));
   if(n<0)return {Kind::Success,-int64_t(errno)};
   if(n>static_cast<ssize_t>(arg1))
     return {Kind::ShapeRejected,0};
   std::memcpy(reinterpret_cast<void*>(static_cast<uintptr_t>(arg0)),
              entropy,static_cast<size_t>(n));
   return {Kind::Success,n};
 }
 if(nr==kLinuxClockGettime||nr==kLinuxClockGetres){
   if(!clock_supported(arg0))
     return {Kind::ShapeRejected,0};
   if(nr==kLinuxClockGetres&&arg1==0)
     return {Kind::Success,0};
   if(!canWrite(arg1,sizeof(LinuxX64Timespec)))
     return {Kind::ShapeRejected,0};
   struct timespec host{};
   int res=nr==kLinuxClockGettime?
       ::clock_gettime(static_cast<clockid_t>(arg0),&host):
       ::clock_getres(static_cast<clockid_t>(arg0),&host);
   if(res<0)return {Kind::Success,-int64_t(errno)};
   const LinuxX64Timespec ts{int64_t(host.tv_sec),int64_t(host.tv_nsec)};
   std::memcpy(reinterpret_cast<void*>(static_cast<uintptr_t>(arg1)),
               &ts,sizeof(ts));
   return {Kind::Success,0};
 }
 if(nr==kLinuxGettimeofday){
   // Deprecated Linux timezone pointer requires a separate guest ABI.
   if(arg1!=0)return {Kind::ShapeRejected,0};
   if(arg0==0)return {Kind::Success,0};
   if(!canWrite(arg0,sizeof(LinuxX64Timeval)))
     return {Kind::ShapeRejected,0};
   struct timeval host{};
   if(::gettimeofday(&host,nullptr)<0)
     return {Kind::Success,-int64_t(errno)};
   const LinuxX64Timeval tv{int64_t(host.tv_sec),int64_t(host.tv_usec)};
   std::memcpy(reinterpret_cast<void*>(static_cast<uintptr_t>(arg0)),
               &tv,sizeof(tv));
   return {Kind::Success,0};
 }
 if(nr==kLinuxTime){
   if(arg0!=0&&!canWrite(arg0,sizeof(int64_t)))
     return {Kind::ShapeRejected,0};
   const time_t now=::time(nullptr);
   if(now==static_cast<time_t>(-1))
     return {Kind::Success,-int64_t(errno)};
   const int64_t sec=int64_t(now);
   if(arg0)std::memcpy(reinterpret_cast<void*>(static_cast<uintptr_t>(arg0)),
                       &sec,sizeof(sec));
   return {Kind::Success,sec};
 }
 if(nr==kLinuxSchedYield){
   const int res=::sched_yield();
   return {Kind::Success,res<0?-int64_t(errno):0};
 }
 return {};
}
} // namespace carx_r3d31
