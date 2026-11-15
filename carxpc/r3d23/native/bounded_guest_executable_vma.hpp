// SPDX-License-Identifier: MIT
// R3D23: precise bounded dynamic x86 guest *executable* VMA registry for FEX.
//
// FEXCore's Decoder::CheckRangeExecutable calls SyscallHandler's
// QueryGuestExecutableRange, NOT merely mmap/mprotect kernel permissions.
// Earlier R3D19 mapped libc RX but the handler reported Wine and ld.so only;
// the decoder consequently generated a #PF instruction-fetch protection
// fault (0x15) upon entering the mapped libc code. This registry tracks the
// PROT_EXEC portions of successful *managed guest* maps/protect/unmap.
//
// Registry never makes a host mapping executable. Host kernel mmap/mprotect
// validation is performed FIRST, and W+X is denied by GuestMappings. On
// failure to track a new mapping the isolated worker must fail closed.
#pragma once
#include <array>
#include <cstdint>
#include <cstddef>
#include <limits>
namespace carx_r3d23 {
constexpr size_t kMaxGuestExecRanges=128;
struct ExecVMA {uint64_t base{0};uint64_t length{0};};
class BoundedExecVMAs final {
 std::array<ExecVMA,kMaxGuestExecRanges> regions{};
 size_t count{0};
public:
 size_t size()const noexcept{return count;}
 ExecVMA find(uint64_t address)const noexcept {
   for(size_t i=0;i<count;++i) {
     const auto& r=regions[i];
     if(address>=r.base && address-r.base<r.length)return r;
   }
   return {};
 }
 // A successful map, protect, or unmap replaces permissions on [addr,end).
 // Split existing RX regions conservatively. Never confuse a reserved
 // anonymous parent VMA with child executable libc file segments.
 bool replace_permissions(uint64_t addr,uint64_t length,
                          bool executable)noexcept {
   if(!length || addr>std::numeric_limits<uint64_t>::max()-length ||
      (addr&4095)!=0 || (length&4095)!=0)return false;
   const uint64_t end=addr+length;
   std::array<ExecVMA,kMaxGuestExecRanges> next{};
   size_t n=0;
   const auto add=[&](uint64_t start,uint64_t len)->bool{
     if(!len)return true;
     if(n>=next.size())return false;
     next[n++]={start,len};
     return true;
   };
   for(size_t i=0;i<count;++i){
     const ExecVMA old=regions[i];
     if(!old.length || old.base>UINT64_MAX-old.length)return false;
     const uint64_t oldEnd=old.base+old.length;
     if(end<=old.base || addr>=oldEnd){
       if(!add(old.base,old.length))return false;
     } else {
       // Remove entire overlap, retaining independently executable sides.
       if(old.base<addr && !add(old.base,addr-old.base))return false;
       if(end<oldEnd && !add(end,oldEnd-end))return false;
     }
   }
   if(executable && !add(addr,length))return false;
   regions=next;
   count=n;
   return true;
 }
};
} // namespace carx_r3d23
