// SPDX-License-Identifier: MIT
// R3D24: guest-only, source-verified protection authority for ELF PT_LOADs
// mapped before the dynamic Linux ABI GuestMappings manager was constructed.
//
// Original Wine and GNU ld.so PT_LOADs were fixed-address MAP_FIXED_NOREPLACE
// reserved, copied, sealed with exact ELF PF_R/W/X and SHA-authenticated.
// Source-locked GNU ld.so now needs mprotect(..., PROT_READ) on Wine RELRO.
// Treating that range as unowned because it is absent from *dynamic* mmap
// manager is incorrect. This class instead registers ONLY verified existing
// ELF PT_LOAD page spans, protects monotonic subranges and never grants new
// rights, maps memory, forwards arbitrary host pointers, or adds RWX.
#pragma once
#include <array>
#include <cstdint>
#include <cstddef>
#include <cerrno>
#include <sys/mman.h>
namespace carx_r3d24 {
constexpr size_t kMaxSealedSegments=96;
struct SealedSegment {
  uint64_t base{}, length{};
  int perms{};
};
class SourceSealedELFProtections final {
 std::array<SealedSegment,kMaxSealedSegments> segments{};
 size_t count{0};
public:
 size_t size() const noexcept{return count;}
 bool register_sealed_ptload(uint64_t base,uint64_t length,int perms)noexcept {
  if(!base || !length || (base&4095ULL) || (length&4095ULL) ||
     base>UINT64_MAX-length ||
     (perms&~(PROT_READ|PROT_WRITE|PROT_EXEC))!=0 ||
     ((perms&PROT_WRITE)&&(perms&PROT_EXEC)) ||
     count>=segments.size())return false;
  for(size_t i=0;i<count;++i){
   auto other=segments[i];
   if(base<other.base+other.length && other.base<base+length)
     return false;
  }
  segments[count++]={base,length,perms};
  return true;
 }
 // The decoder may request only executable guest pages, never holes/RELRO.
 SealedSegment executable_at(uint64_t addr)const noexcept {
  for(size_t i=0;i<count;++i){
   const auto& r=segments[i];
   if((r.perms&PROT_EXEC) && addr>=r.base &&
      addr-r.base<r.length)return r;
  }
  return {};
 }
 bool covers(uint64_t addr,uint64_t len)const noexcept {
  if(!len || addr>UINT64_MAX-len)return false;
  for(size_t i=0;i<count;++i){
   const auto& r=segments[i];
   if(addr>=r.base && addr-r.base<=r.length &&
      len<=r.length-(addr-r.base))return true;
  }
  return false;
 }
 // Success requires a SINGLE owned already-sealed PT_LOAD span; the proposed
 // permissions are a subset of its current per-page rights (RELRO shrink).
 // Split registry before calling kernel. No host mmap or new permissions.
 int64_t narrow_protection(uint64_t addr,uint64_t len,int newPerms)noexcept {
  if(!len || (addr&4095ULL) || (len&4095ULL) ||
     addr>UINT64_MAX-len)return -EINVAL;
  if((newPerms&~(PROT_READ|PROT_WRITE|PROT_EXEC)) ||
     ((newPerms&PROT_WRITE)&&(newPerms&PROT_EXEC)))
    return -EACCES;
  size_t target=count;
  for(size_t i=0;i<count;++i){
    const auto& r=segments[i];
    if(addr>=r.base && addr-r.base<r.length &&
       len<=r.length-(addr-r.base)) {
      target=i;break;
    }
  }
  if(target==count)return -EACCES;
  const auto old=segments[target];
  if((newPerms&~old.perms)!=0)return -EACCES; // strictly monotonic
  if(newPerms==old.perms)return 0; // already sealed, no side effects
  // Splitting one segment needs at most two extra entries.
  const uint64_t left=addr-old.base;
  const uint64_t right=old.length-left-len;
  const size_t required=(left?1:0)+(right?1:0)+1;
  if(count-1+required>segments.size())return -ENOMEM;
  std::array<SealedSegment,kMaxSealedSegments> revised{};
  size_t n=0;
  for(size_t i=0;i<count;++i){
    if(i!=target){revised[n++]=segments[i];continue;}
    if(left)revised[n++]={old.base,left,old.perms};
    revised[n++]={addr,len,newPerms};
    if(right)revised[n++]={addr+len,right,old.perms};
  }
  // No callback to host set_tid_address etc; this only changes previously
  // reserved, source-authenticated guest PT_LOAD page protection.
  if(::mprotect(reinterpret_cast<void*>(static_cast<uintptr_t>(addr)),
                static_cast<size_t>(len),newPerms)!=0)return -errno;
  segments=revised;count=n;
  return 0;
 }
};
} // namespace carx_r3d24
