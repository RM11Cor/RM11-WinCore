#pragma once
// SPDX-License-Identifier: MIT
// KERNIX G0 guest only x86_64 FS/TCB/DTV initial source libc TLS slice.
// This is an OWNED bounded fixture for real guest FEX arch_prctl tests,
// NOT a complete glibc TCB/DTV module registry and never alters host TLS.
#include "kernix_g2e_c3d7j_original_x86_static_tls_variant2_order_gate.h"
#include "kernix_g2e_c1_x86_linux_syscall_boundary.h"
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <sys/mman.h>
#include <unistd.h>
namespace kernix::g0::fsruntime {
struct DTVEntry final {uint64_t value=0,toFree=0;};
struct TCBPrefix final {uint64_t tcb=0,dtv=0,self=0;};
static_assert(sizeof(DTVEntry)==16 && sizeof(TCBPrefix)==24 &&
 offsetof(TCBPrefix,dtv)==8 && offsetof(TCBPrefix,self)==16);
class OwnedGuestFS final {
 public:
  OwnedGuestFS()=default;
  ~OwnedGuestFS(){(void)Release();}
  OwnedGuestFS(const OwnedGuestFS&)=delete;
  OwnedGuestFS& operator=(const OwnedGuestFS&)=delete;
  bool Install(const kernix::g2e::c3d7j::TLSModel& source) noexcept {
    if(region_!=MAP_FAILED || ::sysconf(_SC_PAGESIZE)!=4096 ||
       !source.sourceInitializerMatchesOriginalELF ||
       !source.zeroFillMatchesOriginalPTTLSMemsz ||
       !source.x86VariantIIModelOnly ||
       source.realGuestFSBaseAssigned ||
       source.alignedStaticBlockBytes!=136 ||
       source.originalInitializerBytes!=16 ||
       source.bytes.size()<136 ||
       source.negativeTLSBlockStart>source.bytes.size()-136)return false;
    region_=::mmap(nullptr,8192,PROT_READ|PROT_WRITE,
       MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    if(region_==MAP_FAILED)return false;
    const uint64_t start=reinterpret_cast<uintptr_t>(region_);
    fsBase_=start+4096;
    const uint64_t tlsAt=fsBase_-136;
    const uint64_t preDTV=fsBase_+512;
    if(!kernix::g2e::c1::GuestRange(start,8192) ||
       !kernix::g2e::c1::GuestRange(fsBase_,1024) ||
       (fsBase_&4095) || tlsAt<start ||
       preDTV+3*sizeof(DTVEntry)>start+8192)return false;
    std::memcpy(reinterpret_cast<void*>(static_cast<uintptr_t>(tlsAt)),
       source.bytes.data()+source.negativeTLSBlockStart,136);
    const TCBPrefix tcb{fsBase_,preDTV+sizeof(DTVEntry),fsBase_};
    std::memcpy(reinterpret_cast<void*>(static_cast<uintptr_t>(fsBase_)),
       &tcb,sizeof(tcb));
    const DTVEntry dtv[]={{1,0},{1,0},{tlsAt,0}};
    std::memcpy(reinterpret_cast<void*>(static_cast<uintptr_t>(preDTV)),
       dtv,sizeof(dtv));
    std::memcpy(&sourceQword_,
       source.bytes.data()+source.negativeTLSBlockStart,8);
    return true;
  }
  bool Release() noexcept {
    if(region_==MAP_FAILED)return true;
    if(::munmap(region_,8192)!=0)return false;
    region_=MAP_FAILED;fsBase_=0;sourceQword_=0;
    return true;
  }
  uint64_t FSBase() const noexcept{return fsBase_;}
  uint64_t SourceFirstQword() const noexcept{return sourceQword_;}
  bool GuestReadbacksMatch() const noexcept {
    if(region_==MAP_FAILED || !fsBase_)return false;
    uint64_t values[4]{};
    std::memcpy(values,reinterpret_cast<const void*>(
       static_cast<uintptr_t>(fsBase_+32)),sizeof(values));
    return values[0]==fsBase_ &&
           values[1]==sourceQword_ &&
           values[2]==sourceQword_ &&
           values[3]==fsBase_;
  }
 private:
  void* region_=MAP_FAILED;
  uint64_t fsBase_=0;
  uint64_t sourceQword_=0;
};
} // namespace kernix::g0::fsruntime
