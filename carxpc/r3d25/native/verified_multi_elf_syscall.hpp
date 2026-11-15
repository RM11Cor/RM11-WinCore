// SPDX-License-Identifier: MIT
// R3D25: verify Linux x86 syscall opcode provenance across original ELF
// GNU ld.so, Wine ELF (authenticated source bytes) and verified rootfs libc.
//
// Earlier R3D24 acknowledged 22 authentic GNU syscalls and fixed Wine+ld.so
// RELRO. The next FEX callback exited 93 before the source witness, because
// the R3D3 evidence checker recognized only GNU ld.so's original ELF bytes.
// The next callback may be in Wine, libc, or an unrecognized mapping.
// NEVER force a guessed syscall to succeed. Only source-verified owner ELF
// instructions may be advanced. For libc, a verified readonly fd and the
// EXACT file-backed RX mmap offset + guest RX original bytes must match 0F05.
// No guest opcode generated from a synthetic script or unrelated host file.
#pragma once
#include "carxpc/r3d3/native/r3d3_first_syscall_witness.hpp"
#include "carxpc/r3d23/native/bounded_guest_executable_vma.hpp"
#include <array>
#include <cstdint>
#include <cstddef>
#include <cerrno>
#include <cstring>
#include <sys/stat.h>
#include <unistd.h>
#include <limits>
namespace carx_r3d25 {
enum class Source : uint8_t { None, GNU_LDSO, WINE_ELF, LIBC_FD100 };
constexpr size_t kMaxLibcRXMappings=32;
struct VerifiedLibcRX {
  uint64_t base{0},length{0},fileOffset{0};
  bool valid{false};
};
class RootfsLibcSource final {
 std::array<VerifiedLibcRX,kMaxLibcRXMappings> ranges{};
public:
 bool observe_mmap(uint64_t guestBase,uint64_t length,
                   bool rxReadExec,bool verifiedFd100,
                   uint64_t fileOffset) noexcept {
   if(!guestBase || !length || (guestBase&4095) || (length&4095) ||
      guestBase>UINT64_MAX-length)return false;
   // Clear possible stale source status before a replacement MAP_FIXED.
   for(auto& r:ranges){
     if(r.valid && guestBase<r.base+r.length &&
        r.base<guestBase+length)r.valid=false;
   }
   if(!rxReadExec || !verifiedFd100)return true;
   if((fileOffset&4095)!=0 ||
      fileOffset>UINT64_MAX-length)return false;
   for(auto& r:ranges)if(!r.valid) {
     r={guestBase,length,fileOffset,true};return true;
   }
   return false;
 }
 void invalidate(uint64_t guestBase,uint64_t length) noexcept {
   if(!length || guestBase>UINT64_MAX-length)return;
   for(auto& r:ranges)
     if(r.valid && guestBase<r.base+r.length &&
        r.base<guestBase+length)r.valid=false;
 }
 template<typename ExecAllowed>
 bool verify_opcode(int trustedLibcReadonlyFd,uint64_t guestOpcodeRip,
                    const ExecAllowed& executable) const noexcept {
   if(trustedLibcReadonlyFd<0 ||
      guestOpcodeRip>UINT64_MAX-2)return false;
   auto execRange=executable(guestOpcodeRip);
   if(!execRange.length ||
      guestOpcodeRip<execRange.base ||
      guestOpcodeRip-execRange.base>execRange.length-2)return false;
   for(const auto& r:ranges) {
     if(!r.valid || guestOpcodeRip<r.base ||
        guestOpcodeRip-r.base>r.length-2)continue;
     const uint64_t filePos=r.fileOffset+(guestOpcodeRip-r.base);
     if(filePos>INT64_MAX-2)return false;
     struct stat st{};
     if(::fstat(trustedLibcReadonlyFd,&st)<0 ||
        st.st_size<2 || filePos>uint64_t(st.st_size)-2)return false;
     unsigned char actual[2]{};
     if(::pread(trustedLibcReadonlyFd,actual,2,off_t(filePos))!=2)
       return false;
     if(actual[0]!=0x0F || actual[1]!=0x05)return false;
     // RX guest page was copied from EXACT trusted rootfs source. Require
     // the live bytes remain equal too. observe_mmap tracks RX only and
     // invalidate() runs before any guest mprotect changing its rights.
     const auto* live=reinterpret_cast<const unsigned char*>(
       static_cast<uintptr_t>(guestOpcodeRip));
     return live[0]==actual[0] && live[1]==actual[1];
   }
   return false;
 }
 template<typename ExecAllowed>
 bool make_record(int fd,uint64_t callbackRip,uint64_t syscall,
                  uint64_t nonce,const ExecAllowed& executable,
                  carx_r3d3::Record* record)const noexcept {
   if(!record || !nonce || !callbackRip || syscall>UINT32_MAX)return false;
   const bool at=verify_opcode(fd,callbackRip,executable);
   const bool prior=callbackRip>=2 &&
     verify_opcode(fd,callbackRip-2,executable);
   if(at==prior)return false;
   const uint64_t opRip=at?callbackRip:callbackRip-2;
   uint64_t filePos=0;
   bool found=false;
   for(const auto& r:ranges) {
     if(r.valid && opRip>=r.base && opRip-r.base<=r.length-2){
       filePos=r.fileOffset+(opRip-r.base);
       found=true;break;
     }
   }
   if(!found)return false;
   *record=carx_r3d3::Record{
     carx_r3d3::kMagic,carx_r3d3::kVersion,nonce,syscall,
     opRip,callbackRip,filePos,
     at?carx_r3d3::kObservedAtRip:carx_r3d3::kObservedBeforeRip,0
   };
   return true;
 }
};
template<typename GnuVerify,typename WineVerify,typename LibcVerify>
bool select_exactly_one(const GnuVerify& gnu,const WineVerify& wine,
                        const LibcVerify& libc,Source& chosen,
                        carx_r3d3::Record& selected) {
 carx_r3d3::Record a{},b{},c{};
 const bool x=gnu(&a),y=wine(&b),z=libc(&c);
 if(unsigned(x)+unsigned(y)+unsigned(z)!=1){
   chosen=Source::None;return false;
 }
 chosen=x?Source::GNU_LDSO:y?Source::WINE_ELF:Source::LIBC_FD100;
 selected=x?a:y?b:c;
 return true;
}
} // namespace carx_r3d25
