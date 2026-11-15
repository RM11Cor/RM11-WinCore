// SPDX-License-Identifier: MIT
// R3D40: source-locked x86_64 opcode witnesses for real app-private Wine
// rootfs ELF DSOs mapped from guest FD101..116. No guest->host syscall bridge.
// RX mappings are accepted ONLY from bounded regular ELF x86_64 ET_DYN images
// and checked byte-for-byte against a retained descriptor and live RX bytes.
#pragma once
#include "carxpc/r3d25/native/verified_multi_elf_syscall.hpp"
#include <array>
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cerrno>
#include <climits>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <elf.h>

namespace carx_r3d40 {
constexpr uint64_t kMaxOriginalRootfsFile=256ULL*1024*1024;
struct RootfsRx {
 int fd{-1};
 uint64_t base{0}, length{0}, offset{0};
};
inline bool is_x86_64_elf_dso(int fd) noexcept {
 if(fd<0)return false;
 struct stat st{};
 if(::fstat(fd,&st)!=0 || !S_ISREG(st.st_mode) ||
    st.st_size<int64_t(sizeof(Elf64_Ehdr)) ||
    uint64_t(st.st_size)>kMaxOriginalRootfsFile)return false;
 Elf64_Ehdr eh{};
 if(::pread(fd,&eh,sizeof(eh),0)!=ssize_t(sizeof(eh)))return false;
 if(std::memcmp(eh.e_ident,ELFMAG,SELFMAG)!=0 ||
    eh.e_ident[EI_CLASS]!=ELFCLASS64 ||
    eh.e_ident[EI_DATA]!=ELFDATA2LSB ||
    eh.e_version!=EV_CURRENT ||
    eh.e_machine!=EM_X86_64 || eh.e_type!=ET_DYN ||
    eh.e_ehsize!=sizeof(Elf64_Ehdr) ||
    eh.e_phentsize!=sizeof(Elf64_Phdr) ||
    eh.e_phnum==0 || eh.e_phnum>256)return false;
 const uint64_t pht=uint64_t(eh.e_phnum)*sizeof(Elf64_Phdr);
 if(eh.e_phoff>uint64_t(st.st_size) ||
    pht>uint64_t(st.st_size)-eh.e_phoff ||
    eh.e_phoff>INT64_MAX)return false;
 bool hasExec=false;
 for(unsigned i=0;i<eh.e_phnum;++i) {
   Elf64_Phdr ph{};
   const uint64_t off=eh.e_phoff+uint64_t(i)*sizeof(ph);
   if(::pread(fd,&ph,sizeof(ph),off_t(off))!=ssize_t(sizeof(ph)))
     return false;
   if(ph.p_type!=PT_LOAD)continue;
   if(ph.p_filesz>ph.p_memsz ||
      ph.p_offset>uint64_t(st.st_size) ||
      ph.p_filesz>uint64_t(st.st_size)-ph.p_offset)
     return false;
   if((ph.p_flags&PF_X)!=0)hasExec=true;
 }
 return hasExec;
}
class GuestRootfsRxSource final {
 std::array<RootfsRx,64> ranges{};
 static bool overlaps(const RootfsRx& r,uint64_t base,uint64_t len) noexcept {
   return r.fd>=0 && base<r.base+r.length && r.base<base+len;
 }
 void drop(RootfsRx& r) noexcept {
   if(r.fd>=0)::close(r.fd);
   r={};
 }
public:
 GuestRootfsRxSource()=default;
 GuestRootfsRxSource(const GuestRootfsRxSource&)=delete;
 GuestRootfsRxSource& operator=(const GuestRootfsRxSource&)=delete;
 ~GuestRootfsRxSource(){for(auto& r:ranges)drop(r);}
 void invalidate(uint64_t addr,uint64_t len) noexcept {
   if(!len || addr>UINT64_MAX-len)return;
   for(auto& r:ranges)if(overlaps(r,addr,len))drop(r);
 }
 bool observe_mmap(int verifiedRootfsFd,uint64_t addr,uint64_t len,
                   bool rx,uint64_t off) noexcept {
   if(!addr || !len || (addr&4095) || (len&4095) ||
      (off&4095) || addr>UINT64_MAX-len ||
      off>INT64_MAX || off>UINT64_MAX-len)return false;
   invalidate(addr,len);
   if(!rx)return true;
   if(!is_x86_64_elf_dso(verifiedRootfsFd))return false;
   for(auto& r:ranges)if(r.fd<0) {
     const int dupfd=::fcntl(verifiedRootfsFd,F_DUPFD_CLOEXEC,3);
     if(dupfd<0)return false;
     r={dupfd,addr,len,off};
     return true;
   }
   return false;
 }
 template<typename FindRx>
 bool match_at(uint64_t rip,const FindRx& find,uint64_t& fileOffset) const noexcept {
   if(!rip || rip>UINT64_MAX-2)return false;
   const auto vma=find(rip);
   if(!vma.length || rip<vma.base || rip-vma.base>vma.length-2)
     return false;
   bool found=false;
   for(const auto& r:ranges) {
     if(r.fd<0 || rip<r.base || rip-r.base>r.length-2)continue;
     const uint64_t pos=r.offset+(rip-r.base);
     if(pos>INT64_MAX-2)return false;
     struct stat st{};
     if(::fstat(r.fd,&st)!=0 || st.st_size<2 ||
        pos>uint64_t(st.st_size)-2)return false;
     unsigned char original[2]{};
     if(::pread(r.fd,original,2,off_t(pos))!=2)return false;
     if(original[0]!=0x0f || original[1]!=0x05)return false;
     const auto* live=reinterpret_cast<const unsigned char*>(
       static_cast<uintptr_t>(rip));
     if(live[0]!=original[0] || live[1]!=original[1])return false;
     if(found)return false;
     fileOffset=pos;found=true;
   }
   return found;
 }
 template<typename FindRx>
 bool make_record(uint64_t rip,uint64_t syscall,uint64_t nonce,
                  const FindRx& find,carx_r3d3::Record* out) const noexcept {
   if(!out || !nonce || syscall>UINT32_MAX)return false;
   uint64_t aoff=0,poff=0;
   const bool at=match_at(rip,find,aoff);
   const bool prior=rip>=2 && match_at(rip-2,find,poff);
   if(at==prior)return false;
   const uint64_t op=at?rip:rip-2;
   *out=carx_r3d3::Record{
     carx_r3d3::kMagic,carx_r3d3::kVersion,nonce,syscall,
     op,rip,at?aoff:poff,
     at?carx_r3d3::kObservedAtRip:carx_r3d3::kObservedBeforeRip,0
   };
   return true;
 }
};
} // namespace carx_r3d40
