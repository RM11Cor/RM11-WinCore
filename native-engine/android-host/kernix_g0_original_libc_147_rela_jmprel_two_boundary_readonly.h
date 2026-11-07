// SPDX-License-Identifier: MIT
#pragma once
// Source-attested, read-only original libc x86_64 DT_RELA (86)
// + DT_JMPREL (61) qword observations at authentic GNU ld-linux
// libc and main mprotect syscall boundaries on Linux ARM64.
// Counts and values are evidence only, not verification of actual
// GNU name lookup, IFUNC resolver invocation, guest store RIP,
// full dynamic link completion or Windows process support.
#include "kernix_g2e_c3d7i_original_x86_dynamic_tls_relocation_contract.h"
#include "kernix_g0_source_pinned_libc_large_ro_guest_map.h"
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <elf.h>
#include <limits>

namespace kernix::g0::libcrela {
struct Entry {
  uint64_t target=0,source=0,live=0;
  int64_t addend=0;
  uint32_t type=0,symbol=0;
  bool sourceBacked=false,plt=false;
};
struct Witness {
  std::array<Entry,147> slots{};
  size_t count=0,rela=0,jmprel=0,irelative=0,symbolic=0;
  size_t sourceBacked=0,sourceBSS=0;
  size_t liveMatchesSource=0,liveNonzero=0;
  size_t ifuncNonzero=0,symbolicNonzero=0;
  bool originalSourceShaPinned=false;
  bool guestStoreInstructionsTraced=false;
  bool symbolOrIfuncResolutionsProven=false;
  bool wholeLibcRelocationClosureProven=false;
};
template <class Readable>
inline bool SampleOriginalLibc147RelaJmprelReadonly(
    const uint8_t* source,size_t bytes,bool exactSHA,
    const kernix::g0::PinnedLibcLargeReadonlyGuestMap& map,
    Readable&& readableGuest, Witness& out) noexcept {
  out={};
  namespace d=kernix::g2e::c3d7i;
  const uint64_t base=map.Address();
  if(!source || !exactSHA || !base ||
     bytes!=kernix::g0::PinnedLibcLargeReadonlyGuestMap::kOriginalLibcSize ||
     !map.OriginalOwnedBSSZeroed() ||
     map.BytesHeld()!=0x212000ULL ||
     map.CopiedSourceBytes()!=bytes ||
     bytes<sizeof(Elf64_Ehdr))return false;
  Elf64_Ehdr eh{};
  std::memcpy(&eh,source,sizeof(eh));
  if(std::memcmp(eh.e_ident,ELFMAG,SELFMAG)!=0 ||
     eh.e_ident[EI_CLASS]!=ELFCLASS64 ||
     eh.e_ident[EI_DATA]!=ELFDATA2LSB ||
     eh.e_type!=ET_DYN || eh.e_machine!=EM_X86_64 ||
     eh.e_phentsize!=sizeof(Elf64_Phdr) ||
     !eh.e_phnum || eh.e_phnum>128 || eh.e_phoff>bytes ||
     size_t(eh.e_phnum)>(bytes-eh.e_phoff)/sizeof(Elf64_Phdr))
     return false;
  std::array<Elf64_Phdr,128> phdrs{};
  uint64_t relaVA=0,relaBytes=0,relaSize=0;
  uint64_t jmprelVA=0,jmprelBytes=0,pltRelTag=0;
  unsigned tags=0;
  bool foundDynamic=false,terminated=false;
  for(uint16_t i=0;i<eh.e_phnum;++i){
    auto& ph=phdrs[i];
    std::memcpy(&ph,source+eh.e_phoff+size_t(i)*sizeof(ph),sizeof(ph));
    if(ph.p_type!=PT_DYNAMIC)continue;
    if(foundDynamic || ph.p_offset>bytes ||
       !ph.p_filesz || ph.p_filesz>65536 ||
       ph.p_filesz>bytes-ph.p_offset ||
       ph.p_filesz%sizeof(Elf64_Dyn))return false;
    foundDynamic=true;
    for(uint64_t off=0;off<ph.p_filesz;off+=sizeof(Elf64_Dyn)){
      Elf64_Dyn dyn{};
      std::memcpy(&dyn,source+ph.p_offset+off,sizeof(dyn));
      if(dyn.d_tag==DT_NULL){terminated=true;break;}
      unsigned bit=0;
      if(dyn.d_tag==DT_RELA){bit=1;relaVA=dyn.d_un.d_ptr;}
      else if(dyn.d_tag==DT_RELASZ){bit=2;relaBytes=dyn.d_un.d_val;}
      else if(dyn.d_tag==DT_RELAENT){bit=4;relaSize=dyn.d_un.d_val;}
      else if(dyn.d_tag==DT_JMPREL){bit=8;jmprelVA=dyn.d_un.d_ptr;}
      else if(dyn.d_tag==DT_PLTRELSZ){bit=16;jmprelBytes=dyn.d_un.d_val;}
      else if(dyn.d_tag==DT_PLTREL){bit=32;pltRelTag=dyn.d_un.d_val;}
      if(bit){if(tags&bit)return false;tags|=bit;}
    }
    if(!terminated)return false;
  }
  if(!foundDynamic || !terminated || tags!=63 ||
     relaSize!=sizeof(Elf64_Rela) || pltRelTag!=DT_RELA ||
     relaBytes!=86*sizeof(Elf64_Rela) ||
     jmprelBytes!=61*sizeof(Elf64_Rela) ||
     !relaVA || !jmprelVA ||
     (relaVA<jmprelVA+jmprelBytes &&
      jmprelVA<relaVA+relaBytes))
    return false;
  const auto scan=[&](uint64_t va,uint64_t bytesSpan,bool plt) noexcept -> bool {
    size_t at=0;
    if(!d::SourceFileVA(source,bytes,eh,va,bytesSpan,at))
      return false;
    for(size_t i=0;i<bytesSpan/sizeof(Elf64_Rela);++i){
      Elf64_Rela relocation{};
      std::memcpy(&relocation,
        source+at+i*sizeof(relocation),sizeof(relocation));
      const uint32_t type=ELF64_R_TYPE(relocation.r_info);
      const uint32_t symbol=ELF64_R_SYM(relocation.r_info);
      if((relocation.r_offset&7)!=0 ||
         relocation.r_offset>UINT64_MAX-base ||
         out.count>=out.slots.size())return false;
      if(type==R_X86_64_RELATIVE)return false;
      if(type==R_X86_64_IRELATIVE){
        if(symbol!=0)return false;
      }else if(symbol==0)return false;
      bool sourceWritable=false;
      for(size_t ph=0;ph<eh.e_phnum;++ph) {
        const auto& seg=phdrs[ph];
        if(seg.p_type!=PT_LOAD ||
           (seg.p_flags&(PF_R|PF_W|PF_X))!=(PF_R|PF_W) ||
           relocation.r_offset<seg.p_vaddr ||
           relocation.r_offset-seg.p_vaddr>seg.p_memsz ||
           seg.p_memsz-(relocation.r_offset-seg.p_vaddr)<8)
          continue;
        sourceWritable=true;
        break;
      }
      if(!sourceWritable)return false;
      const uint64_t target=base+relocation.r_offset;
      if(target<base || map.BytesHeld()<8 ||
         target-base>map.BytesHeld()-8 ||
         !readableGuest(target))return false;
      for(size_t k=0;k<out.count;++k)
        if(out.slots[k].target==target)return false;
      auto& x=out.slots[out.count];
      x.target=target;x.type=type;x.symbol=symbol;
      x.addend=relocation.r_addend;x.plt=plt;
      size_t initialFile=0;
      if(d::SourceFileVA(source,bytes,eh,relocation.r_offset,
                         sizeof(uint64_t),initialFile)){
        std::memcpy(&x.source,source+initialFile,8);
        x.sourceBacked=true;++out.sourceBacked;
      }else{
        x.source=0;
        ++out.sourceBSS;
      }
      std::memcpy(&x.live,reinterpret_cast<const void*>(
          static_cast<uintptr_t>(target)),8);
      out.liveMatchesSource+=size_t(x.live==x.source);
      out.liveNonzero+=size_t(x.live!=0);
      if(type==R_X86_64_IRELATIVE){
        ++out.irelative;out.ifuncNonzero+=size_t(x.live!=0);
      }else{
        ++out.symbolic;out.symbolicNonzero+=size_t(x.live!=0);
      }
      if(plt)++out.jmprel;
      else ++out.rela;
      ++out.count;
    }
    return true;
  };
  if(!scan(relaVA,relaBytes,false) ||
     !scan(jmprelVA,jmprelBytes,true) ||
     out.count!=147 || out.rela!=86 || out.jmprel!=61 ||
     out.irelative!=46 || out.symbolic!=101 ||
     out.sourceBacked+out.sourceBSS!=147 ||
     out.liveMatchesSource>147 || out.liveNonzero>147 ||
     out.ifuncNonzero>46 || out.symbolicNonzero>101)
     return false;
  out.originalSourceShaPinned=true;
  return true;
}
} // namespace kernix::g0::libcrela
