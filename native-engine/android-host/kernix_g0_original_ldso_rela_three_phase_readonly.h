// SPDX-License-Identifier: MIT
#pragma once
// G0 Linux ARM64 original ld-linux x86_64 three DT_RELA targets:
// observe a pinned ELF source before guest execution and at authentic
// main GNU_RELRO mprotect. This does not resolve symbolic/IFUNC entries,
// identify x86 guest write instructions or certify relocation closure.
// Source bytes and owned guest qwords are READ ONLY.
#include "kernix_g2e_c3d7i_original_x86_dynamic_tls_relocation_contract.h"
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <elf.h>
#include <limits>

namespace kernix::g0::ldsorela {
struct Entry {
  uint64_t target=0,sourceInitial=0,live=0;
  int64_t addend=0;
  uint32_t type=0,symbol=0;
  bool backed=false;
};
struct Witness {
  std::array<Entry,3> entries{};
  size_t count=0,irelative=0,symbolic=0;
  size_t backed=0,bss=0,sourceEqual=0,sourceDifferent=0;
  bool authenticatedSource=false;
  bool originalLdsoStoreRIPTraced=false;
  bool fullRelocationClosureProven=false;
};
inline bool SampleOriginalLdsoThreeRelaReadOnly(
    const uint8_t* source,size_t bytes,bool sourceSHA,
    const kernix::g2e::c3d7b::NativeChosenPIEGuestLayout& owned,
    const kernix::g2e::c3d7g::PermissionPlan& plan,
    Witness& out) noexcept {
  out={};
  namespace d=kernix::g2e::c3d7i;
  namespace g=kernix::g2e::c3d7g;
  const auto* image=owned.Module(1);
  if(!source || !sourceSHA || !image ||
     !owned.LaunchPlan() || owned.WindowsHeld()!=4 ||
     !plan.sourceShaVerified || !plan.nativeGuestVAIdentityOwned ||
     bytes<sizeof(Elf64_Ehdr))return false;
  Elf64_Ehdr elf{};
  std::memcpy(&elf,source,sizeof(elf));
  if(std::memcmp(elf.e_ident,ELFMAG,SELFMAG)!=0 ||
     elf.e_ident[EI_CLASS]!=ELFCLASS64 ||
     elf.e_ident[EI_DATA]!=ELFDATA2LSB ||
     elf.e_type!=ET_DYN || elf.e_machine!=EM_X86_64 ||
     elf.e_phentsize!=sizeof(Elf64_Phdr) ||
     !elf.e_phnum || elf.e_phnum>128 ||
     elf.e_phoff>bytes ||
     size_t(elf.e_phnum)>(bytes-elf.e_phoff)/sizeof(Elf64_Phdr))
     return false;
  uint64_t tableVA=0,tableBytes=0,entryBytes=0;
  unsigned tags=0;
  bool dynamicFound=false,dynamicTerminated=false;
  std::array<Elf64_Phdr,128> phdrs{};
  for(uint16_t i=0;i<elf.e_phnum;++i){
    auto& ph=phdrs[i];
    std::memcpy(&ph,source+elf.e_phoff+
       size_t(i)*sizeof(ph),sizeof(ph));
    if(ph.p_type!=PT_DYNAMIC)continue;
    if(dynamicFound || !ph.p_filesz || ph.p_filesz>65536 ||
       ph.p_filesz%sizeof(Elf64_Dyn) ||
       ph.p_offset>bytes || ph.p_filesz>bytes-ph.p_offset)return false;
    dynamicFound=true;
    for(uint64_t at=0;at<ph.p_filesz;at+=sizeof(Elf64_Dyn)){
      Elf64_Dyn entry{};
      std::memcpy(&entry,source+ph.p_offset+at,sizeof(entry));
      if(entry.d_tag==DT_NULL){dynamicTerminated=true;break;}
      unsigned bit=0;
      if(entry.d_tag==DT_RELA) {bit=1;tableVA=entry.d_un.d_ptr;}
      else if(entry.d_tag==DT_RELASZ) {bit=2;tableBytes=entry.d_un.d_val;}
      else if(entry.d_tag==DT_RELAENT) {bit=4;entryBytes=entry.d_un.d_val;}
      if(bit) {if(tags&bit)return false;tags|=bit;}
    }
    if(!dynamicTerminated)return false;
  }
  if(!dynamicFound || !dynamicTerminated || tags!=7 ||
     tableBytes!=3*sizeof(Elf64_Rela) ||
     entryBytes!=sizeof(Elf64_Rela))return false;
  size_t fileOffset=0;
  if(!d::SourceFileVA(
       source,bytes,elf,tableVA,tableBytes,fileOffset))return false;
  for(size_t i=0;i<3;++i){
    Elf64_Rela r{};
    std::memcpy(&r,source+fileOffset+i*sizeof(r),sizeof(r));
    const uint32_t type=ELF64_R_TYPE(r.r_info);
    const uint32_t symbol=ELF64_R_SYM(r.r_info);
    if((r.r_offset&7)!=0 || r.r_offset>UINT64_MAX-image->loadBias)
      return false;
    if(type==R_X86_64_IRELATIVE){
      if(symbol!=0)return false;
      ++out.irelative;
    }else{
      if(type==R_X86_64_RELATIVE || symbol==0)return false;
      ++out.symbolic;
    }
    const uint64_t guest=image->loadBias+r.r_offset;
    if(guest<image->chosenImageStart ||
       guest-image->chosenImageStart>g::kModulePages*4096ULL-8)
       return false;
    const size_t pg=static_cast<size_t>(
        (guest-image->chosenImageStart)/4096);
    if((plan.modules[1].rights[pg] &
       (g::kRead|g::kWrite|g::kExecute))!=(g::kRead|g::kWrite))
       return false;
    bool sourceRW=false;
    for(uint16_t p=0;p<elf.e_phnum;++p){
      const auto& segment=phdrs[p];
      if(segment.p_type!=PT_LOAD ||
         (segment.p_flags&(PF_R|PF_W|PF_X))!=(PF_R|PF_W) ||
         r.r_offset<segment.p_vaddr ||
         r.r_offset-segment.p_vaddr>segment.p_memsz ||
         segment.p_memsz-(r.r_offset-segment.p_vaddr)<8)continue;
      sourceRW=true;break;
    }
    if(!sourceRW)return false;
    const auto* live=owned.GuestReadOnlyBytes(1,guest,8);
    if(!live)return false;
    auto& dest=out.entries[i];
    for(size_t prev=0;prev<i;++prev)
      if(out.entries[prev].target==guest)return false;
    dest.target=guest;dest.type=type;dest.symbol=symbol;
    dest.addend=r.r_addend;
    std::memcpy(&dest.live,live,8);
    size_t originalOffset=0;
    if(d::SourceFileVA(source,bytes,elf,r.r_offset,8,originalOffset)){
      std::memcpy(&dest.sourceInitial,source+originalOffset,8);
      dest.backed=true;++out.backed;
    }else{
      // PF_R|PF_W PT_LOAD memory beyond p_filesz is source ELF BSS.
      dest.sourceInitial=0;++out.bss;
    }
    if(dest.live==dest.sourceInitial)++out.sourceEqual;
    else ++out.sourceDifferent;
    ++out.count;
  }
  if(out.count!=3 || out.irelative!=1 || out.symbolic!=2 ||
     out.backed+out.bss!=3 || out.sourceEqual+out.sourceDifferent!=3)
    return false;
  out.authenticatedSource=true;
  return true;
}
} // namespace kernix::g0::ldsorela
