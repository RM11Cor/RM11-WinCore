// SPDX-License-Identifier: MIT
#pragma once
// Original SHA-pinned ld-linux DT_RELA source symbols and IRELATIVE
// resolver executable provenance. No guest instruction execution,
// IFUNC invocation, host path / FD forwarding, or guest data writes.
// Authentic ELF metadata and owned guest bytes are read only.
// This cannot prove ldso dynamic symbol/IFUNC execution or RELRO seal.
#include "kernix_g0_original_ldso_rela_three_phase_readonly.h"
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <elf.h>
#include <limits>

namespace kernix::g0::ldsorelasource {
struct Symbol {
  uint64_t target=0,live=0,definitionGuest=0;
  uint32_t symbolIndex=0;
  uint8_t binding=0,type=0;
  bool sourceDefined=false,exactSelfDefinition=false;
  char name[96]{};
};
struct Witness {
  std::array<Symbol,2> symbolic{};
  size_t symbolicNames=0,definedInLdso=0,matchedOwnDefinitions=0;
  uint64_t resolverSourceVA=0,resolverGuestVA=0;
  uint64_t ifuncSlotTarget=0,ifuncSlotLive=0;
  bool resolverSourceCodeVerified=false;
  bool resolverGuestBytesIdenticalToSource=false;
  bool ifuncExecutedOrResultValidated=false;
  bool fullDynamicRelocationClosureProven=false;
};
inline bool ReadOriginalLdsoThreeRelaSymbolAndResolverSource(
    const uint8_t* source,size_t bytes,bool sha,
    const kernix::g2e::c3d7b::NativeChosenPIEGuestLayout& owned,
    const kernix::g2e::c3d7g::PermissionPlan& plan,
    const kernix::g0::ldsorela::Witness& rela,
    Witness& out) noexcept {
  out={};
  namespace d=kernix::g2e::c3d7i;
  namespace g=kernix::g2e::c3d7g;
  const auto* image=owned.Module(1);
  if(!source || !sha || !image ||
     !owned.LaunchPlan() || owned.WindowsHeld()!=4 ||
     !plan.sourceShaVerified || !plan.nativeGuestVAIdentityOwned ||
     !rela.authenticatedSource || rela.count!=3 ||
     rela.irelative!=1 || rela.symbolic!=2 ||
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
  uint64_t symbolVA=0,symbolSize=0,stringsVA=0,stringsSize=0;
  unsigned seen=0;
  bool foundDynamic=false,terminated=false;
  for(uint16_t i=0;i<elf.e_phnum;++i){
    Elf64_Phdr ph{};
    std::memcpy(&ph,source+elf.e_phoff+
         size_t(i)*sizeof(ph),sizeof(ph));
    if(ph.p_type!=PT_DYNAMIC)continue;
    if(foundDynamic || !ph.p_filesz || ph.p_filesz>65536 ||
       ph.p_filesz%sizeof(Elf64_Dyn) ||
       ph.p_offset>bytes || ph.p_filesz>bytes-ph.p_offset)
      return false;
    foundDynamic=true;
    for(uint64_t at=0;at<ph.p_filesz;at+=sizeof(Elf64_Dyn)){
      Elf64_Dyn tag{};
      std::memcpy(&tag,source+ph.p_offset+at,sizeof(tag));
      if(tag.d_tag==DT_NULL){terminated=true;break;}
      unsigned bit=0;
      if(tag.d_tag==DT_SYMTAB){bit=1;symbolVA=tag.d_un.d_ptr;}
      else if(tag.d_tag==DT_SYMENT){bit=2;symbolSize=tag.d_un.d_val;}
      else if(tag.d_tag==DT_STRTAB){bit=4;stringsVA=tag.d_un.d_ptr;}
      else if(tag.d_tag==DT_STRSZ){bit=8;stringsSize=tag.d_un.d_val;}
      if(bit){if(seen&bit)return false;seen|=bit;}
    }
    if(!terminated)return false;
  }
  if(!foundDynamic || !terminated || seen!=15 ||
     symbolSize!=sizeof(Elf64_Sym) ||
     !stringsSize || stringsSize>2*1024*1024 ||
     !symbolVA || !stringsVA)return false;
  size_t stringsOffset=0;
  if(!d::SourceFileVA(source,bytes,elf,
                       stringsVA,stringsSize,stringsOffset))return false;
  const auto* stringTable=source+stringsOffset;
  const auto sourceLoadRange=[&](uint64_t va,size_t length,
                                 uint32_t must,uint32_t deny) noexcept -> bool{
    for(uint16_t i=0;i<elf.e_phnum;++i){
      Elf64_Phdr ph{};
      std::memcpy(&ph,source+elf.e_phoff+
          size_t(i)*sizeof(ph),sizeof(ph));
      if(ph.p_type!=PT_LOAD ||
         (ph.p_flags&must)!=must || (ph.p_flags&deny)!=0 ||
         va<ph.p_vaddr || va-ph.p_vaddr>ph.p_memsz ||
         length>ph.p_memsz-(va-ph.p_vaddr))continue;
      return true;
    }
    return false;
  };
  for(const auto& entry:rela.entries){
    if(entry.type==R_X86_64_IRELATIVE){
      if(out.resolverSourceCodeVerified ||
         entry.symbol!=0 || entry.addend<0 ||
         entry.target==0 || entry.addend==0)return false;
      const uint64_t resolverVA=static_cast<uint64_t>(entry.addend);
      if(!sourceLoadRange(resolverVA,8,PF_R|PF_X,PF_W) ||
         resolverVA>UINT64_MAX-image->loadBias)return false;
      const uint64_t guest=image->loadBias+resolverVA;
      if(guest<image->chosenImageStart ||
         guest-image->chosenImageStart>g::kModulePages*4096ULL-8)
        return false;
      const size_t pg=static_cast<size_t>(
           (guest-image->chosenImageStart)/4096);
      if((plan.modules[1].rights[pg] &
            (g::kRead|g::kWrite|g::kExecute))!=(g::kRead|g::kExecute))
        return false;
      size_t at=0;
      if(!d::SourceFileVA(source,bytes,elf,resolverVA,8,at))
        return false;
      const auto* live=owned.GuestReadOnlyBytes(1,guest,8);
      if(!live || std::memcmp(live,source+at,8)!=0)return false;
      out.resolverSourceVA=resolverVA;
      out.resolverGuestVA=guest;
      out.ifuncSlotTarget=entry.target;
      out.ifuncSlotLive=entry.live;
      out.resolverSourceCodeVerified=true;
      out.resolverGuestBytesIdenticalToSource=true;
      continue;
    }
    if(entry.type!=R_X86_64_GLOB_DAT || entry.symbol==0 ||
       out.symbolicNames>=out.symbolic.size() ||
       uint64_t(entry.symbol)>UINT64_MAX/sizeof(Elf64_Sym) ||
       symbolVA>UINT64_MAX-uint64_t(entry.symbol)*sizeof(Elf64_Sym))
      return false;
    const uint64_t symVA=symbolVA+
       uint64_t(entry.symbol)*sizeof(Elf64_Sym);
    size_t symOffset=0;
    if(!d::SourceFileVA(source,bytes,elf,
                         symVA,sizeof(Elf64_Sym),symOffset))
      return false;
    Elf64_Sym sym{};
    std::memcpy(&sym,source+symOffset,sizeof(sym));
    if(!sym.st_name || sym.st_name>=stringsSize)return false;
    const char* name=reinterpret_cast<const char*>(
        stringTable+sym.st_name);
    const size_t available=static_cast<size_t>(
        stringsSize-sym.st_name);
    const char* end=static_cast<const char*>(
        std::memchr(name,0,available));
    if(!end || end==name ||
       static_cast<size_t>(end-name)>=sizeof(out.symbolic[0].name))
      return false;
    auto& item=out.symbolic[out.symbolicNames];
    std::memcpy(item.name,name,static_cast<size_t>(end-name));
    item.target=entry.target;
    item.live=entry.live;
    item.symbolIndex=entry.symbol;
    item.binding=ELF64_ST_BIND(sym.st_info);
    item.type=ELF64_ST_TYPE(sym.st_info);
    item.sourceDefined=sym.st_shndx!=SHN_UNDEF;
    if(item.sourceDefined){
      if(!sourceLoadRange(sym.st_value,1,PF_R,0) ||
         sym.st_value>UINT64_MAX-image->loadBias)
        return false;
      item.definitionGuest=image->loadBias+sym.st_value;
      ++out.definedInLdso;
      item.exactSelfDefinition=item.definitionGuest==entry.live;
      out.matchedOwnDefinitions+=size_t(item.exactSelfDefinition);
    }
    ++out.symbolicNames;
  }
  return out.symbolicNames==2 &&
         out.resolverSourceCodeVerified &&
         out.resolverGuestBytesIdenticalToSource &&
         !out.ifuncExecutedOrResultValidated &&
         !out.fullDynamicRelocationClosureProven;
}
} // namespace kernix::g0::ldsorelasource
