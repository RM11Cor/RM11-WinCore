// SPDX-License-Identifier: MIT
#pragma once
// Read-only ELF GNU symbol-version provenance for the ONE original main
// DT_JMPREL puts entry. No memory mutation, no GNU loader emulation,
// no assertion that the original runtime completed dynamic linking.
#include "kernix_g0_original_main_plt_jump_slot_source_witness.h"
#include "kernix_g0_original_main_relro_source_version_requirement_witness.h"
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <elf.h>
#include <limits>

namespace kernix::g0::pltversions {
struct Witness {
  uint16_t mainVersionIndex=0;
  uint16_t libcVersionIndex=0;
  char requiredVersion[64]{};
  char definedVersion[64]{};
  bool mainSourceVerneedVerified=false;
  bool libcSourceVersymVerdefVerified=false;
  bool exactVersionAndAddressMatched=false;
  bool originalGNUVersionedLookupExecuted=false;
};
inline bool PinnedELFHeader(const uint8_t* src,size_t bytes,
                            Elf64_Ehdr& h) noexcept {
  if(!src || bytes<sizeof(h))return false;
  std::memcpy(&h,src,sizeof(h));
  return std::memcmp(h.e_ident,ELFMAG,SELFMAG)==0 &&
         h.e_ident[EI_CLASS]==ELFCLASS64 &&
         h.e_ident[EI_DATA]==ELFDATA2LSB &&
         h.e_type==ET_DYN && h.e_machine==EM_X86_64 &&
         h.e_phentsize==sizeof(Elf64_Phdr) &&
         h.e_phnum>0 && h.e_phnum<=128 &&
         h.e_phoff<=bytes &&
         size_t(h.e_phnum)<=(bytes-h.e_phoff)/sizeof(Elf64_Phdr);
}
inline bool MainRequiredVersion(
     const uint8_t* source,size_t bytes,const mainpltsource::Witness& plt,
     Witness& out) noexcept {
  namespace d=kernix::g2e::c3d7i;
  Elf64_Ehdr e{};
  if(!PinnedELFHeader(source,bytes,e) ||
     !plt.authenticatedSourceJumpSlot ||
     !plt.originalWritablePageVerified ||
     plt.originalGNUJmpSlotResolutionProven ||
     plt.symbolIndex==0)return false;
  uint64_t versymVA=0,needVA=0,needed=0,strVA=0,strBytes=0;
  uint32_t seen=0;
  bool terminated=false,found=false;
  for(uint16_t i=0;i<e.e_phnum;++i){
    Elf64_Phdr ph{};
    std::memcpy(&ph,source+e.e_phoff+size_t(i)*sizeof(ph),sizeof(ph));
    if(ph.p_type!=PT_DYNAMIC)continue;
    if(found || ph.p_offset>bytes ||
       !ph.p_filesz || ph.p_filesz>65536 ||
       ph.p_filesz%sizeof(Elf64_Dyn) ||
       ph.p_filesz>bytes-ph.p_offset)return false;
    found=true;
    for(uint64_t j=0;j<ph.p_filesz;j+=sizeof(Elf64_Dyn)){
      Elf64_Dyn dyn{};
      std::memcpy(&dyn,source+ph.p_offset+j,sizeof(dyn));
      if(dyn.d_tag==DT_NULL){terminated=true;break;}
      uint32_t bit=0;
      switch(dyn.d_tag) {
        case DT_VERSYM:bit=1;versymVA=dyn.d_un.d_ptr;break;
        case DT_VERNEED:bit=2;needVA=dyn.d_un.d_ptr;break;
        case DT_VERNEEDNUM:bit=4;needed=dyn.d_un.d_val;break;
        case DT_STRTAB:bit=8;strVA=dyn.d_un.d_ptr;break;
        case DT_STRSZ:bit=16;strBytes=dyn.d_un.d_val;break;
        default:break;
      }
      if(bit){if(seen&bit)return false;seen|=bit;}
    }
  }
  if(!found || !terminated || seen!=31 || !versymVA ||
     !needVA || !strVA || needed==0 || needed>32 ||
     strBytes==0 || strBytes>1024*1024 ||
     uint64_t(plt.symbolIndex)>(UINT64_MAX-versymVA)/2)
    return false;
  size_t strOffset=0,versymOffset=0;
  if(!d::SourceFileVA(source,bytes,e,strVA,strBytes,strOffset) ||
     !d::SourceFileVA(source,bytes,e,
         versymVA+uint64_t(plt.symbolIndex)*2,2,versymOffset))
    return false;
  uint16_t versym=0;
  std::memcpy(&versym,source+versymOffset,2);
  versym&=0x7fff;
  if(versym<2)return false;
  const auto* strings=source+strOffset;
  uint64_t cursor=needVA;
  size_t matches=0;
  for(uint64_t i=0;i<needed;++i){
    size_t noff=0;
    if(!d::SourceFileVA(source,bytes,e,cursor,sizeof(Elf64_Verneed),noff))
      return false;
    Elf64_Verneed need{};
    std::memcpy(&need,source+noff,sizeof(need));
    if(need.vn_version!=1 || !need.vn_cnt || need.vn_cnt>32 ||
       need.vn_aux<sizeof(Elf64_Verneed) ||
       cursor>UINT64_MAX-need.vn_aux)return false;
    char provider[64]{};
    if(!mainversions::CopyVersionName(
        strings,strBytes,need.vn_file,provider,sizeof(provider)))
      return false;
    uint64_t auxVA=cursor+need.vn_aux;
    for(unsigned k=0;k<need.vn_cnt;++k){
      size_t aoff=0;
      if(!d::SourceFileVA(source,bytes,e,auxVA,
                           sizeof(Elf64_Vernaux),aoff))return false;
      Elf64_Vernaux aux{};
      std::memcpy(&aux,source+aoff,sizeof(aux));
      if((aux.vna_other&0x7fff)==versym) {
        if(++matches!=1 || std::strcmp(provider,"libc.so.6")!=0 ||
           !mainversions::CopyVersionName(strings,strBytes,
              aux.vna_name,out.requiredVersion,
              sizeof(out.requiredVersion)))return false;
      }
      if(k+1<need.vn_cnt){
        if(aux.vna_next<sizeof(aux) ||
           auxVA>UINT64_MAX-aux.vna_next)return false;
        auxVA+=aux.vna_next;
      }
    }
    if(i+1<needed){
      if(need.vn_next<sizeof(need) ||
         cursor>UINT64_MAX-need.vn_next)return false;
      cursor+=need.vn_next;
    }
  }
  if(matches!=1)return false;
  out.mainVersionIndex=versym;
  out.mainSourceVerneedVerified=true;
  return true;
}
inline bool DefinedLibcVersion(
     const uint8_t* libc,size_t bytes,const mainpltsource::Witness& plt,
     const mainpltsource::LibcExportWitness& exported,
     Witness& out) noexcept {
  Elf64_Ehdr e{};
  if(!PinnedELFHeader(libc,bytes,e) ||
     e.e_shentsize!=sizeof(Elf64_Shdr) ||
     e.e_shnum==0 || e.e_shnum>256 ||
     e.e_shoff>bytes ||
     size_t(e.e_shnum)>(bytes-e.e_shoff)/sizeof(Elf64_Shdr) ||
     !out.mainSourceVerneedVerified ||
     !exported.boundedOriginalLibcDynsym ||
     exported.exactDefinedExportMatches!=1 ||
     exported.originalGNUResolverAlgorithmProven ||
     plt.guestValue!=exported.originalLibcBase+
                     exported.sourceSymbolVA)return false;
  auto readSection=[&](uint16_t index,Elf64_Shdr& result) noexcept {
    if(index>=e.e_shnum)return false;
    std::memcpy(&result,libc+e.e_shoff+size_t(index)*sizeof(result),
                sizeof(result));
    return result.sh_offset<=bytes &&
           (result.sh_type==SHT_NOBITS ||
            result.sh_size<=bytes-result.sh_offset);
  };
  Elf64_Shdr dynsym{},dynstr{},versym{},verdef{};
  uint16_t dynsymIndex=0;
  bool ds=false,vs=false,vd=false;
  for(uint16_t i=0;i<e.e_shnum;++i){
    Elf64_Shdr sh{};
    if(!readSection(i,sh))return false;
    if(sh.sh_type==SHT_DYNSYM) {
      if(ds || sh.sh_entsize!=sizeof(Elf64_Sym) ||
         !sh.sh_size || sh.sh_size%sizeof(Elf64_Sym) ||
         sh.sh_size/sizeof(Elf64_Sym)>16384 ||
         sh.sh_link>=e.e_shnum ||
         !readSection(static_cast<uint16_t>(sh.sh_link),dynstr) ||
         dynstr.sh_type!=SHT_STRTAB || !dynstr.sh_size ||
         dynstr.sh_size>2*1024*1024)return false;
      ds=true;dynsym=sh;dynsymIndex=i;
    }else if(sh.sh_type==SHT_GNU_versym) {
      if(vs || sh.sh_entsize!=sizeof(uint16_t) ||
         !sh.sh_size || sh.sh_size%2)return false;
      vs=true;versym=sh;
    }else if(sh.sh_type==SHT_GNU_verdef) {
      if(vd || !sh.sh_size || sh.sh_size>65536 ||
         !sh.sh_info || sh.sh_info>256)return false;
      vd=true;verdef=sh;
    }
  }
  if(!ds || !vs || !vd ||
     versym.sh_link!=dynsymIndex ||
     versym.sh_size/2<dynsym.sh_size/sizeof(Elf64_Sym) ||
     verdef.sh_link!=dynsym.sh_link)return false;
  const uint8_t* strings=libc+dynstr.sh_offset;
  size_t exportCandidates=0,exact=0;
  for(uint64_t i=0;i<dynsym.sh_size/sizeof(Elf64_Sym);++i){
    Elf64_Sym symbol{};
    std::memcpy(&symbol,libc+dynsym.sh_offset+
                        i*sizeof(symbol),sizeof(symbol));
    if(symbol.st_shndx==SHN_UNDEF ||
       symbol.st_value!=exported.sourceSymbolVA ||
       ELF64_ST_TYPE(symbol.st_info)!=STT_FUNC ||
       !libcsourceexports::SameBoundedELFName(
          strings,static_cast<size_t>(dynstr.sh_size),
          symbol.st_name,plt.symbolName))continue;
    ++exportCandidates;
    uint16_t idx=0;
    std::memcpy(&idx,libc+versym.sh_offset+i*2,2);
    if((idx&0x8000) || (idx&0x7fff)<2)continue;
    idx&=0x7fff;
    uint64_t at=0;
    size_t defMatches=0;
    for(uint32_t k=0;k<verdef.sh_info;++k){
      if(at>verdef.sh_size ||
         sizeof(Elf64_Verdef)>verdef.sh_size-at)return false;
      Elf64_Verdef def{};
      std::memcpy(&def,libc+verdef.sh_offset+at,sizeof(def));
      if(def.vd_version!=VER_DEF_CURRENT ||
         !def.vd_cnt || def.vd_cnt>32 ||
         !def.vd_aux || def.vd_aux>verdef.sh_size-at ||
         sizeof(Elf64_Verdaux)>verdef.sh_size-at-def.vd_aux ||
         (def.vd_ndx&0x7fff)==0)return false;
      if((def.vd_ndx&0x7fff)==idx){
        Elf64_Verdaux aux{};
        std::memcpy(&aux,libc+verdef.sh_offset+at+def.vd_aux,
                    sizeof(aux));
        char defName[64]{};
        if(!mainversions::CopyVersionName(
            strings,dynstr.sh_size,aux.vda_name,
            defName,sizeof(defName)))return false;
        if(std::strcmp(defName,out.requiredVersion)==0){
          if(++defMatches!=1)return false;
          std::memcpy(out.definedVersion,defName,sizeof(defName));
          out.libcVersionIndex=idx;
        }
      }
      if(k+1<verdef.sh_info){
        if(def.vd_next<sizeof(def) ||
           def.vd_next>verdef.sh_size-at)return false;
        at+=def.vd_next;
      }
    }
    if(defMatches==1)++exact;
  }
  if(exportCandidates!=1 || exact!=1)return false;
  out.libcSourceVersymVerdefVerified=true;
  out.exactVersionAndAddressMatched=true;
  return true;
}
inline bool AuditOriginalMainPLTLibcSymbolVersion(
   const uint8_t* main,size_t mainSize,bool pinnedMainSHA,
   const uint8_t* libc,size_t libcSize,bool pinnedLibcSHA,
   const mainpltsource::Witness& plt,
   const mainpltsource::LibcExportWitness& exported,
   Witness& out) noexcept {
  out={};
  if(!pinnedMainSHA || !pinnedLibcSHA ||
     !MainRequiredVersion(main,mainSize,plt,out))return false;
  return DefinedLibcVersion(libc,libcSize,plt,exported,out);
}
} // namespace kernix::g0::pltversions
