// SPDX-License-Identifier: MIT
#pragma once
// Source-only GNU version requirement probe for the two NONZERO original
// main ELF GLOB_DAT slots. It never performs symbol lookup, relocation,
// host writes, guest mprotect, or a claim that the GNU dynamic linker
// selected matching versions in source libc.
#include "kernix_g0_original_main_relro_source_relocation_target_audit.h"
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <elf.h>
#include <limits>

namespace kernix::g0::mainversions {
struct SymbolVersion {
  uint16_t originalVersymIndex=0;
  uint32_t originalSymbolIndex=0;
  char symbolName[96]{};
  char providerName[64]{};
  char requiredVersionName[64]{};
};
struct Witness {
  std::array<SymbolVersion,2> sourceRequired{};
  size_t mainNonzeroGLOB_DAT=0;
  size_t mainVersionRequirementsFound=0;
  size_t absentWeakZeroSlots=0;
  bool originalImmutableSourceGnuVersymVerneedVerified=false;
  bool originalLibcVersionDefinitionMatched=false;
  bool originalGNUVersionedRelocationCompletion=false;
};
inline bool CopyVersionName(const unsigned char* strings,
    uint64_t bytes,uint32_t offset,char* dest,size_t cap) noexcept {
  if(!strings || !dest || offset>=bytes || cap<2)return false;
  const void* end=std::memchr(strings+offset,0,
                              static_cast<size_t>(bytes-offset));
  if(!end)return false;
  const size_t length=static_cast<const unsigned char*>(end)-
                      (strings+offset);
  if(!length || length>=cap)return false;
  for(size_t k=0;k<length;++k)
    if(strings[offset+k]<33 || strings[offset+k]>126)return false;
  std::memcpy(dest,strings+offset,length);
  return true;
}
inline bool CheckSourceMainGNUVersionRequirements(
    const unsigned char* source,size_t n,bool exactSourceSHA256,
    const mainrelrotargets::Witness& main,Witness& out) noexcept {
  out={};
  namespace dyn=kernix::g2e::c3d7i;
  if(!source || !exactSourceSHA256 ||
     !main.sourceMainELF64DynamicVerified ||
     main.originalGNUDynamicRelocationClosureProven ||
     main.verifiedSymbolicNameCount!=5 ||
     main.symbolicTargetsGlobDat!=5 ||
     main.symbolicTargetsLiveNonzero!=2 ||
     main.symbolicTargetsLiveZero!=3 || n<sizeof(Elf64_Ehdr))
    return false;
  Elf64_Ehdr elf{};
  std::memcpy(&elf,source,sizeof(elf));
  if(std::memcmp(elf.e_ident,ELFMAG,SELFMAG)!=0 ||
     elf.e_ident[EI_CLASS]!=ELFCLASS64 ||
     elf.e_ident[EI_DATA]!=ELFDATA2LSB ||
     elf.e_type!=ET_DYN || elf.e_machine!=EM_X86_64 ||
     elf.e_phentsize!=sizeof(Elf64_Phdr) ||
     !elf.e_phnum || elf.e_phnum>128 ||
     elf.e_phoff>n ||
     size_t(elf.e_phnum)>(n-elf.e_phoff)/sizeof(Elf64_Phdr))
    return false;
  uint64_t versymVA=0,verneedVA=0,verneedCount=0;
  uint64_t strVA=0,strBytes=0;
  bool seenVersym=false,seenNeed=false,seenNeedCount=false;
  bool seenStr=false,seenStrBytes=false,foundDynamic=false,terminated=false;
  for(uint16_t i=0;i<elf.e_phnum;++i) {
    Elf64_Phdr ph{};
    std::memcpy(&ph,source+elf.e_phoff+
                size_t(i)*sizeof(ph),sizeof(ph));
    if(ph.p_type!=PT_DYNAMIC)continue;
    if(foundDynamic || !ph.p_filesz || ph.p_filesz>65536 ||
       ph.p_filesz%sizeof(Elf64_Dyn) ||
       ph.p_offset>n || ph.p_filesz>n-ph.p_offset)return false;
    foundDynamic=true;
    for(uint64_t off=0;off<ph.p_filesz;off+=sizeof(Elf64_Dyn)) {
      Elf64_Dyn v{};
      std::memcpy(&v,source+ph.p_offset+off,sizeof(v));
      if(v.d_tag==DT_NULL){terminated=true;break;}
      if(v.d_tag==DT_VERSYM) {
        if(seenVersym)return false;
        seenVersym=true;versymVA=v.d_un.d_ptr;
      }else if(v.d_tag==DT_VERNEED) {
        if(seenNeed)return false;
        seenNeed=true;verneedVA=v.d_un.d_ptr;
      }else if(v.d_tag==DT_VERNEEDNUM) {
        if(seenNeedCount)return false;
        seenNeedCount=true;verneedCount=v.d_un.d_val;
      }else if(v.d_tag==DT_STRTAB){
        if(seenStr)return false;
        seenStr=true;strVA=v.d_un.d_ptr;
      }else if(v.d_tag==DT_STRSZ){
        if(seenStrBytes)return false;
        seenStrBytes=true;strBytes=v.d_un.d_val;
      }
    }
  }
  if(!foundDynamic || !terminated || !seenVersym || !seenNeed ||
     !seenNeedCount || !seenStr || !seenStrBytes ||
     !versymVA || !verneedVA || !strVA ||
     !verneedCount || verneedCount>32 ||
     !strBytes || strBytes>1024*1024)return false;
  size_t stringOffset=0;
  if(!dyn::SourceFileVA(source,n,elf,strVA,strBytes,stringOffset))
     return false;
  const unsigned char* strings=source+stringOffset;
  for(size_t i=0;i<main.verifiedSymbolicNameCount;++i) {
    const auto& slot=main.symbolicSourceNames[i];
    if(slot.type!=R_X86_64_GLOB_DAT ||
       slot.sourceDefinition)return false;
    if(!slot.guestValue) {
      if(slot.binding!=STB_WEAK)return false;
      ++out.absentWeakZeroSlots;
      continue;
    }
    if(out.mainNonzeroGLOB_DAT>=out.sourceRequired.size() ||
       uint64_t(slot.symbolIndex)>(UINT64_MAX-versymVA)/2)
      return false;
    ++out.mainNonzeroGLOB_DAT;
    size_t versymOffset=0;
    if(!dyn::SourceFileVA(source,n,elf,
       versymVA+uint64_t(slot.symbolIndex)*2,2,versymOffset))
      return false;
    uint16_t versym=0;
    std::memcpy(&versym,source+versymOffset,sizeof(versym));
    const uint16_t required=versym&0x7fff;
    if(required<2)return false;
    SymbolVersion rec{};
    rec.originalVersymIndex=required;
    rec.originalSymbolIndex=slot.symbolIndex;
    std::memcpy(rec.symbolName,slot.name,sizeof(rec.symbolName));
    uint64_t cursor=verneedVA;
    bool matched=false;
    for(uint64_t node=0;node<verneedCount;++node) {
      size_t needOffset=0;
      if(!dyn::SourceFileVA(source,n,elf,cursor,
           sizeof(Elf64_Verneed),needOffset))return false;
      Elf64_Verneed need{};
      std::memcpy(&need,source+needOffset,sizeof(need));
      if(need.vn_version!=1 || !need.vn_cnt || need.vn_cnt>32 ||
         need.vn_aux<sizeof(Elf64_Verneed) ||
         cursor>UINT64_MAX-need.vn_aux)return false;
      char provider[64]{};
      if(!CopyVersionName(strings,strBytes,need.vn_file,
                          provider,sizeof(provider)))return false;
      uint64_t auxVA=cursor+need.vn_aux;
      for(uint16_t k=0;k<need.vn_cnt;++k) {
        size_t auxOffset=0;
        if(!dyn::SourceFileVA(source,n,elf,auxVA,
          sizeof(Elf64_Vernaux),auxOffset))return false;
        Elf64_Vernaux aux{};
        std::memcpy(&aux,source+auxOffset,sizeof(aux));
        if((aux.vna_other&0x7fff)==required){
          if(matched)return false;
          matched=true;
          std::memcpy(rec.providerName,provider,sizeof(provider));
          if(!CopyVersionName(strings,strBytes,aux.vna_name,
                  rec.requiredVersionName,
                  sizeof(rec.requiredVersionName)))return false;
        }
        if(k+1<need.vn_cnt){
          if(aux.vna_next<sizeof(Elf64_Vernaux) ||
             auxVA>UINT64_MAX-aux.vna_next)return false;
          auxVA+=aux.vna_next;
        }
      }
      if(node+1<verneedCount){
        if(need.vn_next<sizeof(Elf64_Verneed) ||
           cursor>UINT64_MAX-need.vn_next)return false;
        cursor+=need.vn_next;
      }
    }
    if(!matched)return false;
    out.sourceRequired[out.mainVersionRequirementsFound++]=rec;
  }
  out.originalImmutableSourceGnuVersymVerneedVerified=true;
  return out.mainNonzeroGLOB_DAT==2 &&
         out.mainVersionRequirementsFound==2 &&
         out.absentWeakZeroSlots==3;
}
} // namespace kernix::g0::mainversions
