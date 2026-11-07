// SPDX-License-Identifier: MIT
#pragma once
// Bounded read-only comparison: exact SHA-attested original main
// DT_VERNEED requirements vs original libc defined DYNSYM symbols,
// source versym indices and source GNU VERDEF names.
// Does NOT perform symbol resolution, modify guest/host memory,
// certify the GNU ldso's algorithm or seal PT_GNU_RELRO.
#include "kernix_g0_original_main_relro_source_version_requirement_witness.h"
#include "kernix_g0_original_main_relro_libc_source_export_witness.h"
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <elf.h>
#include <limits>

namespace kernix::g0::libcversions {
struct VersionDefinition {
  uint32_t mainSymbolIndex=0;
  uint16_t sourceLibcVersionIndex=0;
  uint64_t sourceLibcSymbolVA=0;
  char symbol[96]{};
  char version[64]{};
};
struct Witness {
  std::array<VersionDefinition,2> checked{};
  size_t libcSymbolVersionExactMatches=0;
  size_t originalMainWeakZeroSlots=0;
  bool originalSourceLibcVersymAndVerdefVerified=false;
  bool originalGNUVersionedLookupExecuted=false;
  bool allOriginalLoaderRelocationsVerified=false;
};

inline bool AuditDefinedLibcSymbolVersions(
    const unsigned char* source,size_t bytes,
    bool pinnedLibcSHA256,uint64_t guestLibcLoadBias,
    const mainversions::Witness& mainRequired,
    const mainrelrotargets::Witness& mainReloc,
    const libcsourceexports::Witness& addresses,
    Witness& out) noexcept {
  out={};
  if(!source || !pinnedLibcSHA256 || !guestLibcLoadBias ||
     bytes<sizeof(Elf64_Ehdr) ||
     !mainRequired.originalImmutableSourceGnuVersymVerneedVerified ||
     mainRequired.originalLibcVersionDefinitionMatched ||
     mainRequired.originalGNUVersionedRelocationCompletion ||
     mainRequired.mainVersionRequirementsFound!=2 ||
     mainRequired.absentWeakZeroSlots!=3 ||
     !addresses.sourceLibcElf64DynsymVerified ||
     addresses.sourceLibcExactGuestAddressMatches!=2 ||
     addresses.mainNonzeroSymbolTargets!=2 ||
     addresses.weakUndefinedMainZeroSlots!=3 ||
     mainReloc.verifiedSymbolicNameCount!=5)
    return false;

  Elf64_Ehdr elf{};
  std::memcpy(&elf,source,sizeof(elf));
  if(std::memcmp(elf.e_ident,ELFMAG,SELFMAG)!=0 ||
     elf.e_ident[EI_CLASS]!=ELFCLASS64 ||
     elf.e_ident[EI_DATA]!=ELFDATA2LSB ||
     elf.e_ident[EI_VERSION]!=EV_CURRENT ||
     elf.e_type!=ET_DYN || elf.e_machine!=EM_X86_64 ||
     elf.e_phentsize!=sizeof(Elf64_Phdr) ||
     !elf.e_phnum || elf.e_phnum>128 ||
     elf.e_phoff>bytes ||
     size_t(elf.e_phnum)>(bytes-elf.e_phoff)/sizeof(Elf64_Phdr) ||
     elf.e_shentsize!=sizeof(Elf64_Shdr) ||
     !elf.e_shnum || elf.e_shnum>256 ||
     elf.e_shoff>bytes ||
     size_t(elf.e_shnum)>(bytes-elf.e_shoff)/sizeof(Elf64_Shdr))
    return false;
  const auto getSection=[&](uint16_t idx,Elf64_Shdr& section)
       noexcept -> bool {
    if(idx>=elf.e_shnum)return false;
    std::memcpy(&section,source+elf.e_shoff+
                 size_t(idx)*sizeof(section),sizeof(section));
    return section.sh_offset<=bytes &&
           section.sh_size<=bytes-section.sh_offset;
  };

  Elf64_Shdr dynsym{},dynstr{},versym{},verdef{};
  uint16_t dynsymIndex=0;
  bool foundDynsym=false,foundVersym=false,foundVerdef=false;
  for(uint16_t i=0;i<elf.e_shnum;++i){
    Elf64_Shdr sh{};
    if(!getSection(i,sh))return false;
    if(sh.sh_type==SHT_DYNSYM) {
      if(foundDynsym || sh.sh_entsize!=sizeof(Elf64_Sym) ||
         !sh.sh_size || sh.sh_size%sizeof(Elf64_Sym) ||
         sh.sh_size/sizeof(Elf64_Sym)>16384 ||
         !getSection(static_cast<uint16_t>(sh.sh_link),dynstr) ||
         sh.sh_link>=elf.e_shnum ||
         dynstr.sh_type!=SHT_STRTAB || !dynstr.sh_size ||
         dynstr.sh_size>2*1024*1024)
        return false;
      dynsym=sh;
      dynsymIndex=i;
      foundDynsym=true;
    }else if(sh.sh_type==SHT_GNU_versym){
      if(foundVersym || sh.sh_entsize!=sizeof(uint16_t) ||
         !sh.sh_size || sh.sh_size%sizeof(uint16_t))
        return false;
      versym=sh;
      foundVersym=true;
    }else if(sh.sh_type==SHT_GNU_verdef){
      if(foundVerdef || !sh.sh_size || sh.sh_size>65536 ||
         !sh.sh_info || sh.sh_info>256)
        return false;
      verdef=sh;
      foundVerdef=true;
    }
  }
  if(!foundDynsym || !foundVersym || !foundVerdef ||
     versym.sh_link!=dynsymIndex ||
     versym.sh_size/sizeof(uint16_t)<
       dynsym.sh_size/sizeof(Elf64_Sym) ||
     verdef.sh_link!=dynsym.sh_link)
    return false;
  const auto* names=source+dynstr.sh_offset;
  const uint64_t namesLength=dynstr.sh_size;

  // Validate the entire verdef linked chain first, then retain exact
  // index-to-version mappings for the two requested symbols.
  struct Def {uint16_t index=0;char name[64]{};};
  std::array<Def,256> defs{};
  size_t defCount=0;
  uint64_t at=0;
  for(uint32_t n=0;n<verdef.sh_info;++n){
    if(at>verdef.sh_size ||
       sizeof(Elf64_Verdef)>verdef.sh_size-at)return false;
    Elf64_Verdef def{};
    std::memcpy(&def,source+verdef.sh_offset+at,sizeof(def));
    if(def.vd_version!=VER_DEF_CURRENT || !def.vd_cnt ||
       def.vd_cnt>32 || (def.vd_ndx&0x7fff)==0 ||
       def.vd_aux<sizeof(Elf64_Verdef) ||
       def.vd_aux>verdef.sh_size-at ||
       sizeof(Elf64_Verdaux)>verdef.sh_size-at-def.vd_aux)
      return false;
    Elf64_Verdaux aux{};
    std::memcpy(&aux,source+verdef.sh_offset+at+def.vd_aux,
                sizeof(aux));
    for(size_t i=0;i<defCount;++i)
      if(defs[i].index==(def.vd_ndx&0x7fff))return false;
    defs[defCount].index=def.vd_ndx&0x7fff;
    if(!mainversions::CopyVersionName(
          names,namesLength,aux.vda_name,
          defs[defCount].name,sizeof(defs[defCount].name)))
      return false;
    ++defCount;
    if(n+1<verdef.sh_info){
      if(def.vd_next<sizeof(Elf64_Verdef) ||
         def.vd_next>verdef.sh_size-at)
        return false;
      at+=def.vd_next;
    }
  }

  for(size_t k=0;k<mainRequired.mainVersionRequirementsFound;++k){
    const auto& required=mainRequired.sourceRequired[k];
    if(std::strcmp(required.providerName,"libc.so.6")!=0)return false;
    const mainrelrotargets::NamedSymbol* rel=nullptr;
    for(size_t j=0;j<mainReloc.verifiedSymbolicNameCount;++j) {
      const auto& candidate=mainReloc.symbolicSourceNames[j];
      if(candidate.symbolIndex==required.originalSymbolIndex &&
         std::strcmp(candidate.name,required.symbolName)==0) {
        if(rel)return false;
        rel=&candidate;
      }
    }
    if(!rel || !rel->guestValue ||
       rel->guestValue<guestLibcLoadBias ||
       rel->type!=R_X86_64_GLOB_DAT)
      return false;
    const uint64_t expectedSourceVA=rel->guestValue-guestLibcLoadBias;
    bool exact=false;
    for(uint64_t i=0;i<dynsym.sh_size/sizeof(Elf64_Sym);++i) {
      Elf64_Sym symbol{};
      std::memcpy(&symbol,source+dynsym.sh_offset+
                   i*sizeof(symbol),sizeof(symbol));
      if(symbol.st_shndx==SHN_UNDEF ||
         !libcsourceexports::SameBoundedELFName(
           names,static_cast<size_t>(namesLength),
           symbol.st_name,required.symbolName) ||
         symbol.st_value!=expectedSourceVA)
        continue;
      const auto symbolType=ELF64_ST_TYPE(symbol.st_info);
      if(symbolType!=STT_FUNC && symbolType!=STT_OBJECT)
        continue;
      uint16_t sourceIndex=0;
      std::memcpy(&sourceIndex,source+versym.sh_offset+
                  i*sizeof(uint16_t),sizeof(sourceIndex));
      sourceIndex&=0x7fff;
      if(sourceIndex<2)continue;
      bool versionNameMatched=false;
      for(size_t d=0;d<defCount;++d) {
        if(defs[d].index!=sourceIndex ||
           std::strcmp(defs[d].name,required.requiredVersionName)!=0)
          continue;
        versionNameMatched=true;
      }
      if(!versionNameMatched)continue;
      // Verify the candidate belongs to original source libc PT_LOAD.
      bool originalSourceLoad=false;
      for(uint16_t p=0;p<elf.e_phnum;++p){
        Elf64_Phdr ph{};
        std::memcpy(&ph,source+elf.e_phoff+
                    size_t(p)*sizeof(ph),sizeof(ph));
        if(ph.p_type!=PT_LOAD || !(ph.p_flags&PF_R) ||
           symbol.st_value<ph.p_vaddr ||
           symbol.st_value-ph.p_vaddr>=ph.p_memsz)continue;
        originalSourceLoad=true;break;
      }
      if(!originalSourceLoad)continue;
      if(exact)return false; // ambiguous exact source exported definition
      exact=true;
      auto& dst=out.checked[k];
      dst.mainSymbolIndex=required.originalSymbolIndex;
      dst.sourceLibcVersionIndex=sourceIndex;
      dst.sourceLibcSymbolVA=symbol.st_value;
      std::memcpy(dst.symbol,required.symbolName,sizeof(dst.symbol));
      std::memcpy(dst.version,required.requiredVersionName,
                  sizeof(dst.version));
    }
    if(!exact)return false;
    ++out.libcSymbolVersionExactMatches;
  }
  out.originalMainWeakZeroSlots=mainRequired.absentWeakZeroSlots;
  out.originalSourceLibcVersymAndVerdefVerified=true;
  return out.libcSymbolVersionExactMatches==2 &&
         out.originalMainWeakZeroSlots==3;
}
} // namespace kernix::g0::libcversions
