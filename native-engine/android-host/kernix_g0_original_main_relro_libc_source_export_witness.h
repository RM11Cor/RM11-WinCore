// SPDX-License-Identifier: MIT
#pragma once
// KERNIX G0: original SHA-verified source glibc ELF dynamic symbol
// address comparison against two NONZERO original main GLOB_DAT slots.
// Read-only source metadata / live guest qwords observed by the existing
// GLOB_DAT witness. Does not implement ELF symbol version/IFUNC semantics,
// dynamic-linker resolution, relocation closure or main GNU_RELRO sealing.
#include "kernix_g0_original_main_relro_source_relocation_target_audit.h"
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <elf.h>
#include <limits>

namespace kernix::g0::libcsourceexports {
struct Witness {
  size_t mainNonzeroSymbolTargets=0;
  size_t sourceLibcDefinedSymbolNamesFound=0;
  size_t sourceLibcExactGuestAddressMatches=0;
  size_t weakUndefinedMainZeroSlots=0;
  bool sourceLibcElf64DynsymVerified=false;
  bool comparedOnlyOriginalOwnedLibcMap=false;
  bool originalLdsoSymbolVersioningVerified=false;
  bool originalLdsoAllRelocationsFinished=false;
};
inline bool SameBoundedELFName(const unsigned char* table,
     size_t bytes,uint32_t at,const char* expected) noexcept {
  if(!table || !expected || at>=bytes)return false;
  const size_t available=bytes-at;
  const char* ptr=reinterpret_cast<const char*>(table+at);
  const void* end=std::memchr(ptr,0,available);
  if(!end)return false;
  const size_t len=static_cast<const char*>(end)-ptr;
  return len>0 && len<96 && std::strlen(expected)==len &&
         std::memcmp(ptr,expected,len)==0;
}
inline bool AuditOriginalLibcExports(
    const unsigned char* libcSource,size_t libcSize,
    bool originalLibcSHA256Verified,uint64_t verifiedNativeGuestLibcBase,
    const mainrelrotargets::Witness& main,
    Witness& result) noexcept {
  result={};
  if(!originalLibcSHA256Verified || !libcSource ||
     !verifiedNativeGuestLibcBase ||
     !main.sourceMainELF64DynamicVerified ||
     !main.originalMainOwnedGuestRWPageVerified ||
     main.originalGNUDynamicRelocationClosureProven ||
     main.verifiedSymbolicNameCount!=5 ||
     main.symbolicTargetsInRELRO!=5 ||
     main.symbolicTargetsLiveNonzero!=2 ||
     main.symbolicTargetsLiveZero!=3 ||
     libcSize<sizeof(Elf64_Ehdr))return false;
  Elf64_Ehdr elf{};
  std::memcpy(&elf,libcSource,sizeof(elf));
  if(std::memcmp(elf.e_ident,ELFMAG,SELFMAG)!=0 ||
     elf.e_ident[EI_CLASS]!=ELFCLASS64 ||
     elf.e_ident[EI_DATA]!=ELFDATA2LSB ||
     elf.e_ident[EI_VERSION]!=EV_CURRENT ||
     elf.e_type!=ET_DYN ||
     elf.e_machine!=EM_X86_64 ||
     elf.e_phentsize!=sizeof(Elf64_Phdr) ||
     elf.e_phnum==0 || elf.e_phnum>128 ||
     elf.e_phoff>libcSize ||
     size_t(elf.e_phnum)>(libcSize-elf.e_phoff)/sizeof(Elf64_Phdr) ||
     elf.e_shentsize!=sizeof(Elf64_Shdr) ||
     elf.e_shnum==0 || elf.e_shnum>256 ||
     elf.e_shoff>libcSize ||
     size_t(elf.e_shnum)>(libcSize-elf.e_shoff)/sizeof(Elf64_Shdr))
    return false;
  Elf64_Shdr dynsym{},strtab{};
  bool found=false;
  for(uint16_t i=0;i<elf.e_shnum;++i) {
    Elf64_Shdr sh{};
    std::memcpy(&sh,libcSource+elf.e_shoff+
                size_t(i)*sizeof(sh),sizeof(sh));
    if(sh.sh_type!=SHT_DYNSYM)continue;
    if(found || sh.sh_entsize!=sizeof(Elf64_Sym) ||
       !sh.sh_size || sh.sh_size%sizeof(Elf64_Sym) ||
       sh.sh_size/sizeof(Elf64_Sym)>16384 ||
       sh.sh_offset>libcSize || sh.sh_size>libcSize-sh.sh_offset ||
       sh.sh_link>=elf.e_shnum)return false;
    std::memcpy(&strtab,libcSource+elf.e_shoff+
        size_t(sh.sh_link)*sizeof(strtab),sizeof(strtab));
    if(strtab.sh_type!=SHT_STRTAB ||
       !strtab.sh_size || strtab.sh_size>2*1024*1024 ||
       strtab.sh_offset>libcSize ||
       strtab.sh_size>libcSize-strtab.sh_offset)return false;
    dynsym=sh;found=true;
  }
  if(!found)return false;
  result.sourceLibcElf64DynsymVerified=true;
  const auto* strings=libcSource+strtab.sh_offset;
  const size_t stringCount=static_cast<size_t>(strtab.sh_size);
  for(size_t k=0;k<main.verifiedSymbolicNameCount;++k) {
    const auto& slot=main.symbolicSourceNames[k];
    if(slot.type!=R_X86_64_GLOB_DAT || slot.sourceDefinition)
      return false;
    if(!slot.guestValue) {
      if(slot.binding!=STB_WEAK)return false;
      ++result.weakUndefinedMainZeroSlots;
      continue;
    }
    // No other guest memory is read; the two values were already
    // collected by the exact one-page main PT_GNU_RELRO audit.
    ++result.mainNonzeroSymbolTargets;
    if(slot.guestValue<verifiedNativeGuestLibcBase)return false;
    const uint64_t symbolValue=
        slot.guestValue-verifiedNativeGuestLibcBase;
    bool nameFound=false,exact=false;
    for(uint64_t pos=0;pos<dynsym.sh_size;pos+=sizeof(Elf64_Sym)) {
      Elf64_Sym symbol{};
      std::memcpy(&symbol,libcSource+dynsym.sh_offset+pos,
                  sizeof(symbol));
      if(!SameBoundedELFName(strings,stringCount,symbol.st_name,
                             slot.name))continue;
      if(symbol.st_shndx==SHN_UNDEF)continue;
      const auto ty=ELF64_ST_TYPE(symbol.st_info);
      if(ty!=STT_FUNC && ty!=STT_OBJECT && ty!=STT_GNU_IFUNC)
         continue;
      nameFound=true;
      if(symbol.st_value!=symbolValue ||
         symbol.st_value>UINT64_MAX-8)continue;
      // The matching symbol must point into a defined source glibc
      // PT_LOAD, not any unauthenticated guest or host address.
      bool mapped=false;
      for(uint16_t j=0;j<elf.e_phnum;++j) {
        Elf64_Phdr ph{};
        std::memcpy(&ph,libcSource+elf.e_phoff+
                    size_t(j)*sizeof(ph),sizeof(ph));
        if(ph.p_type!=PT_LOAD ||
           (ph.p_flags&PF_R)==0 ||
           symbol.st_value<ph.p_vaddr ||
           symbol.st_value-ph.p_vaddr>=ph.p_memsz)
          continue;
        mapped=true;break;
      }
      if(mapped)exact=true;
    }
    if(nameFound)++result.sourceLibcDefinedSymbolNamesFound;
    if(exact)++result.sourceLibcExactGuestAddressMatches;
  }
  result.comparedOnlyOriginalOwnedLibcMap=true;
  return true;
}
} // namespace kernix::g0::libcsourceexports
