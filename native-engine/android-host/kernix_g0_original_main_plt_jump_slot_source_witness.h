// SPDX-License-Identifier: MIT
#pragma once
// Read-only G0 witness for the single ORIGINAL main-ELF x86_64
// DT_JMPREL / R_X86_64_JUMP_SLOT entry. Source is SHA256-attested.
// Observe the owned guest GOT/PLT slot, but never force lazy binding,
// apply a relocation, seal RELRO or claim GNU ldso completion.
#include "kernix_g0_original_main_relro_source_relocation_target_audit.h"
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <elf.h>
#include <limits>

namespace kernix::g0::mainpltsource {
struct Witness {
  uint64_t guestTarget=0;
  uint64_t guestValue=0;
  uint32_t symbolIndex=0;
  unsigned binding=0;
  bool targetInMainRELRO=false;
  bool sourceFileBackedTarget=false;
  bool sourceValueMatchesLive=false;
  bool originalWritablePageVerified=false;
  bool authenticatedSourceJumpSlot=false;
  bool originalGNUJmpSlotResolutionProven=false;
  char symbolName[96]{};
};
inline bool ReadOnlyOriginalMainJumpSlot(
    const uint8_t* source,size_t bytes,bool attestedSHA256,
    const kernix::g2e::c3d7b::NativeChosenPIEGuestLayout& owned,
    const kernix::g2e::c3d7g::PermissionPlan& rights,
    uint64_t originalMainRELROPage,Witness& result) noexcept {
  result={};
  namespace d=kernix::g2e::c3d7i;
  namespace g=kernix::g2e::c3d7g;
  const auto* main=owned.Module(0);
  if(!source || !attestedSHA256 || !main || !owned.LaunchPlan() ||
     owned.WindowsHeld()!=4 || !rights.sourceShaVerified ||
     !rights.nativeGuestVAIdentityOwned ||
     main->loadBias!=main->chosenImageStart ||
     main->lowestAlignedELFVA!=0 ||
     !originalMainRELROPage || bytes<sizeof(Elf64_Ehdr))return false;
  Elf64_Ehdr eh{};
  std::memcpy(&eh,source,sizeof(eh));
  if(std::memcmp(eh.e_ident,ELFMAG,SELFMAG)!=0 ||
     eh.e_ident[EI_CLASS]!=ELFCLASS64 ||
     eh.e_ident[EI_DATA]!=ELFDATA2LSB ||
     eh.e_type!=ET_DYN || eh.e_machine!=EM_X86_64 ||
     eh.e_phentsize!=sizeof(Elf64_Phdr) || !eh.e_phnum ||
     eh.e_phnum>128 || eh.e_phoff>bytes ||
     size_t(eh.e_phnum)>(bytes-eh.e_phoff)/sizeof(Elf64_Phdr))
    return false;
  uint64_t jmprel=0,pltsz=0,symtab=0,strtab=0,strsz=0,syment=0;
  int64_t pltrel=0;
  unsigned dynamics=0;
  bool terminated=false,dup=false;
  unsigned seen=0;
  for(uint16_t i=0;i<eh.e_phnum;++i) {
    Elf64_Phdr ph{};
    std::memcpy(&ph,source+eh.e_phoff+i*sizeof(ph),sizeof(ph));
    if(ph.p_type!=PT_DYNAMIC)continue;
    if(++dynamics!=1 || ph.p_offset>bytes ||
       !ph.p_filesz || ph.p_filesz>65536 ||
       ph.p_filesz%sizeof(Elf64_Dyn) ||
       ph.p_filesz>bytes-ph.p_offset)return false;
    for(uint64_t off=0;off<ph.p_filesz;off+=sizeof(Elf64_Dyn)){
      Elf64_Dyn dyn{};
      std::memcpy(&dyn,source+ph.p_offset+off,sizeof(dyn));
      if(dyn.d_tag==DT_NULL){terminated=true;break;}
      unsigned bit=0;
      switch(dyn.d_tag){
        case DT_JMPREL: bit=1; jmprel=dyn.d_un.d_ptr;break;
        case DT_PLTRELSZ: bit=2; pltsz=dyn.d_un.d_val;break;
        case DT_PLTREL: bit=4; pltrel=dyn.d_un.d_val;break;
        case DT_SYMTAB: bit=8; symtab=dyn.d_un.d_ptr;break;
        case DT_SYMENT: bit=16; syment=dyn.d_un.d_val;break;
        case DT_STRTAB: bit=32; strtab=dyn.d_un.d_ptr;break;
        case DT_STRSZ: bit=64; strsz=dyn.d_un.d_val;break;
        default:break;
      }
      if(bit){if(seen&bit)dup=true;seen|=bit;}
    }
  }
  if(dynamics!=1 || !terminated || dup || seen!=127 ||
     pltrel!=DT_RELA || pltsz!=sizeof(Elf64_Rela) ||
     !jmprel || !symtab || !strtab || !strsz ||
     strsz>1024*1024 || syment!=sizeof(Elf64_Sym))return false;
  size_t relaOff=0,strOff=0;
  if(!d::SourceFileVA(source,bytes,eh,jmprel,pltsz,relaOff) ||
     !d::SourceFileVA(source,bytes,eh,strtab,strsz,strOff))
    return false;
  Elf64_Rela rela{};
  std::memcpy(&rela,source+relaOff,sizeof(rela));
  const auto sym=ELF64_R_SYM(rela.r_info);
  if(ELF64_R_TYPE(rela.r_info)!=R_X86_64_JUMP_SLOT ||
     sym==0 || uint64_t(sym)>(UINT64_MAX-symtab)/sizeof(Elf64_Sym))
    return false;
  size_t symOff=0;
  if(!d::SourceFileVA(source,bytes,eh,
       symtab+uint64_t(sym)*sizeof(Elf64_Sym),
       sizeof(Elf64_Sym),symOff))return false;
  Elf64_Sym defined{};
  std::memcpy(&defined,source+symOff,sizeof(defined));
  if(defined.st_shndx!=SHN_UNDEF ||
     defined.st_name>=strsz ||
     (ELF64_ST_TYPE(defined.st_info)!=STT_FUNC &&
      ELF64_ST_TYPE(defined.st_info)!=STT_NOTYPE))return false;
  const char* name=reinterpret_cast<const char*>(
     source+strOff+defined.st_name);
  const size_t available=static_cast<size_t>(strsz-defined.st_name);
  const void* ending=std::memchr(name,0,available);
  if(!ending)return false;
  const size_t len=static_cast<const char*>(ending)-name;
  if(len==0 || len>=sizeof(result.symbolName))return false;
  for(size_t i=0;i<len;++i)
    if(static_cast<unsigned char>(name[i])<33 ||
       static_cast<unsigned char>(name[i])>126)return false;
  if(rela.r_offset>UINT64_MAX-8 ||
     main->loadBias>UINT64_MAX-rela.r_offset)return false;
  const uint64_t target=main->loadBias+rela.r_offset;
  if(target<main->chosenImageStart ||
     target-main->chosenImageStart>g::kModulePages*4096ULL-8 ||
     (target&7)!=0)return false;
  bool originalRW=false;
  for(uint16_t i=0;i<eh.e_phnum;++i){
    Elf64_Phdr ph{};
    std::memcpy(&ph,source+eh.e_phoff+i*sizeof(ph),sizeof(ph));
    if(ph.p_type!=PT_LOAD ||
       (ph.p_flags&(PF_R|PF_W|PF_X))!=(PF_R|PF_W) ||
       rela.r_offset<ph.p_vaddr ||
       rela.r_offset-ph.p_vaddr>ph.p_memsz ||
       ph.p_memsz-(rela.r_offset-ph.p_vaddr)<8)continue;
    originalRW=true;break;
  }
  const size_t page=static_cast<size_t>(
       (target-main->chosenImageStart)/4096);
  if(!originalRW ||
     rights.modules[0].rights[page]!=(g::kRead|g::kWrite))
    return false;
  const auto* live=owned.GuestReadOnlyBytes(0,target,8);
  if(!live)return false;
  uint64_t value=0;
  std::memcpy(&value,live,8);
  const size_t sourceOffset=static_cast<size_t>(0);
  (void)sourceOffset;
  size_t originalOff=0;
  const bool fileBacked=d::SourceFileVA(
      source,bytes,eh,rela.r_offset,8,originalOff);
  result.guestTarget=target;
  result.guestValue=value;
  result.symbolIndex=sym;
  result.binding=ELF64_ST_BIND(defined.st_info);
  result.targetInMainRELRO=target>=originalMainRELROPage &&
                           target-originalMainRELROPage<4096;
  result.sourceFileBackedTarget=fileBacked;
  if(fileBacked){
    uint64_t fromSource=0;
    std::memcpy(&fromSource,source+originalOff,8);
    result.sourceValueMatchesLive=fromSource==value;
  }
  result.originalWritablePageVerified=true;
  result.authenticatedSourceJumpSlot=true;
  std::memcpy(result.symbolName,name,len);
  return true;
}
} // namespace kernix::g0::mainpltsource
