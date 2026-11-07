// SPDX-License-Identifier: MIT
#pragma once
// G0 observation-only: source-authenticated ORIGINAL main x86_64 ELF
// DT_RELA targets that lie in the one exact, still-writable PT_GNU_RELRO
// page requested by real upstream FEX original GNU ld-linux.
// Never seal, rewrite a pointer, invoke guest/host loader or claim
// full relocation completion from a value comparison: selected x86
// RELA/RELR fixture stores may precede original GNU ld-linux execution.
#include "kernix_g2e_c3d7i_original_x86_dynamic_tls_relocation_contract.h"
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <elf.h>
#include <limits>

namespace kernix::g0::mainrelrotargets {
struct Witness {
  size_t sourceMainRelaEntries=0;
  size_t sourceRelaTargetsInThisRELROPage=0;
  size_t relativeTargetsInRELRO=0;
  size_t relativeTargetsMatchingLoadBiasAddend=0;
  size_t relativeTargetsNotMatchingExpected=0;
  size_t symbolicTargetsInRELRO=0;
  size_t irelativeTargetsInRELRO=0;
  size_t sourceMainPLTRelaEntries=0;
  bool sourceMainELF64DynamicVerified=false;
  bool originalMainOwnedGuestRWPageVerified=false;
  bool readOnlyTargetInspection=true;
  bool originalGNUDynamicRelocationClosureProven=false;
};

// Source ELF bytes must come from the already SHA-256-verified immutable
// GuestPreflight snapshot, never from untrusted x86 register pointers.
// The live target read is limited to one independently source-authorized
// owned guest RW page. No native host file or path access.
inline bool AuditOriginalMainRELROTargets(
    const uint8_t* source,size_t bytes,bool originalSourceSHA256Attested,
    const kernix::g2e::c3d7b::NativeChosenPIEGuestLayout& owned,
    const kernix::g2e::c3d7g::PermissionPlan& permission,
    uint64_t relroGuestPage,bool originalPageNativeRW,
    Witness& out) noexcept {
  out={};
  namespace d=kernix::g2e::c3d7i;
  namespace g=kernix::g2e::c3d7g;
  const auto* main=owned.Module(0);
  if(!originalSourceSHA256Attested || !source ||
     !main || !owned.LaunchPlan() || owned.WindowsHeld()!=4 ||
     !originalPageNativeRW ||
     !permission.sourceShaVerified ||
     !permission.nativeGuestVAIdentityOwned ||
     main->loadBias!=main->chosenImageStart ||
     main->lowestAlignedELFVA!=0 ||
     relroGuestPage<main->chosenImageStart ||
     (relroGuestPage&4095)!=0 ||
     relroGuestPage-main->chosenImageStart>
       g::kModulePages*4096ULL-4096 ||
     !owned.GuestReadOnlyBytes(0,relroGuestPage,4096))
    return false;
  const size_t page=static_cast<size_t>(
    (relroGuestPage-main->chosenImageStart)/4096);
  if(permission.modules[0].rights[page]!=(g::kRead|g::kWrite))
    return false;
  out.originalMainOwnedGuestRWPageVerified=true;
  if(bytes<sizeof(Elf64_Ehdr))return false;
  Elf64_Ehdr elf{};
  std::memcpy(&elf,source,sizeof(elf));
  if(std::memcmp(elf.e_ident,ELFMAG,SELFMAG)!=0 ||
     elf.e_ident[EI_CLASS]!=ELFCLASS64 ||
     elf.e_ident[EI_DATA]!=ELFDATA2LSB ||
     elf.e_ident[EI_VERSION]!=EV_CURRENT ||
     elf.e_type!=ET_DYN || elf.e_machine!=EM_X86_64 ||
     elf.e_phentsize!=sizeof(Elf64_Phdr) ||
     elf.e_phnum==0 || elf.e_phnum>128 ||
     elf.e_phoff>bytes ||
     size_t(elf.e_phnum)>(bytes-elf.e_phoff)/sizeof(Elf64_Phdr))
    return false;
  bool foundDynamic=false,terminated=false;
  uint64_t relaVA=0,relaBytes=0,relaEnt=0,pltBytes=0;
  bool seenRELA=false,seenRELASZ=false,seenRELAENT=false;
  for(uint16_t i=0;i<elf.e_phnum;++i) {
    Elf64_Phdr ph{};
    std::memcpy(&ph,source+elf.e_phoff+
      size_t(i)*sizeof(ph),sizeof(ph));
    if(ph.p_type!=PT_DYNAMIC)continue;
    if(foundDynamic || !ph.p_filesz ||
       ph.p_filesz>65536 || ph.p_filesz%sizeof(Elf64_Dyn) ||
       ph.p_offset>bytes || ph.p_filesz>bytes-ph.p_offset)
      return false;
    foundDynamic=true;
    for(uint64_t j=0;j<ph.p_filesz;j+=sizeof(Elf64_Dyn)){
      Elf64_Dyn val{};
      std::memcpy(&val,source+ph.p_offset+j,sizeof(val));
      if(val.d_tag==DT_NULL){terminated=true;break;}
      if(val.d_tag==DT_RELA){
        if(seenRELA)return false;
        seenRELA=true;relaVA=val.d_un.d_ptr;
      }else if(val.d_tag==DT_RELASZ){
        if(seenRELASZ)return false;
        seenRELASZ=true;relaBytes=val.d_un.d_val;
      }else if(val.d_tag==DT_RELAENT){
        if(seenRELAENT)return false;
        seenRELAENT=true;relaEnt=val.d_un.d_val;
      }else if(val.d_tag==DT_PLTRELSZ){
        pltBytes=val.d_un.d_val;
      }
    }
  }
  if(!foundDynamic || !terminated || !seenRELA ||
     !seenRELASZ || !seenRELAENT ||
     relaEnt!=sizeof(Elf64_Rela) ||
     !relaBytes || relaBytes%sizeof(Elf64_Rela) ||
     relaBytes/sizeof(Elf64_Rela)>32768 ||
     pltBytes%sizeof(Elf64_Rela))
    return false;
  size_t offset=0;
  if(!d::SourceFileVA(source,bytes,elf,relaVA,relaBytes,offset))
    return false;
  out.sourceMainRelaEntries=static_cast<size_t>(
    relaBytes/sizeof(Elf64_Rela));
  out.sourceMainPLTRelaEntries=static_cast<size_t>(
    pltBytes/sizeof(Elf64_Rela));
  for(size_t i=0;i<out.sourceMainRelaEntries;++i) {
    Elf64_Rela entry{};
    std::memcpy(&entry,source+offset+i*sizeof(entry),
      sizeof(entry));
    if(entry.r_offset>UINT64_MAX-8 ||
       main->loadBias>UINT64_MAX-entry.r_offset)
      return false;
    const uint64_t guest=main->loadBias+entry.r_offset;
    if(guest<relroGuestPage ||
       guest-relroGuestPage>4096-8)continue;
    // Every in-RELRO dynamic target must remain within its bounded
    // original PF_R|PF_W load, never imported executable or host memory.
    bool originalRW=false;
    for(uint16_t j=0;j<elf.e_phnum;++j) {
      Elf64_Phdr ph{};
      std::memcpy(&ph,source+elf.e_phoff+
        size_t(j)*sizeof(ph),sizeof(ph));
      if(ph.p_type!=PT_LOAD ||
         (ph.p_flags&(PF_R|PF_W|PF_X))!=(PF_R|PF_W) ||
         entry.r_offset<ph.p_vaddr ||
         entry.r_offset-ph.p_vaddr>ph.p_memsz ||
         8>ph.p_memsz-(entry.r_offset-ph.p_vaddr))
        continue;
      originalRW=true;break;
    }
    if(!originalRW || !owned.GuestReadOnlyBytes(0,guest,8))
      return false;
    ++out.sourceRelaTargetsInThisRELROPage;
    const auto type=ELF64_R_TYPE(entry.r_info);
    if(type==R_X86_64_RELATIVE) {
      ++out.relativeTargetsInRELRO;
      uint64_t live=0;
      std::memcpy(&live,owned.GuestReadOnlyBytes(0,guest,8),8);
      if(entry.r_addend>=0 &&
         main->loadBias<=UINT64_MAX-uint64_t(entry.r_addend) &&
         live==main->loadBias+uint64_t(entry.r_addend))
        ++out.relativeTargetsMatchingLoadBiasAddend;
      else ++out.relativeTargetsNotMatchingExpected;
    } else if(type==R_X86_64_IRELATIVE) {
      ++out.irelativeTargetsInRELRO;
    } else {
      ++out.symbolicTargetsInRELRO;
    }
  }
  out.sourceMainELF64DynamicVerified=true;
  return true;
}
} // namespace kernix::g0::mainrelrotargets
