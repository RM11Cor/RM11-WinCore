// SPDX-License-Identifier: MIT
#pragma once
// Linux ARM64 G0: exact SHA-pinned original libc.so.6 compact DT_RELR
// source decode and READ-ONLY observation of 1067 owned guest targets.
// Two timepoints are observed, *before* the genuine original libc
// PT_GNU_RELRO mprotect and at the later original main mprotect.
// No IFUNC execution, guest relocation writes, host syscall forwarding,
// source mutation or new RELRO seal. Changed guest qwords alone do NOT
// prove the responsible x86 instruction RIP or full relocation closure.
#include "kernix_g2e_c3d7i_original_x86_dynamic_tls_relocation_contract.h"
#include "kernix_g0_source_pinned_libc_large_ro_guest_map.h"
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <elf.h>
#include <limits>

namespace kernix::g0::libcrelr {
struct Entry {
  uint64_t guest=0,sourceAddend=0,expected=0,live=0;
  bool fileBacked=false;
};
struct Witness {
  std::array<Entry,1067> entries{};
  size_t count=0,sourceBacked=0,sourceBSS=0;
  size_t liveEqualSource=0,liveEqualExpected=0;
  bool originalLibcSHAProven=false;
  bool actualGuestStoreRIPsTraced=false;
  bool fullOriginalRelocationClosureProven=false;
};

template <typename AddressPermissions>
inline bool SampleOriginalLibc1067RELRReadOnly(
    const uint8_t* source,size_t bytes,bool exactSHA,
    const kernix::g0::PinnedLibcLargeReadonlyGuestMap& map,
    AddressPermissions&& readableOwnedGuestData,
    Witness& result) noexcept {
  result={};
  namespace d=kernix::g2e::c3d7i;
  const uint64_t base=map.Address();
  if(!source || !exactSHA || !base ||
     bytes!=kernix::g0::PinnedLibcLargeReadonlyGuestMap::kOriginalLibcSize ||
     !map.OriginalOwnedBSSZeroed() ||
     map.BytesHeld()!=0x212000ULL ||
     map.CopiedSourceBytes()!=bytes ||
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
  std::array<Elf64_Phdr,128> phdrs{};
  uint64_t relrVA=0,relrSize=0,relrEntry=0;
  bool dynamicFound=false,dynamicTerminated=false;
  unsigned tags=0;
  for(uint16_t i=0;i<elf.e_phnum;++i){
    Elf64_Phdr ph{};
    std::memcpy(&ph,source+elf.e_phoff+
        size_t(i)*sizeof(ph),sizeof(ph));
    phdrs[i]=ph;
    if(ph.p_type!=PT_DYNAMIC)continue;
    if(dynamicFound || ph.p_offset>bytes ||
       !ph.p_filesz || ph.p_filesz>65536 ||
       ph.p_filesz>bytes-ph.p_offset ||
       ph.p_filesz%sizeof(Elf64_Dyn))
      return false;
    dynamicFound=true;
    for(uint64_t at=0;at<ph.p_filesz;at+=sizeof(Elf64_Dyn)){
      Elf64_Dyn dyn{};
      std::memcpy(&dyn,source+ph.p_offset+at,sizeof(dyn));
      if(dyn.d_tag==DT_NULL){dynamicTerminated=true;break;}
      unsigned bit=0;
      if(dyn.d_tag==DT_RELR){bit=1;relrVA=dyn.d_un.d_ptr;}
      else if(dyn.d_tag==DT_RELRSZ){bit=2;relrSize=dyn.d_un.d_val;}
      else if(dyn.d_tag==DT_RELRENT){bit=4;relrEntry=dyn.d_un.d_val;}
      if(bit){if(tags&bit)return false;tags|=bit;}
    }
    if(!dynamicTerminated)return false;
  }
  if(!dynamicFound || !dynamicTerminated || tags!=7 ||
     relrEntry!=sizeof(uint64_t) ||
     relrSize!=32*sizeof(uint64_t))
    return false;
  size_t fileOffset=0;
  if(!d::SourceFileVA(source,bytes,elf,relrVA,relrSize,fileOffset))
    return false;
  const auto capture=[&](uint64_t va) noexcept -> bool {
    if((va&7)!=0 || va>UINT64_MAX-base)return false;
    bool writableNonexecPTLoad=false;
    for(uint16_t j=0;j<elf.e_phnum;++j){
      const auto& ph=phdrs[j];
      if(ph.p_type!=PT_LOAD ||
         (ph.p_flags&(PF_R|PF_W|PF_X))!=(PF_R|PF_W) ||
         va<ph.p_vaddr || va-ph.p_vaddr>ph.p_memsz ||
         ph.p_memsz-(va-ph.p_vaddr)<8)continue;
      writableNonexecPTLoad=true;break;
    }
    if(!writableNonexecPTLoad)return false;
    const uint64_t guest=base+va;
    if(guest<base || guest-base>map.BytesHeld()-8 ||
       result.count>=result.entries.size() ||
       (result.count && guest<=result.entries[result.count-1].guest) ||
       !readableOwnedGuestData(guest))
      return false;
    auto& slot=result.entries[result.count];
    slot.guest=guest;
    size_t sourceOffset=0;
    if(d::SourceFileVA(source,bytes,elf,va,8,sourceOffset)){
      std::memcpy(&slot.sourceAddend,source+sourceOffset,8);
      slot.fileBacked=true;
      ++result.sourceBacked;
    }else{
      // Source zero-fill beyond PT_LOAD p_filesz, not a fabricated
      // source byte value. Ownership + currently readable VMA checked.
      slot.sourceAddend=0;
      ++result.sourceBSS;
    }
    if(slot.sourceAddend>UINT64_MAX-base)return false;
    slot.expected=base+slot.sourceAddend;
    std::memcpy(&slot.live,reinterpret_cast<const void*>(
         static_cast<uintptr_t>(guest)),8);
    result.liveEqualSource+=size_t(slot.live==slot.sourceAddend);
    result.liveEqualExpected+=size_t(slot.live==slot.expected);
    ++result.count;
    return true;
  };
  uint64_t cursor=0;
  bool first=true;
  for(size_t i=0;i<relrSize/8;++i){
    uint64_t word=0;
    std::memcpy(&word,source+fileOffset+i*8,8);
    if((word&1)==0){
      if(word>UINT64_MAX-8 || !capture(word))return false;
      cursor=word+8;
      first=false;
    }else{
      if(first || cursor>UINT64_MAX-63*8)return false;
      for(unsigned bit=1;bit<64;++bit){
        if(!(word&(uint64_t(1)<<bit)))continue;
        if(!capture(cursor+uint64_t(bit-1)*8))return false;
      }
      cursor+=63*8;
    }
  }
  if(result.count!=1067 ||
     result.sourceBacked+result.sourceBSS!=1067 ||
     result.liveEqualSource>result.count ||
     result.liveEqualExpected>result.count)return false;
  result.originalLibcSHAProven=true;
  return true;
}
} // namespace kernix::g0::libcrelr
