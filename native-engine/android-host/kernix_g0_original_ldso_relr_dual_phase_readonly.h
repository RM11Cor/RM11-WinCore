// SPDX-License-Identifier: MIT
#pragma once
// KERNIX G0 Linux ARM64: decode original GNU ld-linux x86_64 DT_RELR
// (11 authentic targets) from exact SHA-pinned ELF source and sample
// owned guest qwords BEFORE FEX and at the genuine main RELRO syscall.
// NO guest writing, no fake guest RIP, no ldso algorithm proof and
// no main RELRO protection change.
#include "kernix_g0_original_source_relr_target_witness.h"
#include "kernix_g2e_c3d7i_original_x86_dynamic_tls_relocation_contract.h"
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <elf.h>
#include <limits>

namespace kernix::g0::ldsorelr {
struct Entry {
  uint64_t target=0;
  uint64_t sourceAddend=0;
  uint64_t expected=0;
  uint64_t live=0;
  bool fileBacked=false;
};
struct Witness {
  std::array<Entry,16> entries{};
  size_t count=0,backed=0,unbacked=0;
  size_t expectedKnown=0,expectedMatching=0,expectedDifferent=0;
  size_t sourceMatching=0,sourceDifferent=0;
  bool attestedOriginalSource=false;
  bool guestLdsoWriteRIPTraced=false;
  bool originalRelocationClosureProven=false;
};
inline bool SampleOriginalLdsoRelrReadOnly(
    const uint8_t* source,size_t bytes,bool originalSourceSHA,
    const kernix::g2e::c3d7b::NativeChosenPIEGuestLayout& owned,
    const kernix::g2e::c3d7g::PermissionPlan& permission,
    Witness& out) noexcept {
  out={};
  namespace g=kernix::g2e::c3d7g;
  const auto* image=owned.Module(1);
  if(!originalSourceSHA || !source || !image ||
     !owned.LaunchPlan() || owned.WindowsHeld()!=4 ||
     !permission.sourceShaVerified ||
     !permission.nativeGuestVAIdentityOwned ||
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
  kernix::g0::relr::Phdrs ph{};
  ph.count=elf.e_phnum;
  bool seenDynamic=false;
  bool tagRelr=false,tagSize=false,tagEntry=false,terminated=false;
  uint64_t tableVA=0,tableSize=0,entrySize=0;
  for(uint16_t i=0;i<elf.e_phnum;++i){
    std::memcpy(&ph.entries[i],source+elf.e_phoff+
          size_t(i)*sizeof(Elf64_Phdr),sizeof(Elf64_Phdr));
    const auto& segment=ph.entries[i];
    if(segment.p_type!=PT_DYNAMIC)continue;
    if(seenDynamic || !segment.p_filesz ||
       segment.p_filesz>65536 ||
       segment.p_filesz%sizeof(Elf64_Dyn) ||
       segment.p_offset>bytes ||
       segment.p_filesz>bytes-segment.p_offset)return false;
    seenDynamic=true;
    for(uint64_t at=0;at<segment.p_filesz;at+=sizeof(Elf64_Dyn)){
      Elf64_Dyn dyn{};
      std::memcpy(&dyn,source+segment.p_offset+at,sizeof(dyn));
      if(dyn.d_tag==DT_NULL){terminated=true;break;}
      if(dyn.d_tag==DT_RELR) {
        if(tagRelr)return false;
        tagRelr=true;tableVA=dyn.d_un.d_ptr;
      }else if(dyn.d_tag==DT_RELRSZ){
        if(tagSize)return false;
        tagSize=true;tableSize=dyn.d_un.d_val;
      }else if(dyn.d_tag==DT_RELRENT){
        if(tagEntry)return false;
        tagEntry=true;entrySize=dyn.d_un.d_val;
      }
    }
    if(!terminated)return false;
  }
  if(!seenDynamic || !tagRelr || !tagSize || !tagEntry ||
     !tableSize || tableSize!=3*sizeof(uint64_t) ||
     entrySize!=sizeof(uint64_t))return false;
  size_t tableOffset=0;
  if(!kernix::g0::relr::SourcePTLoadFileVA(
         ph,bytes,tableVA,tableSize,tableOffset))
    return false;
  const auto capture=[&](uint64_t va) noexcept -> bool{
    if((va&7)!=0 || va>UINT64_MAX-image->loadBias)
      return false;
    const uint64_t guest=image->loadBias+va;
    if(guest<image->chosenImageStart ||
       guest-image->chosenImageStart>g::kModulePages*4096ULL-8 ||
       out.count>=out.entries.size())
       return false;
    const size_t pg=static_cast<size_t>(
      (guest-image->chosenImageStart)/4096);
    if((permission.modules[1].rights[pg]&(g::kRead|g::kWrite|g::kExecute))!=
          (g::kRead|g::kWrite))
       return false;
    bool sourceRW=false;
    for(uint16_t p=0;p<ph.count;++p){
      const auto& seg=ph.entries[p];
      if(seg.p_type!=PT_LOAD ||
         (seg.p_flags&(PF_R|PF_W|PF_X))!=(PF_R|PF_W) ||
         va<seg.p_vaddr || va-seg.p_vaddr>seg.p_memsz ||
         seg.p_memsz-(va-seg.p_vaddr)<8)continue;
      sourceRW=true;break;
    }
    if(!sourceRW)return false;
    auto& record=out.entries[out.count];
    for(size_t earlier=0;earlier<out.count;++earlier)
      if(out.entries[earlier].target==guest)return false;
    const auto* live=owned.GuestReadOnlyBytes(1,guest,8);
    if(!live)return false;
    record.target=guest;
    std::memcpy(&record.live,live,8);
    size_t sourceOffset=0;
    if(kernix::g0::relr::SourcePTLoadFileVA(
         ph,bytes,va,8,sourceOffset)){
      std::memcpy(&record.sourceAddend,source+sourceOffset,8);
      record.fileBacked=true;
      ++out.backed;
    }else {
      // Valid source BSS has zero initial addend; classify separately,
      // not as an invented file-byte source value.
      record.sourceAddend=0;
      ++out.unbacked;
    }
    if(record.sourceAddend>UINT64_MAX-image->loadBias)return false;
    record.expected=image->loadBias+record.sourceAddend;
    ++out.expectedKnown;
    if(record.live==record.expected)++out.expectedMatching;
    else ++out.expectedDifferent;
    if(record.live==record.sourceAddend)++out.sourceMatching;
    else ++out.sourceDifferent;
    ++out.count;
    return true;
  };
  uint64_t cursor=0;
  bool hasBase=false;
  for(uint64_t i=0;i<tableSize/8;++i){
    uint64_t word=0;
    std::memcpy(&word,source+tableOffset+i*8,8);
    if((word&1)==0){
      if(word>UINT64_MAX-8 || !capture(word))return false;
      cursor=word+8;hasBase=true;
    }else{
      if(!hasBase || cursor>UINT64_MAX-63*8)return false;
      for(unsigned bit=1;bit<64;++bit){
        if(!(word&(uint64_t(1)<<bit)))continue;
        const uint64_t next=cursor+uint64_t(bit-1)*8;
        if(!capture(next))return false;
      }
      cursor+=63*8;
    }
  }
  if(out.count!=11 || out.expectedKnown!=11 ||
     out.backed+out.unbacked!=11 ||
     out.expectedMatching+out.expectedDifferent!=11 ||
     out.sourceMatching+out.sourceDifferent!=11)
    return false;
  out.attestedOriginalSource=true;
  return true;
}
} // namespace kernix::g0::ldsorelr
