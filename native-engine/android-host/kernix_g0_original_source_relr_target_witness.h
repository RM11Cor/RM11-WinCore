#pragma once
// SPDX-License-Identifier: MIT
// G0 original GNU x86_64 ELF DT_RELR source witness, NOT original
// ld-linux relocation execution. All bytes are input from a separate
// SHA-256-verified immutable guest ELF snapshot. No guest pointer, host
// address, native mmap/mprotect, or source ELF is ever modified here.
// A candidate comes from a genuine compact RELR descriptor, is aligned,
// points at a PF_R|PF_W non-PF_X source PT_LOAD, and its source addend
// refers back to the original ELF image. It remains a *preflight*
// until the real FEX x86 guest is seen writing the source target.
#include <elf.h>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#ifndef DT_RELR
#define DT_RELR 36
#endif
#ifndef DT_RELRSZ
#define DT_RELRSZ 35
#endif
#ifndef DT_RELRENT
#define DT_RELRENT 37
#endif
namespace kernix::g0::relr {
enum class Reject : uint8_t {
  None, OriginalSourceNotAttested, MalformedELF,
  MissingDynamic, DuplicateDynamic, MissingRELR,
  MalformedRELR, InvalidTarget, NoSafeSourceTarget
};
struct Witness {
  uint64_t sourceTableVA=0;
  uint64_t sourceTableSize=0;
  uint64_t sourceDescriptorWord=0;
  uint64_t sourceDescriptorIndex=0;
  uint64_t sourceTargetVA=0;
  uint64_t sourceTargetFileOffset=0;
  uint64_t sourceInitialAddend=0;
  uint64_t guestLoadBias=0;
  uint64_t guestTarget=0;
  uint64_t expectedRelocatedPointer=0;
  size_t relrWords=0;
  size_t totalDecodedTargets=0;
  size_t sourceBackedWritableTargets=0;
  size_t sourceImageAddendCandidates=0;
  bool authenticSourceELF64DynamicRELR=false;
  bool verifiedGuestRWTargetNotExecutable=false;
  bool sourceDescriptorDecoded=false;
  bool guestRelocationActuallyExecuted=false;
  bool originalLdsoRelocationActuallyExecuted=false;
};
struct Phdrs {
  std::array<Elf64_Phdr,128> entries{};
  uint16_t count=0;
};
inline bool SourcePTLoadFileVA(const Phdrs& segments,size_t bytes,
                              uint64_t va,uint64_t n,size_t& at) noexcept {
  if(n==0 || va>UINT64_MAX-n)return false;
  for(size_t i=0;i<segments.count;++i){
    const auto& p=segments.entries[i];
    if(p.p_type!=PT_LOAD || va<p.p_vaddr ||
       p.p_offset>bytes || p.p_filesz>bytes-p.p_offset)continue;
    const uint64_t delta=va-p.p_vaddr;
    if(delta>p.p_filesz || n>p.p_filesz-delta)continue;
    at=static_cast<size_t>(p.p_offset+delta);
    return true;
  }
  return false;
}
inline bool SourcePointerInsidePTLoad(const Phdrs& ph,uint64_t va) noexcept {
  for(size_t i=0;i<ph.count;++i){
    const auto& p=ph.entries[i];
    if(p.p_type!=PT_LOAD || !p.p_memsz ||
       p.p_vaddr>UINT64_MAX-p.p_memsz)continue;
    if(va>=p.p_vaddr && va-p.p_vaddr<p.p_memsz)return true;
  }
  return false;
}
inline bool SourceTargetInWritableNonExecutablePTLoad(
    const Phdrs& ph,size_t bytes,uint64_t va,size_t& at) noexcept {
  if((va&7U)!=0)return false;
  for(size_t i=0;i<ph.count;++i){
    const auto& p=ph.entries[i];
    if(p.p_type!=PT_LOAD ||
       (p.p_flags&(PF_R|PF_W|PF_X))!=(PF_R|PF_W) ||
       p.p_offset>bytes || p.p_filesz>bytes-p.p_offset ||
       va<p.p_vaddr)continue;
    const uint64_t offset=va-p.p_vaddr;
    if(offset>p.p_filesz || sizeof(uint64_t)>p.p_filesz-offset)
      continue;
    at=static_cast<size_t>(p.p_offset+offset);
    return true;
  }
  return false;
}
inline bool SourceOriginalRELRWitness(
    const uint8_t* bytes,size_t n,bool exactSourceSHA256Attested,
    uint64_t candidateGuestLoadBias,Witness& result,
    Reject& reason) noexcept {
  result={};
  reason=Reject::OriginalSourceNotAttested;
  if(!exactSourceSHA256Attested || !bytes)return false;
  reason=Reject::MalformedELF;
  if(n<sizeof(Elf64_Ehdr) || n>4*1024*1024)return false;
  Elf64_Ehdr eh{};
  std::memcpy(&eh,bytes,sizeof(eh));
  if(std::memcmp(eh.e_ident,ELFMAG,SELFMAG)!=0 ||
     eh.e_ident[EI_CLASS]!=ELFCLASS64 ||
     eh.e_ident[EI_DATA]!=ELFDATA2LSB ||
     eh.e_ident[EI_VERSION]!=EV_CURRENT ||
     eh.e_machine!=EM_X86_64 ||
     eh.e_type!=ET_DYN ||
     eh.e_phentsize!=sizeof(Elf64_Phdr) ||
     eh.e_phnum==0 || eh.e_phnum>128 ||
     eh.e_phoff>n ||
     static_cast<size_t>(eh.e_phnum)>(n-eh.e_phoff)/sizeof(Elf64_Phdr))
    return false;
  Phdrs ph{};
  ph.count=eh.e_phnum;
  for(size_t i=0;i<ph.count;++i){
    std::memcpy(&ph.entries[i],
      bytes+static_cast<size_t>(eh.e_phoff)+i*sizeof(Elf64_Phdr),
      sizeof(Elf64_Phdr));
    const auto& p=ph.entries[i];
    if(p.p_type==PT_LOAD &&
       (p.p_offset>n || p.p_filesz>n-p.p_offset ||
        p.p_filesz>p.p_memsz || p.p_vaddr>UINT64_MAX-p.p_memsz ||
        (p.p_offset%4096)!=(p.p_vaddr%4096) ||
        (p.p_flags&(PF_W|PF_X))==(PF_W|PF_X)))return false;
  }
  reason=Reject::MissingDynamic;
  bool dynamicSeen=false,tagRelr=false,tagSize=false,tagEntry=false;
  uint64_t tableVA=0,tableSize=0,entryBytes=0;
  for(size_t i=0;i<ph.count;++i){
    const auto& p=ph.entries[i];
    if(p.p_type!=PT_DYNAMIC)continue;
    if(dynamicSeen){reason=Reject::DuplicateDynamic;return false;}
    dynamicSeen=true;
    reason=Reject::MalformedELF;
    if(!p.p_filesz || p.p_filesz>65536 ||
       p.p_filesz%sizeof(Elf64_Dyn) ||
       p.p_offset>n || p.p_filesz>n-p.p_offset)return false;
    bool end=false;
    for(uint64_t off=0;off<p.p_filesz;off+=sizeof(Elf64_Dyn)){
      Elf64_Dyn d{};
      std::memcpy(&d,bytes+static_cast<size_t>(p.p_offset+off),sizeof(d));
      if(d.d_tag==DT_NULL){end=true;break;}
      if(d.d_tag==DT_RELR){
        if(tagRelr){reason=Reject::DuplicateDynamic;return false;}
        tagRelr=true;tableVA=d.d_un.d_ptr;
      }else if(d.d_tag==DT_RELRSZ){
        if(tagSize){reason=Reject::DuplicateDynamic;return false;}
        tagSize=true;tableSize=d.d_un.d_val;
      }else if(d.d_tag==DT_RELRENT){
        if(tagEntry){reason=Reject::DuplicateDynamic;return false;}
        tagEntry=true;entryBytes=d.d_un.d_val;
      }
    }
    if(!end)return false;
  }
  if(!dynamicSeen){reason=Reject::MissingDynamic;return false;}
  reason=Reject::MissingRELR;
  if(!tagRelr || !tagSize || !tagEntry || !tableSize)return false;
  reason=Reject::MalformedRELR;
  if(entryBytes!=sizeof(uint64_t) ||
     tableSize%sizeof(uint64_t) ||
     tableSize/sizeof(uint64_t)>65536 ||
     tableVA>UINT64_MAX-tableSize)return false;
  size_t tableFileOff=0;
  if(!SourcePTLoadFileVA(ph,n,tableVA,tableSize,tableFileOff))
    return false;
  Witness selected{};
  selected.sourceTableVA=tableVA;
  selected.sourceTableSize=tableSize;
  selected.relrWords=static_cast<size_t>(tableSize/8);
  selected.guestLoadBias=candidateGuestLoadBias;
  uint64_t cursor=0;
  bool first=true;
  const auto inspect=[&](uint64_t target,uint64_t word,
                         uint64_t index,Witness& w) noexcept -> bool {
    if(target&7U)return false;
    ++w.totalDecodedTargets;
    size_t sourceOffset=0;
    if(!SourceTargetInWritableNonExecutablePTLoad(
           ph,n,target,sourceOffset))return false;
    ++w.sourceBackedWritableTargets;
    uint64_t originalAddend=0;
    std::memcpy(&originalAddend,bytes+sourceOffset,8);
    if(!SourcePointerInsidePTLoad(ph,originalAddend))return true;
    ++w.sourceImageAddendCandidates;
    if(w.authenticSourceELF64DynamicRELR)return true;
    if(candidateGuestLoadBias>UINT64_MAX-originalAddend ||
       candidateGuestLoadBias>UINT64_MAX-target)return true;
    w.sourceDescriptorWord=word;
    w.sourceDescriptorIndex=index;
    w.sourceTargetVA=target;
    w.sourceTargetFileOffset=sourceOffset;
    w.sourceInitialAddend=originalAddend;
    w.guestTarget=candidateGuestLoadBias+target;
    w.expectedRelocatedPointer=candidateGuestLoadBias+originalAddend;
    w.authenticSourceELF64DynamicRELR=true;
    w.verifiedGuestRWTargetNotExecutable=true;
    w.sourceDescriptorDecoded=true;
    return true;
  };
  for(uint64_t i=0;i<tableSize/8;++i){
    uint64_t word=0;
    std::memcpy(&word,bytes+tableFileOff+static_cast<size_t>(i*8),8);
    if((word&1)==0){
      if(word>UINT64_MAX-8 || !inspect(word,word,i,selected)){
        reason=Reject::InvalidTarget;return false;
      }
      cursor=word+8;first=false;
    }else {
      if(first || cursor>UINT64_MAX-63*8){
        reason=Reject::MalformedRELR;return false;
      }
      for(unsigned bit=1;bit<64;++bit){
        if(!(word&(uint64_t(1)<<bit)))continue;
        const uint64_t target=cursor+uint64_t(bit-1)*8;
        if(!inspect(target,word,i,selected)){
          reason=Reject::InvalidTarget;return false;
        }
      }
      cursor+=63*8;
    }
  }
  if(!selected.authenticSourceELF64DynamicRELR){
    reason=Reject::NoSafeSourceTarget;return false;
  }
  result=selected;
  reason=Reject::None;
  return true;
}
} // namespace kernix::g0::relr
