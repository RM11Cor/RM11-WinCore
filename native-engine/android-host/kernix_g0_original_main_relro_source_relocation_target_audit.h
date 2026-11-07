// SPDX-License-Identifier: MIT
#pragma once
// G0 observation-only: source-authenticated ORIGINAL main x86_64 ELF
// DT_RELA targets that lie in the one exact, still-writable PT_GNU_RELRO
// page requested by real upstream FEX original GNU ld-linux.
// Never seal, rewrite a pointer, invoke guest/host loader or claim
// full relocation completion from a value comparison: selected x86
// RELA/RELR fixture stores may precede original GNU ld-linux execution.
#include "kernix_g2e_c3d7i_original_x86_dynamic_tls_relocation_contract.h"
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <elf.h>
#include <limits>

namespace kernix::g0::mainrelrotargets {
struct OriginalRelativeSlot {
  uint64_t guestTarget=0;
  uint64_t expectedValue=0;
  uint64_t guestValue=0;
  bool targetInRELRO=false;
};
struct NamedSymbol {
  uint64_t guestTarget=0;
  uint64_t guestValue=0;
  uint32_t symbolIndex=0;
  uint8_t binding=0;
  uint8_t type=0;
  bool sourceDefinition=false;
  char name[96]{};
};
struct Witness {
  std::array<NamedSymbol,16> symbolicSourceNames{};
  std::array<OriginalRelativeSlot,2> relativeRELROSlots{};
  size_t verifiedSymbolicNameCount=0;
  size_t weakSymbolCount=0;
  size_t weakSymbolLiveZeroCount=0;
  size_t strongSymbolCount=0;
  size_t strongSymbolLiveZeroCount=0;
  size_t sourceMainRelaEntries=0;
  size_t sourceRelaTargetsInThisRELROPage=0;
  size_t relativeTargetsInRELRO=0;
  size_t relativeTargetsMatchingLoadBiasAddend=0;
  size_t relativeTargetsNotMatchingExpected=0;
  size_t symbolicTargetsInRELRO=0;
  size_t symbolicTargetsGlobDat=0;
  size_t symbolicTargetsOther=0;
  size_t symbolicTargetsLiveZero=0;
  size_t symbolicTargetsLiveNonzero=0;
  size_t symbolicTargetsSourceFileBacked=0;
  size_t symbolicTargetsSourceNotFileBacked=0;
  size_t symbolicTargetsUnchangedFromOriginalFile=0;
  size_t symbolicTargetsDifferentFromOriginalFile=0;
  size_t symbolicTargetsLiveOwnedOriginalELF=0;
  size_t symbolicTargetsLiveNotInOriginalOwnedELF=0;
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
  uint64_t symbolVA=0,stringVA=0,stringBytes=0,symbolEntrySize=0;
  bool seenRELA=false,seenRELASZ=false,seenRELAENT=false;
  bool seenSYMTAB=false,seenSYMENT=false,seenSTRTAB=false,seenSTRSZ=false;
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
      }else if(val.d_tag==DT_SYMTAB){
        if(seenSYMTAB)return false;
        seenSYMTAB=true;symbolVA=val.d_un.d_ptr;
      }else if(val.d_tag==DT_SYMENT){
        if(seenSYMENT)return false;
        seenSYMENT=true;symbolEntrySize=val.d_un.d_val;
      }else if(val.d_tag==DT_STRTAB){
        if(seenSTRTAB)return false;
        seenSTRTAB=true;stringVA=val.d_un.d_ptr;
      }else if(val.d_tag==DT_STRSZ){
        if(seenSTRSZ)return false;
        seenSTRSZ=true;stringBytes=val.d_un.d_val;
      }
    }
  }
  if(!foundDynamic || !terminated || !seenRELA ||
     !seenRELASZ || !seenRELAENT ||
     relaEnt!=sizeof(Elf64_Rela) ||
     !relaBytes || relaBytes%sizeof(Elf64_Rela) ||
     relaBytes/sizeof(Elf64_Rela)>32768 ||
     pltBytes%sizeof(Elf64_Rela) ||
     !seenSYMTAB || !seenSYMENT ||
     !seenSTRTAB || !seenSTRSZ ||
     symbolEntrySize!=sizeof(Elf64_Sym) ||
     stringBytes==0 || stringBytes>1024*1024)
    return false;
  size_t offset=0,stringsOffset=0;
  if(!d::SourceFileVA(source,bytes,elf,relaVA,relaBytes,offset) ||
     !d::SourceFileVA(source,bytes,elf,stringVA,stringBytes,stringsOffset))
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
      if(out.relativeTargetsInRELRO>=out.relativeRELROSlots.size())
        return false;
      const auto pos=out.relativeTargetsInRELRO++;
      uint64_t live=0,expected=0;
      std::memcpy(&live,owned.GuestReadOnlyBytes(0,guest,8),8);
      if(entry.r_addend>=0) {
        if(main->loadBias>UINT64_MAX-uint64_t(entry.r_addend))
          return false;
        expected=main->loadBias+uint64_t(entry.r_addend);
      }else{
        const uint64_t magnitude=uint64_t(-(entry.r_addend+1))+1;
        if(main->loadBias<magnitude)return false;
        expected=main->loadBias-magnitude;
      }
      out.relativeRELROSlots[pos]={guest,expected,live,true};
      if(live==expected)++out.relativeTargetsMatchingLoadBiasAddend;
      else ++out.relativeTargetsNotMatchingExpected;
    } else if(type==R_X86_64_IRELATIVE) {
      ++out.irelativeTargetsInRELRO;
    } else {
      // These are genuine original source ELF relocations, but the
      // original source .rela.dyn may require symbol versioning, IFUNC
      // resolution, external libc or the original ldso. A changed
      // 8-byte value is NOT proof of correct symbol resolution.
      ++out.symbolicTargetsInRELRO;
      if(type==R_X86_64_GLOB_DAT)
        ++out.symbolicTargetsGlobDat;
      else ++out.symbolicTargetsOther;
      // Name is extracted from the ORIGINAL immutable ELF symbol and
      // string tables; it does NOT infer which module resolved it.
      const uint32_t symbolIndex=ELF64_R_SYM(entry.r_info);
      if(!symbolIndex ||
         out.verifiedSymbolicNameCount>=out.symbolicSourceNames.size() ||
         uint64_t(symbolIndex)>UINT64_MAX/sizeof(Elf64_Sym) ||
         symbolVA>UINT64_MAX-uint64_t(symbolIndex)*sizeof(Elf64_Sym))
        return false;
      size_t symbolFileOffset=0;
      if(!d::SourceFileVA(source,bytes,elf,
           symbolVA+uint64_t(symbolIndex)*sizeof(Elf64_Sym),
           sizeof(Elf64_Sym),symbolFileOffset))
        return false;
      Elf64_Sym symbol{};
      std::memcpy(&symbol,source+symbolFileOffset,sizeof(symbol));
      if(symbol.st_name>=stringBytes)return false;
      const char* originalName=reinterpret_cast<const char*>(
          source+stringsOffset+symbol.st_name);
      const size_t available=static_cast<size_t>(
          stringBytes-symbol.st_name);
      const void* end=std::memchr(originalName,0,available);
      if(!end)return false;
      const size_t nameLength=
        static_cast<const char*>(end)-originalName;
      auto& named=out.symbolicSourceNames[
        out.verifiedSymbolicNameCount];
      if(!nameLength || nameLength>=sizeof(named.name))return false;
      for(size_t k=0;k<nameLength;++k) {
        if(static_cast<unsigned char>(originalName[k])<33 ||
           static_cast<unsigned char>(originalName[k])>126)
          return false; // protect diagnostic log integrity
      }
      std::memcpy(named.name,originalName,nameLength);
      named.guestTarget=guest;
      named.symbolIndex=symbolIndex;
      named.binding=ELF64_ST_BIND(symbol.st_info);
      named.type=static_cast<uint8_t>(type);
      named.sourceDefinition=symbol.st_shndx!=SHN_UNDEF;
      ++out.verifiedSymbolicNameCount;
      uint64_t live=0;
      std::memcpy(&live,owned.GuestReadOnlyBytes(0,guest,8),8);
      named.guestValue=live;
      if(named.binding==STB_WEAK){
        ++out.weakSymbolCount;
        if(live==0)++out.weakSymbolLiveZeroCount;
      }else{
        ++out.strongSymbolCount;
        if(live==0)++out.strongSymbolLiveZeroCount;
      }
      if(live==0)++out.symbolicTargetsLiveZero;
      else ++out.symbolicTargetsLiveNonzero;
      size_t fileOffset=0;
      if(d::SourceFileVA(source,bytes,elf,entry.r_offset,8,
                          fileOffset)) {
        ++out.symbolicTargetsSourceFileBacked;
        uint64_t original=0;
        std::memcpy(&original,source+fileOffset,8);
        if(original==live)
          ++out.symbolicTargetsUnchangedFromOriginalFile;
        else ++out.symbolicTargetsDifferentFromOriginalFile;
      } else {
        // A non-file-backed target is NOT assumed to be source-zero
        // or "relocated"; classify it separately and do not read any
        // unowned host/guest page.
        ++out.symbolicTargetsSourceNotFileBacked;
      }
      bool originalOwned=false;
      if(live!=0) {
        for(size_t moduleIndex=0;moduleIndex<3;++moduleIndex) {
          const auto* module=owned.Module(moduleIndex);
          if(!module ||
             live<module->chosenImageStart ||
             live-module->chosenImageStart>
                g::kModulePages*4096ULL-1)
            continue;
          if(owned.GuestReadOnlyBytes(moduleIndex,live,1)) {
            originalOwned=true;
            break;
          }
        }
        if(originalOwned)++out.symbolicTargetsLiveOwnedOriginalELF;
        else ++out.symbolicTargetsLiveNotInOriginalOwnedELF;
      }
    }
  }
  out.sourceMainELF64DynamicVerified=true;
  return true;
}

// Source-only, read-only inventory of original main .rela.dyn RELATIVE
// targets outside its PT_GNU_RELRO page. Complements the existing
// in-RELRO two-target witness. It does not perform relocations or
// certify that the unmodified GNU ldso performed a particular write.
struct OutsideRELRORelativeWitness {
  size_t mainRelaEntries=0;
  size_t relativeEntries=0;
  size_t insideRELROEntries=0;
  size_t outsideRELROEntries=0;
  size_t outsideValueMatches=0;
  size_t outsideValueDiffers=0;
  uint64_t outsideTarget=0;
  uint64_t outsideExpected=0;
  uint64_t outsideLive=0;
  bool outsideSourceOriginalRWPTLoad=false;
  bool outsideGuestOwnedNativeRWPage=false;
  bool originalLdsoRelocationClosureProven=false;
};
inline bool AuditOriginalMainRelativeOutsideRELRO(
    const uint8_t* source,size_t size,bool attestedMainSHA,
    const kernix::g2e::c3d7b::NativeChosenPIEGuestLayout& owned,
    const kernix::g2e::c3d7g::PermissionPlan& permission,
    uint64_t relroPage,OutsideRELRORelativeWitness& out) noexcept {
  out={};
  namespace d=kernix::g2e::c3d7i;
  namespace g=kernix::g2e::c3d7g;
  const auto* main=owned.Module(0);
  if(!attestedMainSHA || !source || !main ||
     !owned.LaunchPlan() || owned.WindowsHeld()!=4 ||
     !permission.sourceShaVerified ||
     !permission.nativeGuestVAIdentityOwned ||
     main->lowestAlignedELFVA!=0 ||
     main->loadBias!=main->chosenImageStart ||
     (relroPage&4095)!=0 || size<sizeof(Elf64_Ehdr))
    return false;
  Elf64_Ehdr elf{};
  std::memcpy(&elf,source,sizeof(elf));
  if(std::memcmp(elf.e_ident,ELFMAG,SELFMAG)!=0 ||
     elf.e_ident[EI_CLASS]!=ELFCLASS64 ||
     elf.e_ident[EI_DATA]!=ELFDATA2LSB ||
     elf.e_type!=ET_DYN || elf.e_machine!=EM_X86_64 ||
     elf.e_phentsize!=sizeof(Elf64_Phdr) ||
     !elf.e_phnum || elf.e_phnum>128 ||
     elf.e_phoff>size ||
     size_t(elf.e_phnum)>(size-elf.e_phoff)/sizeof(Elf64_Phdr))
    return false;
  uint64_t relaVA=0,relaBytes=0,relaEnt=0;
  bool dynamicSeen=false,terminated=false;
  unsigned flags=0;
  for(uint16_t p=0;p<elf.e_phnum;++p){
    Elf64_Phdr ph{};
    std::memcpy(&ph,source+elf.e_phoff+size_t(p)*sizeof(ph),sizeof(ph));
    if(ph.p_type!=PT_DYNAMIC)continue;
    if(dynamicSeen || !ph.p_filesz ||
       ph.p_filesz>65536 || ph.p_offset>size ||
       ph.p_filesz>size-ph.p_offset ||
       ph.p_filesz%sizeof(Elf64_Dyn))return false;
    dynamicSeen=true;
    for(uint64_t j=0;j<ph.p_filesz;j+=sizeof(Elf64_Dyn)){
      Elf64_Dyn dtag{};
      std::memcpy(&dtag,source+ph.p_offset+j,sizeof(dtag));
      if(dtag.d_tag==DT_NULL){terminated=true;break;}
      unsigned bit=0;
      if(dtag.d_tag==DT_RELA){bit=1;relaVA=dtag.d_un.d_ptr;}
      if(dtag.d_tag==DT_RELASZ){bit=2;relaBytes=dtag.d_un.d_val;}
      if(dtag.d_tag==DT_RELAENT){bit=4;relaEnt=dtag.d_un.d_val;}
      if(bit){if(flags&bit)return false;flags|=bit;}
    }
  }
  if(!dynamicSeen || !terminated || flags!=7 ||
     relaEnt!=sizeof(Elf64_Rela) ||
     !relaBytes || relaBytes%relaEnt ||
     relaBytes/relaEnt>32768)return false;
  size_t sourceOffset=0;
  if(!d::SourceFileVA(source,size,elf,relaVA,relaBytes,sourceOffset))
    return false;
  out.mainRelaEntries=static_cast<size_t>(relaBytes/relaEnt);
  for(size_t i=0;i<out.mainRelaEntries;++i){
    Elf64_Rela r{};
    std::memcpy(&r,source+sourceOffset+i*sizeof(r),sizeof(r));
    if(ELF64_R_TYPE(r.r_info)!=R_X86_64_RELATIVE)continue;
    if(ELF64_R_SYM(r.r_info)!=0 ||
       main->loadBias>UINT64_MAX-r.r_offset)return false;
    ++out.relativeEntries;
    const uint64_t target=main->loadBias+r.r_offset;
    if(target>=relroPage && target-relroPage<4096){
      ++out.insideRELROEntries;
      continue;
    }
    ++out.outsideRELROEntries;
    if(out.outsideRELROEntries>1 ||
       r.r_offset>UINT64_MAX-8 ||
       target<main->chosenImageStart ||
       target-main->chosenImageStart>g::kModulePages*4096ULL-8 ||
       (target&7)!=0)return false;
    for(uint16_t p=0;p<elf.e_phnum;++p){
      Elf64_Phdr ph{};
      std::memcpy(&ph,source+elf.e_phoff+size_t(p)*sizeof(ph),sizeof(ph));
      if(ph.p_type!=PT_LOAD ||
         (ph.p_flags&(PF_R|PF_W|PF_X))!=(PF_R|PF_W) ||
         r.r_offset<ph.p_vaddr ||
         r.r_offset-ph.p_vaddr>ph.p_memsz ||
         ph.p_memsz-(r.r_offset-ph.p_vaddr)<8)continue;
      out.outsideSourceOriginalRWPTLoad=true;
      break;
    }
    if(!out.outsideSourceOriginalRWPTLoad)return false;
    const size_t pg=static_cast<size_t>(
        (target-main->chosenImageStart)/4096);
    if(permission.modules[0].rights[pg]!=(g::kRead|g::kWrite))
      return false;
    const auto* live=owned.GuestReadOnlyBytes(0,target,8);
    if(!live)return false;
    out.outsideGuestOwnedNativeRWPage=true;
    out.outsideTarget=target;
    std::memcpy(&out.outsideLive,live,8);
    if(r.r_addend>=0){
      if(main->loadBias>UINT64_MAX-uint64_t(r.r_addend))
        return false;
      out.outsideExpected=main->loadBias+uint64_t(r.r_addend);
    }else{
      const uint64_t magnitude=uint64_t(-(r.r_addend+1))+1;
      if(main->loadBias<magnitude)return false;
      out.outsideExpected=main->loadBias-magnitude;
    }
    if(out.outsideLive==out.outsideExpected)
      ++out.outsideValueMatches;
    else ++out.outsideValueDiffers;
  }
  return out.outsideRELROEntries==1 &&
         out.outsideValueMatches+out.outsideValueDiffers==1 &&
         out.outsideGuestOwnedNativeRWPage;
}


// SHA-attested read-only composite across all three authentic main
// R_X86_64_RELATIVE entries. Two are in main PT_GNU_RELRO, one outside.
// The source ELF authorizes each target before looking up its owned
// guest bytes; a matching value does not attribute any x86 store RIP.
struct ThreeRelativeSnapshot {
  std::array<OriginalRelativeSlot,3> slots{};
  size_t total=0;
  size_t relro=0;
  size_t outside=0;
  size_t exactExpected=0;
  size_t notExpected=0;
  bool sourceAuthenticated=false;
  bool originalLdsoStoreRIPProven=false;
};
inline bool ReadOnlyOriginalMainThreeRelative(
    const uint8_t* source,size_t bytes,bool sourceSHA,
    const kernix::g2e::c3d7b::NativeChosenPIEGuestLayout& owned,
    const kernix::g2e::c3d7g::PermissionPlan& policy,
    uint64_t mainRELROPage,ThreeRelativeSnapshot& out) noexcept {
  out={};
  Witness inside{};
  OutsideRELRORelativeWitness outside{};
  if(!AuditOriginalMainRELROTargets(
         source,bytes,sourceSHA,owned,policy,mainRELROPage,
         true,inside) ||
     !AuditOriginalMainRelativeOutsideRELRO(
         source,bytes,sourceSHA,owned,policy,mainRELROPage,
         outside) ||
     !inside.sourceMainELF64DynamicVerified ||
     !inside.originalMainOwnedGuestRWPageVerified ||
     !inside.readOnlyTargetInspection ||
     inside.originalGNUDynamicRelocationClosureProven ||
     inside.sourceMainRelaEntries!=outside.mainRelaEntries ||
     inside.relativeTargetsInRELRO!=2 ||
     outside.insideRELROEntries!=2 ||
     outside.outsideRELROEntries!=1 ||
     outside.relativeEntries!=3 ||
     !outside.outsideSourceOriginalRWPTLoad ||
     !outside.outsideGuestOwnedNativeRWPage ||
     outside.originalLdsoRelocationClosureProven)
    return false;
  out.slots[0]=inside.relativeRELROSlots[0];
  out.slots[1]=inside.relativeRELROSlots[1];
  out.slots[2]={
    outside.outsideTarget,outside.outsideExpected,outside.outsideLive,false
  };
  for(size_t k=0;k<out.slots.size();++k) {
    const auto& x=out.slots[k];
    if(!x.guestTarget || !x.expectedValue)return false;
    for(size_t prev=0;prev<k;++prev)
      if(x.guestTarget==out.slots[prev].guestTarget)return false;
    out.total++;
    if(x.targetInRELRO)++out.relro;else ++out.outside;
    if(x.guestValue==x.expectedValue)
      ++out.exactExpected;
    else ++out.notExpected;
  }
  if(out.total!=3 || out.relro!=2 || out.outside!=1 ||
     out.exactExpected+out.notExpected!=3)return false;
  out.sourceAuthenticated=true;
  return true;
}

} // namespace kernix::g0::mainrelrotargets
