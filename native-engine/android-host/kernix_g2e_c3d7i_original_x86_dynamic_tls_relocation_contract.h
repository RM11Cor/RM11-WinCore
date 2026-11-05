#pragma once
// SPDX-License-Identifier: MIT
// KERNIX G2-E/C3-D7I — inspect exact SHA-attested Linux x86_64 ELF
// DYNAMIC relocation metadata and initial static TLS contract ONLY.
// This is NOT a loader, syscall bridge, relocation writer, FS/GS setup,
// RELRO seal, FEX guest execution, Android runtime, Wine or game support.
// An authentic ELF source signature is verified by GuestPreflight,
// never by a synthetic fixture. All table accesses are size checked.
#include "kernix_g2e_c3d7h_original_elf_relro_after_relocation_policy.h"
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <elf.h>
#include <limits>
#include <unistd.h>

#ifndef DT_RELR
#define DT_RELR 36
#endif
#ifndef DT_RELRSZ
#define DT_RELRSZ 35
#endif
#ifndef DT_RELRENT
#define DT_RELRENT 37
#endif
#ifndef DT_RELACOUNT
#define DT_RELACOUNT 0x6ffffff9
#endif

namespace kernix::g2e::c3d7i {
enum class Reject : uint8_t {
  None, OriginalSourceNotVerified, NoNativeOriginalWindow,
  MalformedELF, MissingDynamic, DynamicNotTerminated,
  DuplicateMetadata, MissingDynamicStringTable, BadDynamicTable,
  UnsupportedRELType, TextRelocationsForbidden, BadRelocationBounds,
  MalformedTLS, OutsidePermittedGuestImage
};
struct ModuleDynamic {
  uint64_t originalImageVA=0;
  size_t dynamicEntries=0;
  size_t neededLibraries=0;
  size_t relaEntries=0;
  size_t pltRelaEntries=0;
  size_t relrWords=0;
  size_t relrTargets=0;
  size_t validatedNeededStrings=0;
  size_t relativeRelaEntries=0;
  size_t irelativeRelaEntries=0;
  size_t symbolicRelaEntries=0;
  size_t relocationTargetsNotInitialRW=0;
  size_t relocationTargetsOutsideImage=0;
  size_t tlsHeaders=0;
  uint64_t tlsOriginalGuestVA=0;
  uint64_t tlsInitFileSize=0;
  uint64_t tlsTotalMemorySize=0;
  uint64_t tlsAlignment=0;
  bool hasDynamic=false;
  bool tagsStrictlyBounded=false;
  bool relocationTablesWithinOriginalFileBytes=false;
  bool tlsHasSourceBacking=false;
  bool fsgsInitialized=false;
  bool guestRelocationsApplied=false;
};
struct Plan {
  std::array<ModuleDynamic,3> modules{};
  size_t originalDynamicEntries=0;
  size_t totalNeededLibraries=0;
  size_t totalRelaEntries=0;
  size_t totalPltRelaEntries=0;
  size_t totalRelrWords=0;
  size_t totalRelrTargets=0;
  size_t totalValidatedNeededStrings=0;
  size_t totalTLSHeaders=0;
  size_t relocationTargetsOutsideInitialRW=0;
  bool originalThreeSHA256SourcesVerified=false;
  bool allOriginalDynamicTablesBounded=false;
  bool allOriginalTLSRangesBounded=false;
  bool x86GuestFSGSInitialized=false;
  bool originalELFRelocationsApplied=false;
  bool originalLinuxLdsoExecuted=false;
  bool relroSealed=false;
  bool androidDeviceTested=false;
};
struct Metadata {
  uint64_t rela=0,relaSize=0,relaEnt=0;
  uint64_t jmprel=0,pltSize=0,pltRel=0;
  uint64_t relr=0,relrSize=0,relrEnt=0;
  uint64_t strtab=0,strsize=0,symtab=0,syment=0;
  uint64_t relaCount=0;
  bool seenRela=false,seenRelaSize=false,seenRelaEnt=false;
  bool seenJmprel=false,seenPltSize=false,seenPltRel=false;
  bool seenRelr=false,seenRelrSize=false,seenRelrEnt=false;
  bool seenStrtab=false,seenStrsize=false,seenSymtab=false,seenSyment=false;
  bool seenRelaCount=false;
  std::array<uint64_t,128> neededOffsets{};
  size_t neededCount=0;
};
inline bool AddDynamicValue(uint64_t& dest,bool& seen,
                            uint64_t value) noexcept {
  if(seen)return false; // never accept spoofed duplicate control tags
  seen=true;dest=value;return true;
}
inline bool SourceFileVA(const unsigned char* src,size_t n,
                         const Elf64_Ehdr& elf,
                         uint64_t virt,uint64_t bytes,
                         size_t& offset) noexcept {
  if(!src || !bytes || virt>UINT64_MAX-bytes)return false;
  for(uint16_t i=0;i<elf.e_phnum;++i) {
    Elf64_Phdr ph{};
    std::memcpy(&ph,src+elf.e_phoff+
                size_t(i)*sizeof(ph),sizeof(ph));
    if(ph.p_type!=PT_LOAD || virt<ph.p_vaddr)continue;
    const uint64_t delta=virt-ph.p_vaddr;
    if(delta>ph.p_filesz || bytes>ph.p_filesz-delta ||
       ph.p_offset>UINT64_MAX-delta)continue;
    const uint64_t at=ph.p_offset+delta;
    if(at>n || bytes>n-at)continue;
    offset=static_cast<size_t>(at);
    return true;
  }
  return false;
}
// Authentic ELF x86_64 RELR is compact: an even word supplies a real
// 8-byte-aligned relocation target address; subsequent odd words
// encode up to 63 further 8-byte targets relative to the previous
// target + 8. Check every decoded target *before* any relocation is
// allowed to write to guest data. This scanner performs no writes.
inline bool CountRelr(const unsigned char* src,size_t n,
                      const Elf64_Ehdr& elf,
                      const c3d7b::ImageMeta& img,
                      const c3d7g::ModulePolicy& perms,
                      uint64_t sourceVA,uint64_t bytes,
                      ModuleDynamic& out,Reject& why) noexcept {
  if(!bytes)return true;
  size_t fileOffset=0;
  if(bytes%sizeof(uint64_t) ||
     !SourceFileVA(src,n,elf,sourceVA,bytes,fileOffset)) {
    why=Reject::BadDynamicTable;return false;
  }
  uint64_t next=0;
  bool hasBase=false;
  const auto inspectTarget=[&](uint64_t va) noexcept -> bool {
    if((va&7)!=0) {why=Reject::BadRelocationBounds;return false;}
    if(va<img.lowestAlignedELFVA ||
       img.loadBias>UINT64_MAX-va ||
       img.loadBias+va<img.chosenImageStart) {
      ++out.relocationTargetsOutsideImage;
      return true;
    }
    const uint64_t offset=img.loadBias+va-img.chosenImageStart;
    if(offset>c3d7b::kImageCapacity-8) {
      ++out.relocationTargetsOutsideImage;
      return true;
    }
    const size_t pg=static_cast<size_t>(offset/4096);
    if((perms.rights[pg]&(c3d7g::kRead|c3d7g::kWrite))!=
       (c3d7g::kRead|c3d7g::kWrite))
      ++out.relocationTargetsNotInitialRW;
    ++out.relrTargets;
    return true;
  };
  for(uint64_t i=0;i<bytes/8;++i) {
    uint64_t word=0;
    std::memcpy(&word,src+fileOffset+i*8,8);
    if((word&1)==0) {
      if(!inspectTarget(word) || word>UINT64_MAX-8) {
        why=Reject::BadRelocationBounds;return false;
      }
      next=word+8;hasBase=true;
    } else {
      if(!hasBase || next>UINT64_MAX-63*8) {
        why=Reject::BadRelocationBounds;return false;
      }
      for(unsigned bit=1;bit<64;++bit) {
        if((word&(uint64_t(1)<<bit))==0)continue;
        const uint64_t target=next+uint64_t(bit-1)*8;
        if(!inspectTarget(target))return false;
      }
      next+=63*8;
    }
  }
  return true;
}
inline bool CountRela(const unsigned char* src,size_t n,
                      const Elf64_Ehdr& elf,
                      const c3d7b::ImageMeta& image,
                      const c3d7g::ModulePolicy& permissions,
                      uint64_t tableVA,uint64_t size,
                      ModuleDynamic& result,Reject& why) noexcept {
  if(!size)return true;
  size_t off=0;
  if(size%sizeof(Elf64_Rela)!=0 ||
     !SourceFileVA(src,n,elf,tableVA,size,off)) {
    why=Reject::BadDynamicTable;return false;
  }
  const uint64_t count=size/sizeof(Elf64_Rela);
  if(count>1000000) {why=Reject::BadDynamicTable;return false;}
  for(uint64_t i=0;i<count;++i) {
    Elf64_Rela rela{};
    std::memcpy(&rela,src+off+i*sizeof(rela),sizeof(rela));
    const uint32_t type=ELF64_R_TYPE(rela.r_info);
    if(type==R_X86_64_RELATIVE)++result.relativeRelaEntries;
    else if(type==R_X86_64_IRELATIVE)++result.irelativeRelaEntries;
    else ++result.symbolicRelaEntries;
    if(rela.r_offset<image.lowestAlignedELFVA ||
       image.loadBias>UINT64_MAX-rela.r_offset ||
       image.loadBias+rela.r_offset<image.chosenImageStart) {
      ++result.relocationTargetsOutsideImage;
      continue;
    }
    const uint64_t guest=image.loadBias+rela.r_offset;
    const uint64_t rel=guest-image.chosenImageStart;
    if(rel>c3d7b::kImageCapacity-sizeof(uint64_t)) {
      ++result.relocationTargetsOutsideImage;
      continue;
    }
    const size_t pg=static_cast<size_t>(rel/4096);
    if((permissions.rights[pg]&(c3d7g::kWrite|c3d7g::kRead))!=
       (c3d7g::kWrite|c3d7g::kRead))
      ++result.relocationTargetsNotInitialRW;
  }
  return true;
}
inline bool InspectModule(
  const unsigned char* src,size_t n,
  const c3d7b::ImageMeta& img,
  const c3d7g::ModulePolicy& rights,
  ModuleDynamic& out,Reject& why) noexcept {
  out={};
  why=Reject::MalformedELF;
  if(!src || n<sizeof(Elf64_Ehdr))return false;
  Elf64_Ehdr elf{};
  std::memcpy(&elf,src,sizeof(elf));
  if(!g2b::GuestElfHeader(elf) || elf.e_type!=ET_DYN ||
     elf.e_machine!=EM_X86_64 ||
     elf.e_phentsize!=sizeof(Elf64_Phdr) ||
     !elf.e_phnum || elf.e_phnum>128 ||
     !g2b::ElfRange(elf.e_phoff,
       uint64_t(elf.e_phnum)*sizeof(Elf64_Phdr),n) ||
     rights.nativeOwnedStart!=img.chosenImageStart)
    return false;
  out.originalImageVA=img.chosenImageStart;
  Metadata m;
  bool foundDynamic=false,foundTLS=false;
  for(uint16_t i=0;i<elf.e_phnum;++i) {
    Elf64_Phdr ph{};
    std::memcpy(&ph,src+elf.e_phoff+
                 size_t(i)*sizeof(ph),sizeof(ph));
    if(ph.p_type==PT_TLS) {
      why=Reject::MalformedTLS;
      if(foundTLS || !ph.p_memsz || ph.p_filesz>ph.p_memsz ||
         ph.p_offset>n || ph.p_filesz>n-ph.p_offset ||
         ph.p_vaddr<img.lowestAlignedELFVA ||
         ph.p_vaddr>UINT64_MAX-ph.p_memsz ||
         ph.p_vaddr+ph.p_memsz>img.highestAlignedELFVA ||
         ph.p_align==0 ||
         (ph.p_align&(ph.p_align-1))!=0 ||
         img.loadBias>UINT64_MAX-ph.p_vaddr)return false;
      foundTLS=true;
      out.tlsHeaders=1;
      out.tlsOriginalGuestVA=img.loadBias+ph.p_vaddr;
      out.tlsInitFileSize=ph.p_filesz;
      out.tlsTotalMemorySize=ph.p_memsz;
      out.tlsAlignment=ph.p_align;
      out.tlsHasSourceBacking=true;
    }
    if(ph.p_type!=PT_DYNAMIC)continue;
    why=Reject::BadDynamicTable;
    if(foundDynamic || ph.p_filesz<sizeof(Elf64_Dyn) ||
       ph.p_filesz%sizeof(Elf64_Dyn) ||
       ph.p_offset>n || ph.p_filesz>n-ph.p_offset ||
       ph.p_filesz>65536)return false;
    foundDynamic=true;out.hasDynamic=true;
    bool terminated=false;
    for(uint64_t off=0;off<ph.p_filesz;off+=sizeof(Elf64_Dyn)) {
      Elf64_Dyn d{};
      std::memcpy(&d,src+ph.p_offset+off,sizeof(d));
      ++out.dynamicEntries;
      if(d.d_tag==DT_NULL){terminated=true;break;}
      const uint64_t v=d.d_un.d_val;
      bool added=true;
      switch(d.d_tag) {
        case DT_NEEDED:
          if(m.neededCount>=m.neededOffsets.size()) {
            why=Reject::BadDynamicTable;return false;
          }
          m.neededOffsets[m.neededCount++]=v;
          ++out.neededLibraries;
          break;
        case DT_RELA:added=AddDynamicValue(m.rela,m.seenRela,v);break;
        case DT_RELASZ:added=AddDynamicValue(m.relaSize,m.seenRelaSize,v);break;
        case DT_RELAENT:added=AddDynamicValue(m.relaEnt,m.seenRelaEnt,v);break;
        case DT_JMPREL:added=AddDynamicValue(m.jmprel,m.seenJmprel,v);break;
        case DT_PLTRELSZ:added=AddDynamicValue(m.pltSize,m.seenPltSize,v);break;
        case DT_PLTREL:added=AddDynamicValue(m.pltRel,m.seenPltRel,v);break;
        case DT_RELR:added=AddDynamicValue(m.relr,m.seenRelr,v);break;
        case DT_RELRSZ:added=AddDynamicValue(m.relrSize,m.seenRelrSize,v);break;
        case DT_RELRENT:added=AddDynamicValue(m.relrEnt,m.seenRelrEnt,v);break;
        case DT_STRTAB:added=AddDynamicValue(m.strtab,m.seenStrtab,v);break;
        case DT_STRSZ:added=AddDynamicValue(m.strsize,m.seenStrsize,v);break;
        case DT_SYMTAB:added=AddDynamicValue(m.symtab,m.seenSymtab,v);break;
        case DT_SYMENT:added=AddDynamicValue(m.syment,m.seenSyment,v);break;
        case DT_RELACOUNT:added=AddDynamicValue(m.relaCount,m.seenRelaCount,v);break;
        case DT_TEXTREL:why=Reject::TextRelocationsForbidden;return false;
        case DT_FLAGS:
          if(v&DF_TEXTREL){why=Reject::TextRelocationsForbidden;return false;}
          break;
        case DT_REL:
        case DT_RELSZ:
        case DT_RELENT:
          why=Reject::UnsupportedRELType;return false;
        default:break;
      }
      if(!added){why=Reject::DuplicateMetadata;return false;}
    }
    if(!terminated){why=Reject::DynamicNotTerminated;return false;}
  }
  if(!foundDynamic){why=Reject::MissingDynamic;return false;}
  why=Reject::BadDynamicTable;
  if((m.seenRelaSize && m.relaSize && !m.seenRela) ||
     (m.seenRela && m.relaSize && m.relaEnt!=sizeof(Elf64_Rela)) ||
     (m.seenRelaCount && m.relaCount>m.relaSize/sizeof(Elf64_Rela)) ||
     (m.pltSize && (!m.seenJmprel || m.pltRel!=DT_RELA ||
                    m.pltSize%sizeof(Elf64_Rela))) ||
     (m.relrSize && (!m.seenRelr ||
                     m.relrEnt!=sizeof(Elf64_Addr) ||
                     m.relrSize%sizeof(Elf64_Addr))) ||
     (m.seenRelr && !m.seenRelrEnt) ||
     (m.seenRelr && !m.seenRelrSize))
    return false;
  // Every needed-library offset must resolve inside the real DT_STRTAB
  // source bytes; strings may not run past STRSZ. A missing string
  // table is invalid even for a single DT_NEEDED.
  size_t stringsOff=0;
  if(!m.seenStrtab || !m.seenStrsize || m.strsize==0 ||
     !SourceFileVA(src,n,elf,m.strtab,m.strsize,stringsOff)) {
    why=Reject::MissingDynamicStringTable;return false;
  }
  for(size_t i=0;i<m.neededCount;++i) {
    const uint64_t off=m.neededOffsets[i];
    if(off>=m.strsize) {
      why=Reject::MissingDynamicStringTable;return false;
    }
    const size_t available=static_cast<size_t>(m.strsize-off);
    if(!std::memchr(src+stringsOff+off,0,available)) {
      why=Reject::MissingDynamicStringTable;return false;
    }
    ++out.validatedNeededStrings;
  }
  if(m.seenSymtab &&
      (m.syment!=sizeof(Elf64_Sym)))return false;
  if(m.seenSymtab) {
    size_t symbolsOff=0;
    if(!SourceFileVA(src,n,elf,m.symtab,sizeof(Elf64_Sym),symbolsOff))
      return false;
  }
  if(m.relaSize) {
    if(!CountRela(src,n,elf,img,rights,m.rela,m.relaSize,out,why))
      return false;
    out.relaEntries=static_cast<size_t>(m.relaSize/sizeof(Elf64_Rela));
  }
  if(m.pltSize) {
    if(!CountRela(src,n,elf,img,rights,m.jmprel,m.pltSize,out,why))
      return false;
    out.pltRelaEntries=static_cast<size_t>(
      m.pltSize/sizeof(Elf64_Rela));
  }
  if(m.relrSize) {
    if(!CountRelr(src,n,elf,img,rights,m.relr,m.relrSize,out,why))
      return false;
    out.relrWords=static_cast<size_t>(m.relrSize/sizeof(Elf64_Addr));
  }
  out.tagsStrictlyBounded=true;
  out.relocationTablesWithinOriginalFileBytes=true;
  why=Reject::None;
  return true;
}
inline bool InspectOriginalThreeModules(
  const GuestPreflight& source,
  const c3d7b::NativeChosenPIEGuestLayout& owned,
  const c3d7g::PermissionPlan& initial,
  const c3d7h::Plan& relro,
  Plan& out,Reject& why) noexcept {
  out={};
  why=Reject::OriginalSourceNotVerified;
  if(!source.exactSha256Matched ||
     !source.readOnlyAnonymousSnapshots ||
     !source.exactInterpreterAndGlibcClosure ||
     source.guestCodeExecuted || source.dynamicLinkerExecuted ||
     source.fexAttached || source.wineExecuted ||
     !initial.sourceShaVerified ||
     !initial.nativeGuestVAIdentityOwned ||
     !initial.allPTLoadPagesPlanned ||
     !relro.exactOriginalSHA256Sources ||
     !relro.glibcBothEndpointsRoundedDown ||
     !relro.noGuestELFRelocationsApplied ||
     !relro.noNativeMprotectApplied ||
     owned.WindowsHeld()!=4 ||
     ::sysconf(_SC_PAGESIZE)!=4096)
    return false;
  for(size_t i=0;i<3;++i) {
    const auto* image=owned.Module(i);
    why=Reject::NoNativeOriginalWindow;
    if(!image || !source.snapshots[i].bytes() ||
       !source.snapshots[i].readOnlySnapshot() ||
       source.snapshots[i].size()!=kGuest[i].bytes)
      return false;
    if(!InspectModule(source.snapshots[i].bytes(),
         source.snapshots[i].size(),*image,initial.modules[i],
         out.modules[i],why))
      return false;
    out.originalDynamicEntries+=out.modules[i].dynamicEntries;
    out.totalNeededLibraries+=out.modules[i].neededLibraries;
    out.totalRelaEntries+=out.modules[i].relaEntries;
    out.totalPltRelaEntries+=out.modules[i].pltRelaEntries;
    out.totalRelrWords+=out.modules[i].relrWords;
    out.totalRelrTargets+=out.modules[i].relrTargets;
    out.totalValidatedNeededStrings+=out.modules[i].validatedNeededStrings;
    out.totalTLSHeaders+=out.modules[i].tlsHeaders;
    out.relocationTargetsOutsideInitialRW+=
      out.modules[i].relocationTargetsNotInitialRW+
      out.modules[i].relocationTargetsOutsideImage;
  }
  out.originalThreeSHA256SourcesVerified=true;
  out.allOriginalDynamicTablesBounded=true;
  out.allOriginalTLSRangesBounded=true;
  why=Reject::None;
  return true;
}
} // namespace kernix::g2e::c3d7i
