#pragma once
// SPDX-License-Identifier: MIT
// Source-locked GNU x86_64 ELF GLOB_DAT proof for one libc->ld-linux
// link that the genuine loader has NOT yet performed. Diagnostic ONLY:
// this is NOT a general dynamic linker, not production relocation and
// not evidence of glibc/IFUNC/TLS startup. Never patch RX or host GOT.
#include "kernix_g2e_c3d7i_original_x86_dynamic_tls_relocation_contract.h"
#include "kernix_g2e_c1_x86_linux_syscall_boundary.h"
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <elf.h>
#include <limits>

namespace kernix::g0::originalglobdat {
inline constexpr size_t kOriginalLibcSize=2118168;
inline constexpr size_t kOriginalLdsoSize=235408;
inline constexpr uint64_t kLibcGOTVaddr=0x202eb0ULL;
inline constexpr uint64_t kLibcGOTSourceOffset=0x201eb0ULL;
inline constexpr uint64_t kLdsoSymbolVaddr=0x37aa0ULL;
inline constexpr uint64_t kLdsoSymbolSize=952ULL;
inline constexpr uint32_t kLibcUndefinedSymbolIndex=7;
inline constexpr uint32_t kLdsoDefinedSymbolIndex=5;

struct Witness {
  uint64_t guestGOT=0;
  uint64_t sourceBoundLdsoSymbolVA=0;
  uint64_t originalGOTValue=0;
  uint64_t updatedGOTValue=0;
  bool exactSourceELF64GLOB_DATEntryVerified=false;
  bool libcUndefinedGLIBC_PRIVATENameVerified=false;
  bool ldsoSourceGlobalRoDefinedInsideRWPTLoad=false;
  bool guestGOTOwnedRWAndInitiallyZero=false;
  bool targetOriginalGuestLdsoOwnerChecked=false;
  bool onlyExactEightGuestWritableBytesChanged=false;
  bool noHostSyscallNorNativeMapFixed=true;
  bool completeOriginalDynamicRelocations=false;
};

inline bool Header(const uint8_t* source,size_t n,Elf64_Ehdr& eh) noexcept {
  if(!source || n<sizeof(eh))return false;
  std::memcpy(&eh,source,sizeof(eh));
  return std::memcmp(eh.e_ident,ELFMAG,SELFMAG)==0 &&
         eh.e_ident[EI_CLASS]==ELFCLASS64 &&
         eh.e_ident[EI_DATA]==ELFDATA2LSB &&
         eh.e_machine==EM_X86_64 && eh.e_type==ET_DYN &&
         eh.e_phentsize==sizeof(Elf64_Phdr) &&
         eh.e_phnum>0 && eh.e_phnum<=64 &&
         eh.e_phoff<=n &&
         uint64_t(eh.e_phnum)*sizeof(Elf64_Phdr)<=n-eh.e_phoff;
}
inline bool FileVA(const uint8_t* src,size_t n,const Elf64_Ehdr& eh,
                   uint64_t va,uint64_t len,size_t& off) noexcept {
  return kernix::g2e::c3d7i::SourceFileVA(src,n,eh,va,len,off);
}
inline bool OriginalRWPTLOAD(const uint8_t* src,size_t n,
                             const Elf64_Ehdr& eh,uint64_t va,
                             uint64_t len) noexcept {
  if(!len || va>UINT64_MAX-len)return false;
  for(uint16_t i=0;i<eh.e_phnum;++i) {
    Elf64_Phdr ph{};
    std::memcpy(&ph,src+eh.e_phoff+size_t(i)*sizeof(ph),sizeof(ph));
    if(ph.p_type!=PT_LOAD || (ph.p_flags&(PF_R|PF_W|PF_X))!=(PF_R|PF_W) ||
       va<ph.p_vaddr || va-ph.p_vaddr>ph.p_memsz ||
       len>ph.p_memsz-(va-ph.p_vaddr))continue;
    size_t fileOff=0;
    if(FileVA(src,n,eh,va,len,fileOff))return true;
  }
  return false;
}
struct Dynamic {
  uint64_t rela=0,relasz=0,relaent=0;
  uint64_t symtab=0,syment=0,strtab=0,strsz=0;
};
inline bool OriginalDynamic(const uint8_t* src,size_t n,
                            const Elf64_Ehdr& eh,Dynamic& out) noexcept {
  bool seen=false;
  for(uint16_t i=0;i<eh.e_phnum;++i) {
    Elf64_Phdr ph{};
    std::memcpy(&ph,src+eh.e_phoff+size_t(i)*sizeof(ph),sizeof(ph));
    if(ph.p_type!=PT_DYNAMIC)continue;
    if(seen || !ph.p_filesz ||
       ph.p_filesz>65536 || ph.p_filesz%sizeof(Elf64_Dyn) ||
       ph.p_offset>n || ph.p_filesz>n-ph.p_offset)return false;
    seen=true;
    bool terminated=false;
    for(uint64_t j=0;j<ph.p_filesz;j+=sizeof(Elf64_Dyn)) {
      Elf64_Dyn d{};
      std::memcpy(&d,src+ph.p_offset+j,sizeof(d));
      if(d.d_tag==DT_NULL){terminated=true;break;}
      if(d.d_tag==DT_RELA)out.rela=d.d_un.d_ptr;
      if(d.d_tag==DT_RELASZ)out.relasz=d.d_un.d_val;
      if(d.d_tag==DT_RELAENT)out.relaent=d.d_un.d_val;
      if(d.d_tag==DT_SYMTAB)out.symtab=d.d_un.d_ptr;
      if(d.d_tag==DT_SYMENT)out.syment=d.d_un.d_val;
      if(d.d_tag==DT_STRTAB)out.strtab=d.d_un.d_ptr;
      if(d.d_tag==DT_STRSZ)out.strsz=d.d_un.d_val;
    }
    if(!terminated)return false;
  }
  return seen && out.symtab && out.syment==sizeof(Elf64_Sym) &&
         out.strtab && out.strsz>16 && out.strsz<=1024*1024;
}
inline bool SourceDynamicNamedSymbol(
    const uint8_t* src,size_t n,const Elf64_Ehdr& eh,
    const Dynamic& dyn,uint32_t index,
    bool shouldBeDefined,Elf64_Sym& symbol) noexcept {
  if(dyn.symtab>UINT64_MAX-uint64_t(index)*sizeof(Elf64_Sym))
    return false;
  size_t symOff=0,strOff=0;
  if(!FileVA(src,n,eh,dyn.symtab+uint64_t(index)*sizeof(Elf64_Sym),
             sizeof(Elf64_Sym),symOff) ||
     !FileVA(src,n,eh,dyn.strtab,dyn.strsz,strOff))return false;
  std::memcpy(&symbol,src+symOff,sizeof(symbol));
  constexpr char kName[]="_rtld_global_ro";
  if(symbol.st_name>dyn.strsz ||
     sizeof(kName)>dyn.strsz-symbol.st_name ||
     std::memcmp(src+strOff+symbol.st_name,kName,sizeof(kName))!=0 ||
     ELF64_ST_BIND(symbol.st_info)!=STB_GLOBAL ||
     (shouldBeDefined?(symbol.st_shndx==SHN_UNDEF):
                      (symbol.st_shndx!=SHN_UNDEF)))return false;
  return true;
}
// All pointers passed here come ONLY from the original triad SHA-256
// snapshots and their independently native owned 4K W^X witnesses.
inline Witness ApplyOriginalLibcRtldGlobalRoOneGLOB_DAT(
    const uint8_t* originalLibc,size_t libcBytes,
    const uint8_t* originalLdso,size_t ldsoBytes,
    uint64_t guestLibcBase,uint64_t guestLdsoLoadBias,
    bool guestLibcGOTNativeRWAttested,
    bool guestLdsoSourceSymbolNativeRWAttested) noexcept {
  Witness out{};
  if(!originalLibc || libcBytes!=kOriginalLibcSize ||
     !originalLdso || ldsoBytes!=kOriginalLdsoSize ||
     !guestLibcGOTNativeRWAttested ||
     !guestLdsoSourceSymbolNativeRWAttested ||
     guestLibcBase>UINT64_MAX-kLibcGOTVaddr ||
     guestLdsoLoadBias>UINT64_MAX-kLdsoSymbolVaddr ||
     !kernix::g2e::c1::GuestRange(guestLibcBase+kLibcGOTVaddr,8) ||
     !kernix::g2e::c1::GuestRange(guestLdsoLoadBias+kLdsoSymbolVaddr,8))
    return out;
  Elf64_Ehdr libc{},ldso{};
  if(!Header(originalLibc,libcBytes,libc) ||
     !Header(originalLdso,ldsoBytes,ldso) ||
     !OriginalRWPTLOAD(originalLibc,libcBytes,libc,kLibcGOTVaddr,8) ||
     !OriginalRWPTLOAD(originalLdso,ldsoBytes,ldso,
                       kLdsoSymbolVaddr,kLdsoSymbolSize))return out;
  Dynamic libcDyn{},ldsoDyn{};
  if(!OriginalDynamic(originalLibc,libcBytes,libc,libcDyn) ||
     !OriginalDynamic(originalLdso,ldsoBytes,ldso,ldsoDyn) ||
     !libcDyn.rela || !libcDyn.relasz ||
     libcDyn.relaent!=sizeof(Elf64_Rela) ||
     libcDyn.relasz%sizeof(Elf64_Rela) ||
     libcDyn.relasz/sizeof(Elf64_Rela)>32768)return out;
  size_t relaOff=0;
  if(!FileVA(originalLibc,libcBytes,libc,
             libcDyn.rela,libcDyn.relasz,relaOff))return out;
  size_t occurrences=0;
  for(size_t i=0;i<libcDyn.relasz/sizeof(Elf64_Rela);++i) {
    Elf64_Rela rel{};
    std::memcpy(&rel,originalLibc+relaOff+i*sizeof(rel),sizeof(rel));
    if(rel.r_offset!=kLibcGOTVaddr)continue;
    if(rel.r_info!=ELF64_R_INFO(kLibcUndefinedSymbolIndex,R_X86_64_GLOB_DAT) ||
       rel.r_addend!=0)return out;
    ++occurrences;
  }
  if(occurrences!=1)return out;
  out.exactSourceELF64GLOB_DATEntryVerified=true;
  Elf64_Sym undefinedLibc{},definedLdso{};
  if(!SourceDynamicNamedSymbol(originalLibc,libcBytes,libc,libcDyn,
        kLibcUndefinedSymbolIndex,false,undefinedLibc) ||
     undefinedLibc.st_value!=0 ||
     !SourceDynamicNamedSymbol(originalLdso,ldsoBytes,ldso,ldsoDyn,
        kLdsoDefinedSymbolIndex,true,definedLdso) ||
     definedLdso.st_value!=kLdsoSymbolVaddr ||
     definedLdso.st_size!=kLdsoSymbolSize ||
     ELF64_ST_TYPE(definedLdso.st_info)!=STT_OBJECT)return out;
  out.libcUndefinedGLIBC_PRIVATENameVerified=true;
  out.ldsoSourceGlobalRoDefinedInsideRWPTLoad=true;
  size_t sourceGOTOffset=0;
  if(!FileVA(originalLibc,libcBytes,libc,kLibcGOTVaddr,8,
             sourceGOTOffset) ||
     sourceGOTOffset!=kLibcGOTSourceOffset)return out;
  uint64_t sourceValue=UINT64_MAX;
  std::memcpy(&sourceValue,originalLibc+sourceGOTOffset,8);
  if(sourceValue!=0)return out;
  const uint64_t target=guestLibcBase+kLibcGOTVaddr;
  const uint64_t value=guestLdsoLoadBias+kLdsoSymbolVaddr;
  auto* guestGOT=reinterpret_cast<uint8_t*>(static_cast<uintptr_t>(target));
  uint64_t previous=UINT64_MAX;
  std::memcpy(&previous,guestGOT,sizeof(previous));
  if(previous!=sourceValue || target==value)return out;
  out.guestGOT=target;
  out.sourceBoundLdsoSymbolVA=value;
  out.originalGOTValue=previous;
  out.guestGOTOwnedRWAndInitiallyZero=true;
  out.targetOriginalGuestLdsoOwnerChecked=true;
  // ONE 8-byte guest RW store. No executable page, host FD, host GOT,
  // android/ARM64 relocation, or any other virtual source mapping.
  std::memcpy(guestGOT,&value,sizeof(value));
  std::memcpy(&out.updatedGOTValue,guestGOT,sizeof(value));
  out.onlyExactEightGuestWritableBytesChanged=out.updatedGOTValue==value;
  return out;
}
} // namespace kernix::g0::originalglobdat
