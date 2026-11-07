// SPDX-License-Identifier: MIT
#pragma once
// KERNIX G0: exact original-source witness for all forty-five nonzero
// glibc x86_64 R_X86_64_IRELATIVE *stored result addresses*.
// It checks source PF_R|PF_X nonwritable executable bytes against the
// currently protected owner-held libc guest RX VMA. The source filename,
// SHA, original RELA entries and snapshots are separately authenticated.
// This is READ ONLY: NO IFUNC invocation, result correctness proof,
// instruction-write RIP trace, full GNU dynamic-link closure or main seal.
#include "kernix_g0_original_libc_46_irelative_resolver_source_inventory.h"
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <elf.h>

namespace kernix::g0::libcifuncresult {
struct Entry {
  size_t sourceRelaIndex=0;
  uint64_t guestReturn=0;
  uint64_t sourceExecutableVA=0;
  bool guestRXMatchesSourceBytes=false;
};
struct Witness {
  std::array<Entry,45> nonzeroEntries{};
  size_t checkedNonzero=0;
  size_t sourceRX=0;
  size_t guestRX=0;
  size_t firstEightSourceGuestEqual=0;
  size_t distinctResultCodeAddresses=0;
  size_t duplicatedResultCodeAddresses=0;
  bool originalSHA256Pinned=false;
  bool guestRelocationStoreRIPsTraced=false;
  bool originalIFUNCResolverInvocationsProven=false;
  bool storedResultsSemanticallyCorrectProven=false;
  bool originalLoaderRelocationClosureProven=false;
};
template<class GuestExecutable>
inline bool Audit45OriginalLibcIFUNCReturnCodePointersReadOnly(
    const uint8_t* original,size_t bytes,bool exactSHA,
    const kernix::g0::PinnedLibcLargeReadonlyGuestMap& map,
    const kernix::g0::libcifuncinventory::Witness& resolvers,
    GuestExecutable&& authenticatedGuestRX,Witness& out) noexcept {
  out={};
  namespace d=kernix::g2e::c3d7i;
  const uint64_t base=map.Address();
  if(!original || !exactSHA || !base ||
     !resolvers.originalSourceSHA256Verified ||
     resolvers.total!=46 || resolvers.sourceRX!=46 ||
     resolvers.guestRXEqual!=46 || resolvers.unchanged!=46 ||
     resolvers.nonzeroAtLibc!=45 || resolvers.nonzeroAtMain!=45 ||
     resolvers.zeroBoth!=1 ||
     resolvers.nonzeroResultInsideLibcRX!=45 ||
     resolvers.nonzeroResultOutsideLibcRX!=0 ||
     resolvers.originalResolversExecutedByThisAudit ||
     resolvers.originalLoaderStoreRIPsTraced ||
     resolvers.originalIFUNCResultsCorrectlyBoundProven ||
     resolvers.originalDynamicRelocationClosureProven ||
     bytes!=kernix::g0::PinnedLibcLargeReadonlyGuestMap::kOriginalLibcSize ||
     map.CopiedSourceBytes()!=bytes ||
     map.BytesHeld()!=0x212000ULL ||
     !map.OriginalOwnedBSSZeroed() ||
     bytes<sizeof(Elf64_Ehdr))return false;
  Elf64_Ehdr eh{};
  std::memcpy(&eh,original,sizeof(eh));
  if(std::memcmp(eh.e_ident,ELFMAG,SELFMAG)!=0 ||
     eh.e_ident[EI_CLASS]!=ELFCLASS64 ||
     eh.e_ident[EI_DATA]!=ELFDATA2LSB ||
     eh.e_type!=ET_DYN || eh.e_machine!=EM_X86_64 ||
     eh.e_phentsize!=sizeof(Elf64_Phdr) ||
     !eh.e_phnum || eh.e_phnum>128 ||
     eh.e_phoff>bytes ||
     size_t(eh.e_phnum)>(bytes-eh.e_phoff)/sizeof(Elf64_Phdr))
     return false;
  std::array<Elf64_Phdr,128> phdrs{};
  for(uint16_t i=0;i<eh.e_phnum;++i){
    std::memcpy(&phdrs[i],original+eh.e_phoff+
        size_t(i)*sizeof(Elf64_Phdr),sizeof(Elf64_Phdr));
  }
  const auto isOriginalExecutable=[&](uint64_t va,
                                      size_t count) noexcept -> bool {
    for(uint16_t i=0;i<eh.e_phnum;++i){
      const auto& ph=phdrs[i];
      if(ph.p_type!=PT_LOAD ||
         (ph.p_flags&(PF_R|PF_X|PF_W))!=(PF_R|PF_X) ||
         va<ph.p_vaddr || va-ph.p_vaddr>ph.p_filesz ||
         count>ph.p_filesz-(va-ph.p_vaddr))continue;
      return true;
    }
    return false;
  };
  for(const auto& resolver:resolvers.entries){
    if(!resolver.sourceRelaIndex && !resolver.target)return false;
    if(!resolver.originalSourceAndGuestRXIdentical ||
       !resolver.guestResolver ||
       !resolver.target ||
       resolver.valueAtLibc!=resolver.valueAtMain)return false;
    if(resolver.valueAtMain==0){
      if(resolver.nonzeroResultInsideOriginalLibcRX)return false;
      continue;
    }
    if(!resolver.nonzeroResultInsideOriginalLibcRX ||
       out.checkedNonzero>=out.nonzeroEntries.size() ||
       resolver.valueAtMain<base)return false;
    const uint64_t address=resolver.valueAtMain;
    const uint64_t va=address-base;
    if(map.BytesHeld()<8 || va>map.BytesHeld()-8 ||
       !isOriginalExecutable(va,8) ||
       !authenticatedGuestRX(address))
      return false;
    size_t fileOffset=0;
    if(!d::SourceFileVA(original,bytes,eh,va,8,fileOffset))
      return false;
    const unsigned char* live=map.AuthenticatedReadonlyBytes(address,8);
    if(!live || std::memcmp(live,original+fileOffset,8)!=0)
      return false;
    size_t earlierEqual=0;
    for(size_t j=0;j<out.checkedNonzero;++j)
      earlierEqual+=size_t(out.nonzeroEntries[j].guestReturn==address);
    if(!earlierEqual)++out.distinctResultCodeAddresses;
    else ++out.duplicatedResultCodeAddresses;
    auto& result=out.nonzeroEntries[out.checkedNonzero];
    result.sourceRelaIndex=resolver.sourceRelaIndex;
    result.guestReturn=address;
    result.sourceExecutableVA=va;
    result.guestRXMatchesSourceBytes=true;
    ++out.checkedNonzero;
    ++out.sourceRX;
    ++out.guestRX;
    ++out.firstEightSourceGuestEqual;
  }
  if(out.checkedNonzero!=45 || out.sourceRX!=45 ||
     out.guestRX!=45 || out.firstEightSourceGuestEqual!=45 ||
     out.distinctResultCodeAddresses+
       out.duplicatedResultCodeAddresses!=45)return false;
  out.originalSHA256Pinned=true;
  return true;
}
} // namespace kernix::g0::libcifuncresult
