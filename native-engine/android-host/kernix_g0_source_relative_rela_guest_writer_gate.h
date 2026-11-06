#pragma once
// SPDX-License-Identifier: MIT
// KERNIX G0: host-only authorization of EXACT source x86 main ELF
// R_X86_64_RELATIVE Elf64_Rela for an explicitly authored guest x86
// relocation-fixture writer. THIS IS NOT native ld-linux relocation
// machinery. It proves source-derived guest arithmetic and guest RW
// store inside the same FEX session. Full relocation/glibc remains false.
#include "kernix_g2e_c3d7i_original_x86_dynamic_tls_relocation_contract.h"
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <elf.h>
#include <limits>

namespace kernix::g0::relawriter {
struct Witness {
  uint64_t sourceGuestRela=0;
  uint64_t sourceRelocationInfo=0;
  uint64_t guestTarget=0;
  uint64_t expectedSourceValue=0;
  uint64_t previousValue=0;
  uint64_t guestMainLoadBias=0;
  uint64_t sourceAddend=0;
  uint64_t originalTargetOffset=0;
  bool authenticatedOriginalRela=false;
  bool independentGuestPTLoadWritePermitted=false;
  bool actuallyExecutedByOriginalLdso=false;
};
enum class Reject : uint8_t {
  None, Source, ELF, Dynamic, RelaTable, NoSafeRelative,
  SourceGuestRelaMismatch, SourceGuestTargetMismatch
};
inline bool FindSourceMainRelativeRela(
    const kernix::g2e::GuestPreflight& original,
    const kernix::g2e::c3d7b::NativeChosenPIEGuestLayout& owned,
    const kernix::g2e::c3d7g::PermissionPlan& permissions,
    const kernix::g2e::c3d7i::Plan& dynamic,
    Witness& out,Reject& reject) noexcept {
  namespace d=kernix::g2e::c3d7i;
  namespace g=kernix::g2e::c3d7g;
  namespace b=kernix::g2e::c3d7b;
  out={};reject=Reject::Source;
  const auto* m=owned.Module(0);
  const auto& snap=original.snapshots[0];
  if(!original.exactSha256Matched ||
     !original.exactInterpreterAndGlibcClosure ||
     !original.readOnlyAnonymousSnapshots ||
     !dynamic.originalThreeSHA256SourcesVerified ||
     !dynamic.allOriginalDynamicTablesBounded ||
     !dynamic.allOriginalTLSRangesBounded ||
     dynamic.modules[0].relativeRelaEntries==0 ||
     !permissions.allPTLoadPagesPlanned ||
     owned.WindowsHeld()!=4 ||
     !m || !snap.bytes() || !snap.readOnlySnapshot() ||
     m->lowestAlignedELFVA!=0 ||
     m->loadBias!=m->chosenImageStart)return false;
  const unsigned char* bytes=snap.bytes();
  const size_t n=snap.size();
  reject=Reject::ELF;
  if(n<sizeof(Elf64_Ehdr))return false;
  Elf64_Ehdr eh{};
  std::memcpy(&eh,bytes,sizeof(eh));
  if(!kernix::g2e::g2b::GuestElfHeader(eh) ||
     !kernix::g2e::g2b::ElfRange(
       eh.e_phoff,uint64_t(eh.e_phnum)*sizeof(Elf64_Phdr),n))return false;
  uint64_t relaVA=0,relaSize=0,relaEnt=0;
  bool relaSeen=false,sizeSeen=false,entrySeen=false,dynSeen=false;
  reject=Reject::Dynamic;
  for(uint16_t i=0;i<eh.e_phnum;++i) {
    Elf64_Phdr ph{};
    std::memcpy(&ph,bytes+eh.e_phoff+size_t(i)*sizeof(ph),sizeof(ph));
    if(ph.p_type!=PT_DYNAMIC)continue;
    if(dynSeen || !ph.p_filesz || ph.p_filesz>65536 ||
       ph.p_filesz%sizeof(Elf64_Dyn) ||
       ph.p_offset>n || ph.p_filesz>n-ph.p_offset)return false;
    dynSeen=true;
    bool ended=false;
    for(uint64_t off=0;off<ph.p_filesz;off+=sizeof(Elf64_Dyn)) {
      Elf64_Dyn entry{};
      std::memcpy(&entry,bytes+ph.p_offset+off,sizeof(entry));
      if(entry.d_tag==DT_NULL){ended=true;break;}
      if(entry.d_tag==DT_RELA) {
        if(relaSeen)return false;
        relaVA=entry.d_un.d_ptr;relaSeen=true;
      }
      if(entry.d_tag==DT_RELASZ) {
        if(sizeSeen)return false;
        relaSize=entry.d_un.d_val;sizeSeen=true;
      }
      if(entry.d_tag==DT_RELAENT) {
        if(entrySeen)return false;
        relaEnt=entry.d_un.d_val;entrySeen=true;
      }
    }
    if(!ended)return false;
  }
  reject=Reject::RelaTable;
  if(!dynSeen || !relaSeen || !sizeSeen || !entrySeen ||
     relaEnt!=sizeof(Elf64_Rela) ||
     !relaSize || relaSize%sizeof(Elf64_Rela) ||
     relaSize/sizeof(Elf64_Rela)>16384 ||
     relaVA>UINT64_MAX-relaSize ||
     m->loadBias>UINT64_MAX-relaVA-relaSize)return false;
  size_t sourceRelaFileOff=0;
  if(!d::SourceFileVA(bytes,n,eh,relaVA,relaSize,sourceRelaFileOff))
    return false;
  reject=Reject::NoSafeRelative;
  for(size_t i=0;i<relaSize/sizeof(Elf64_Rela);++i) {
    const uint64_t delta=uint64_t(i)*sizeof(Elf64_Rela);
    Elf64_Rela rel{};
    std::memcpy(&rel,bytes+sourceRelaFileOff+delta,sizeof(rel));
    if(rel.r_info!=uint64_t(R_X86_64_RELATIVE) ||
       rel.r_addend<0 || (rel.r_offset&7) ||
       rel.r_offset>UINT64_MAX-m->loadBias ||
       uint64_t(rel.r_addend)>UINT64_MAX-m->loadBias)
      continue;
    const uint64_t target=m->loadBias+rel.r_offset;
    const uint64_t expected=m->loadBias+uint64_t(rel.r_addend);
    if(target<m->chosenImageStart ||
       target-m->chosenImageStart>b::kImageCapacity-sizeof(uint64_t))
      continue;
    const size_t page=static_cast<size_t>(
      (target-m->chosenImageStart)/b::kPagesize);
    if((permissions.modules[0].rights[page]&(g::kRead|g::kWrite))!=
       (g::kRead|g::kWrite))continue;
    const uint64_t guestRela=m->loadBias+relaVA+delta;
    const auto* relaAt=owned.GuestReadOnlyBytes(0,guestRela,sizeof(rel));
    const auto* targetAt=owned.GuestReadOnlyBytes(
        0,target,sizeof(uint64_t));
    if(!relaAt || !targetAt ||
       std::memcmp(relaAt,bytes+sourceRelaFileOff+delta,sizeof(rel))!=0)
      continue;
    uint64_t before=0;
    std::memcpy(&before,targetAt,sizeof(before));
    if(before==expected)continue;
    out.sourceGuestRela=guestRela;
    out.sourceRelocationInfo=rel.r_info;
    out.guestTarget=target;
    out.expectedSourceValue=expected;
    out.previousValue=before;
    out.guestMainLoadBias=m->loadBias;
    out.sourceAddend=static_cast<uint64_t>(rel.r_addend);
    out.originalTargetOffset=rel.r_offset;
    out.authenticatedOriginalRela=true;
    out.independentGuestPTLoadWritePermitted=true;
    out.actuallyExecutedByOriginalLdso=false;
    reject=Reject::None;
    return true;
  }
  return false;
}
} // namespace kernix::g0::relawriter
