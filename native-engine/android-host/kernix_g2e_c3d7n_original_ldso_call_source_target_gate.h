#pragma once
// SPDX-License-Identifier: MIT
// C3-D7N: validate x86_64 ORIGINAL ld-linux entry's SECOND instruction
// (rel32 CALL), its actual immutable source-backed PT_LOAD RX target and
// original startup stack. Source-only; DOES NOT execute, patch, write or
// syscall. This is not dynamic linker startup or a generalized decoder.
#include "kernix_g2e_c3d7g_original_elf_pt_load_page_policy.h"
#include <array>
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <elf.h>
#include <limits>
namespace kernix::g2e::c3d7n {
enum class Reject : uint8_t {
  None, SourceNotAttested, OriginalEntryInvalid, OpcodeNotWhitelisted,
  RelativeCallArithmeticInvalid, TargetNotSourceBackedRX,
  TargetOverlapsEntry, StackNotOwned
};
struct CallProof {
  uint64_t originalEntry=0;
  uint64_t originalTarget=0;
  uint64_t originalReturnRIP=0;
  uint64_t originalGuestStartupRSP=0;
  size_t originalSourceEntryFileOffset=0;
  size_t originalSourceTargetFileOffset=0;
  int32_t relativeDisplacement=0;
  std::array<uint8_t,16> originalEntryBytes{};
  std::array<uint8_t,16> originalTargetBytes{};
  bool pinnedSourceElfSHA256Verified=false;
  bool originalEntryAndTargetFileBackedRX=false;
  bool originalCALLRel32Whitelisted=false;
  bool guestReturnSlotInitiallyWritable=false;
  bool noSourceFileModified=true;
  bool noExecutionOrPatch=true;
};
// ELF target must live in a *file-backed executable PT_LOAD* original
// source segment. Its entire first 16 bytes must be file-backed and
// contained in an RX guest VMA before any test-only trap patch.
// All arithmetic is signed checked, no pointer translation guesses.
inline bool SourceRX16(const unsigned char* src,size_t size,
     const Elf64_Ehdr& elf,uint64_t fileVaddr,
     size_t& off) noexcept {
  if(!src || fileVaddr>UINT64_MAX-16)return false;
  bool found=false;
  for(uint16_t z=0;z<elf.e_phnum;++z) {
    Elf64_Phdr ph{};
    std::memcpy(&ph,src+elf.e_phoff+size_t(z)*sizeof(ph),sizeof(ph));
    if(ph.p_type!=PT_LOAD || (ph.p_flags&PF_X)==0 ||
       (ph.p_flags&PF_W)!=0 || fileVaddr<ph.p_vaddr)continue;
    const uint64_t rel=fileVaddr-ph.p_vaddr;
    if(rel>ph.p_filesz || ph.p_filesz-rel<16 ||
       ph.p_offset>size || rel>size-ph.p_offset ||
       size-ph.p_offset-rel<16)continue;
    if(found)return false;
    found=true;
    off=static_cast<size_t>(ph.p_offset+rel);
  }
  return found;
}
inline bool DecodeSourceOriginalRel32CALL(
   const uint8_t* first,size_t len,uint64_t entry,
   uint64_t& target,int32_t& rel,Reject& reject) noexcept {
  target=0;rel=0;
  reject=Reject::OpcodeNotWhitelisted;
  if(!first || len<8 || first[0]!=0x48 ||
     first[1]!=0x89 || first[2]!=0xe7 ||
     first[3]!=0xe8)return false;
  std::memcpy(&rel,first+4,sizeof(rel));
  reject=Reject::RelativeCallArithmeticInvalid;
  if(entry<65536 || entry>uint64_t(INT64_MAX-8))return false;
  const int64_t absolute=int64_t(entry+8)+int64_t(rel);
  if(absolute<65536 || uint64_t(absolute)>UINT64_MAX-16)
    return false;
  target=static_cast<uint64_t>(absolute);
  reject=Reject::None;
  return true;
}
inline bool VerifyAuthenticLdsoSecondCallTarget(
    const GuestPreflight& source,
    const c3d7b::NativeChosenPIEGuestLayout& guest,
    const c3d7g::PermissionPlan& permission,
    CallProof& out,Reject& reject) noexcept {
  out={};
  reject=Reject::SourceNotAttested;
  if(!source.exactSha256Matched ||
     !source.readOnlyAnonymousSnapshots ||
     !source.exactInterpreterAndGlibcClosure ||
     source.guestCodeExecuted || source.dynamicLinkerExecuted ||
     source.fexAttached || source.wineExecuted ||
     !permission.sourceShaVerified ||
     !permission.allPTLoadPagesPlanned ||
     !permission.nativeGuestVAIdentityOwned ||
     !permission.deniedWritableExecutablePages ||
     guest.WindowsHeld()!=4 || !guest.LaunchPlan() ||
     !guest.Module(1) ||
     ::sysconf(_SC_PAGESIZE)!=4096)return false;
  const auto& original=source.snapshots[1];
  const auto* image=guest.Module(1);
  const auto* startup=guest.LaunchPlan();
  reject=Reject::OriginalEntryInvalid;
  if(!original.readOnlySnapshot() || !original.bytes() ||
     original.size()<sizeof(Elf64_Ehdr))return false;
  Elf64_Ehdr elf{};
  std::memcpy(&elf,original.bytes(),sizeof(elf));
  if(!g2b::GuestElfHeader(elf) || elf.e_type!=ET_DYN ||
     elf.e_machine!=EM_X86_64 ||
     elf.e_phentsize!=sizeof(Elf64_Phdr) ||
     !elf.e_phnum || elf.e_phnum>128 ||
     !g2b::ElfRange(elf.e_phoff,
        uint64_t(elf.e_phnum)*sizeof(Elf64_Phdr),original.size()) ||
     elf.e_entry>UINT64_MAX-image->loadBias ||
     startup->guestInterpreterEntry!=image->loadBias+elf.e_entry)
    return false;
  const uint64_t start=startup->guestInterpreterEntry;
  size_t entryOff=0;
  reject=Reject::TargetNotSourceBackedRX;
  if(!SourceRX16(original.bytes(),original.size(),elf,
       elf.e_entry,entryOff))return false;
  const auto* stagedEntry=guest.GuestReadOnlyBytes(1,start,16);
  if(!stagedEntry || std::memcmp(stagedEntry,
       original.bytes()+entryOff,16)!=0)return false;
  uint64_t target=0;
  int32_t relative=0;
  if(!DecodeSourceOriginalRel32CALL(
       original.bytes()+entryOff,16,start,
       target,relative,reject))return false;
  reject=Reject::TargetOverlapsEntry;
  if((target>=start && target<start+16) ||
     (start>=target && start<target+16))return false;
  reject=Reject::TargetNotSourceBackedRX;
  if(target<image->loadBias ||
     target-image->loadBias<image->lowestAlignedELFVA)
    return false;
  const uint64_t targetELF=target-image->loadBias;
  size_t targetOff=0;
  if(!SourceRX16(original.bytes(),original.size(),elf,
       targetELF,targetOff))return false;
  const auto* stagedTarget=guest.GuestReadOnlyBytes(1,target,16);
  if(!stagedTarget ||
     std::memcmp(stagedTarget,original.bytes()+targetOff,16)!=0)
    return false;
  const uint64_t imageBase=image->chosenImageStart;
  if(start<imageBase || target<imageBase ||
     start-imageBase>c3d7b::kImageCapacity-16 ||
     target-imageBase>c3d7b::kImageCapacity-16)
    return false;
  for(const uint64_t addr:
      {start,start+3,start+7,target,target+15}) {
    const size_t pg=static_cast<size_t>((addr-imageBase)/4096);
    if(pg>=c3d7g::kModulePages ||
       permission.modules[1].rights[pg]!=
       (c3d7g::kRead|c3d7g::kExecute))return false;
  }
  reject=Reject::StackNotOwned;
  if(startup->stack.guestRSP<startup->stack.guestBottom+4096+8 ||
     startup->stack.guestRSP-8<startup->stack.guestBottom ||
     startup->stack.guestRSP>startup->stack.guestBottom+
         c3d7b::kStackCapacity-8)
    return false;
  out.originalEntry=start;
  out.originalTarget=target;
  out.originalReturnRIP=start+8;
  out.originalGuestStartupRSP=startup->stack.guestRSP;
  out.originalSourceEntryFileOffset=entryOff;
  out.originalSourceTargetFileOffset=targetOff;
  out.relativeDisplacement=relative;
  std::memcpy(out.originalEntryBytes.data(),
              stagedEntry,out.originalEntryBytes.size());
  std::memcpy(out.originalTargetBytes.data(),
              stagedTarget,out.originalTargetBytes.size());
  out.pinnedSourceElfSHA256Verified=true;
  out.originalEntryAndTargetFileBackedRX=true;
  out.originalCALLRel32Whitelisted=true;
  out.guestReturnSlotInitiallyWritable=true;
  reject=Reject::None;
  return true;
}
} // namespace kernix::g2e::c3d7n
