// SPDX-License-Identifier: MIT
#pragma once
// Source-only triad inventory: count original SHA-pinned main,
// GNU ld-linux and libc dynamic relocation records independently.
// This never applies relocations or asserts that genuine ldso
// resolved the ELF symbol graph. A source inventory does NOT grant
// main RELRO mprotect permission or prove PE/Windows execution.
#include "kernix_g2e_c3d7i_original_x86_dynamic_tls_relocation_contract.h"
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>

namespace kernix::g0::triadsourceinventory {
struct Module {
  size_t rela=0,plt=0,relrWords=0,relrTargets=0;
  size_t relative=0,irelative=0,symbolic=0;
  size_t sourceRelocationTargets=0;
  size_t needed=0;
  size_t relocationTargetsOutsideRW=0;
  size_t sourceOwnedIndex=0;
  bool attestedOriginalELFSource=false;
  bool actualGuestRelocationAlgorithmTraced=false;
};
struct Witness {
  std::array<Module,3> modules{};
  size_t originalModules=0;
  size_t totalRela=0,totalPLT=0,totalRELRWords=0;
  size_t totalRELRTgt=0,totalRelative=0,totalIRelative=0;
  size_t totalSymbolic=0,totalSourceTargets=0;
  size_t totalNeeded=0,totalOutsideInitialRW=0;
  bool originalThreeSHA256SourcesVerified=false;
  bool guestRelocationClosureProven=false;
  bool AndroidDeviceTested=false;
};
// The input is the PRE-FEX source metadata plan, used during the LIVE
// guest syscall only for read-only accounting. Its preflight flags
// cannot substitute for a live original-ldso relocation witness.
inline bool OriginalThreeELFSourceRelocationInventory(
    const kernix::g2e::c3d7i::Plan& plan,
    const kernix::g2e::g2b::GuestPreflight& source,
    const kernix::g2e::c3d7b::NativeChosenPIEGuestLayout& owned,
    Witness& out) noexcept {
  out={};
  if(!source.exactSha256Matched ||
     !source.readOnlyAnonymousSnapshots ||
     !source.exactInterpreterAndGlibcClosure ||
     !plan.originalThreeSHA256SourcesVerified ||
     !plan.allOriginalDynamicTablesBounded ||
     !plan.allOriginalTLSRangesBounded ||
     plan.originalELFRelocationsApplied ||
     plan.relroSealed || plan.androidDeviceTested ||
     !owned.LaunchPlan() || owned.WindowsHeld()!=4)
    return false;
  for(size_t i=0;i<3;++i){
    const auto* original=owned.Module(i);
    const auto& src=source.snapshots[i];
    const auto& meta=plan.modules[i];
    if(!original || !src.readOnlySnapshot() || !src.bytes() ||
       !src.size() || !meta.hasDynamic ||
       !meta.tagsStrictlyBounded ||
       !meta.relocationTablesWithinOriginalFileBytes ||
       meta.guestRelocationsApplied ||
       meta.originalImageVA!=original->chosenImageStart ||
       meta.relativeRelaEntries>
         std::numeric_limits<size_t>::max()-meta.irelativeRelaEntries ||
       meta.relativeRelaEntries+meta.irelativeRelaEntries>
         std::numeric_limits<size_t>::max()-meta.symbolicRelaEntries)
      return false;
    const size_t typed=meta.relativeRelaEntries+
         meta.irelativeRelaEntries+meta.symbolicRelaEntries;
    if(meta.relaEntries>
          std::numeric_limits<size_t>::max()-meta.pltRelaEntries ||
       meta.relaEntries+meta.pltRelaEntries!=typed ||
       typed>std::numeric_limits<size_t>::max()-meta.relrTargets)
      return false;
    auto& row=out.modules[i];
    row.rela=meta.relaEntries;
    row.plt=meta.pltRelaEntries;
    row.relrWords=meta.relrWords;
    row.relrTargets=meta.relrTargets;
    row.relative=meta.relativeRelaEntries;
    row.irelative=meta.irelativeRelaEntries;
    row.symbolic=meta.symbolicRelaEntries;
    row.sourceRelocationTargets=typed+meta.relrTargets;
    row.needed=meta.neededLibraries;
    if(meta.relocationTargetsNotInitialRW>
         std::numeric_limits<size_t>::max()-
         meta.relocationTargetsOutsideImage)return false;
    row.relocationTargetsOutsideRW=
        meta.relocationTargetsNotInitialRW+
        meta.relocationTargetsOutsideImage;
    row.sourceOwnedIndex=i;
    row.attestedOriginalELFSource=true;
    const auto accumulate=[](size_t& total,size_t add) noexcept -> bool{
      if(total>std::numeric_limits<size_t>::max()-add)
        return false;
      total+=add;
      return true;
    };
    if(!accumulate(out.totalRela,row.rela) ||
       !accumulate(out.totalPLT,row.plt) ||
       !accumulate(out.totalRELRWords,row.relrWords) ||
       !accumulate(out.totalRELRTgt,row.relrTargets) ||
       !accumulate(out.totalRelative,row.relative) ||
       !accumulate(out.totalIRelative,row.irelative) ||
       !accumulate(out.totalSymbolic,row.symbolic) ||
       !accumulate(out.totalSourceTargets,row.sourceRelocationTargets) ||
       !accumulate(out.totalNeeded,row.needed) ||
       !accumulate(out.totalOutsideInitialRW,
                   row.relocationTargetsOutsideRW))
       return false;
    ++out.originalModules;
  }
  if(out.originalModules!=3 ||
     out.totalRela!=plan.totalRelaEntries ||
     out.totalPLT!=plan.totalPltRelaEntries ||
     out.totalRELRWords!=plan.totalRelrWords ||
     out.totalRELRTgt!=plan.totalRelrTargets ||
     out.totalNeeded!=plan.totalNeededLibraries ||
     out.totalOutsideInitialRW!=plan.relocationTargetsOutsideInitialRW ||
     out.totalRelative+out.totalIRelative+out.totalSymbolic!=
       out.totalRela+out.totalPLT ||
     out.totalSourceTargets!=out.totalRela+
       out.totalPLT+out.totalRELRTgt)
    return false;
  out.originalThreeSHA256SourcesVerified=true;
  return true;
}
} // namespace kernix::g0::triadsourceinventory
