// SPDX-License-Identifier: MIT
// C3-D7G second Linux gate: actually mprotect the source-verified
// kernel-owned 4K guest image pages from exact PT_LOAD permission plan,
// enforce PROT_NONE ELF holes and stack guard, re-check every mapped
// original source PT_LOAD byte, and prove injected failure unmaps all.
// No FEX, original ld-linux instruction execution, or Android device test.
#include "kernix_g0_original_source_ptload_fex_executable_range.h"
#include "kernix_g0_original_source_guest_program_break_owner.h"
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <elf.h>
#include <fcntl.h>
#include <fstream>
#include <string>
#include <vector>
#include <unistd.h>
namespace c7g=kernix::g2e::c3d7g;
namespace c7b=kernix::g2e::c3d7b;
namespace rx=kernix::g0::source_exec;
namespace brk=kernix::g0::guestbrk;
struct Area {
  uint64_t first=0,last=0;
  std::string rights;
};
static std::vector<Area> Areas() {
  std::vector<Area> out;
  std::ifstream stream("/proc/self/maps");
  std::string line;
  while(std::getline(stream,line)) {
    unsigned long long lo=0,hi=0;
    char flags[5]{};
    if(std::sscanf(line.c_str(),"%llx-%llx %4s",
       &lo,&hi,flags)!=3)continue;
    out.push_back({uint64_t(lo),uint64_t(hi),flags});
  }
  return out;
}
static std::string RightsAt(const std::vector<Area>& maps,
                             uint64_t guest) {
  for(const auto& m:maps) {
    if(guest>=m.first && guest<m.last)return m.rights;
  }
  return "unmapped";
}
static std::string Expected(uint8_t rights) {
  if(rights==0)return "---p";
  if(rights==c7g::kRead)return "r--p";
  if(rights==(c7g::kRead|c7g::kWrite))return "rw-p";
  if(rights==(c7g::kRead|c7g::kExecute))return "r-xp";
  return "invalid";
}
static bool SourcePTLoadFileBytesPreserved(
  const kernix::g2e::GuestPreflight& source,
  const c7b::NativeChosenPIEGuestLayout& guest,size_t module) {
  const auto* meta=guest.Module(module);
  const auto& bytes=source.snapshots[module];
  if(!meta || !bytes.bytes() || !bytes.readOnlySnapshot())return false;
  Elf64_Ehdr eh{};
  std::memcpy(&eh,bytes.bytes(),sizeof(eh));
  for(uint16_t i=0;i<eh.e_phnum;++i) {
    Elf64_Phdr ph{};
    std::memcpy(&ph,bytes.bytes()+eh.e_phoff+
         size_t(i)*sizeof(ph),sizeof(ph));
    if(ph.p_type!=PT_LOAD || !ph.p_filesz)continue;
    if(ph.p_vaddr<meta->lowestAlignedELFVA)return false;
    const uint64_t guestVA=meta->loadBias+ph.p_vaddr;
    const auto* srcAt=guest.GuestReadOnlyBytes(
       module,guestVA,static_cast<size_t>(ph.p_filesz));
    if(!srcAt ||
       std::memcmp(srcAt,bytes.bytes()+ph.p_offset,
                   static_cast<size_t>(ph.p_filesz))!=0)
      return false;
  }
  return true;
}
int main(int argc,char** argv) {
  if(argc!=2 || !argv[1])return 2;
  if(sysconf(_SC_PAGESIZE)!=4096)return 3;
  int root=open(argv[1],O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
  if(root<0)return 4;
  std::array<uint8_t,16> seed{};
  for(size_t i=0;i<seed.size();++i)
    seed[i]=uint8_t(i+1);
  kernix::g2e::GuestPreflight original;
  std::string err;
  if(!kernix::g2e::Validate(root,original,err)) {
    std::fprintf(stderr,"C3D7G_SOURCE_INVALID %s\n",err.c_str());
    close(root);return 5;
  }
  // First prove failure *during* native mprotect never leaves an owned
  // image, stack or intermediate W^X mapping alive.
  {
    c7b::NativeChosenPIEGuestLayout injected;
    c7b::Witness init;
    if(!injected.Stage(root,seed,init)) {
      close(root);return 6;
    }
    c7g::ApplyWitness fail;
    if(c7g::ApplyOwnedOriginalPTLoadPagePermissions(
         injected,original,fail,1) ||
       fail.failureErrno!=ECANCELED ||
       fail.nativeMprotectOperations!=1 ||
       fail.ownedWindowsReleasedOnFailure!=4 ||
       injected.WindowsHeld()!=0)
    {
      std::fprintf(stderr,
        "C3D7G_INJECT_FAIL_UNSAFE errno=%d protected=%zu released=%zu held=%zu\n",
        fail.failureErrno,fail.nativeMprotectOperations,
        fail.ownedWindowsReleasedOnFailure,injected.WindowsHeld());
      close(root);return 7;
    }
  }
  c7b::NativeChosenPIEGuestLayout guest;
  c7b::Witness setup;
  if(!guest.Stage(root,seed,setup) ||
     !setup.pinnedOriginalELFSHA256Verified ||
     !setup.originalBytesCopiedReadOnly ||
     setup.originalLdsoExecuted ||
     setup.originalELFCodeExecuted ||
     guest.WindowsHeld()!=4) {
    close(root);return 8;
  }
  close(root);
  c7g::PermissionPlan sourcePlan;
  c7g::Reject reject;
  if(!c7g::BuildVerifiedOriginalPermissionPlan(
       original,guest,sourcePlan,reject))
    return 9;
  c7g::ApplyWitness proof;
  if(!c7g::ApplyOwnedOriginalPTLoadPagePermissions(
       guest,original,proof)) {
    std::fprintf(stderr,
      "C3D7G_PERMISSION_APPLY_REJECTED errno=%d phase=%u ops=%zu\n",
      proof.failureErrno,unsigned(proof.planningReject),
      proof.nativeMprotectOperations);
    return 10;
  }
  if(!proof.originalPinnedSourceValidated ||
     !proof.eachPTLoadFlagTranslatedToNative ||
     !proof.nativeNoWritableExecutablePage ||
     !proof.nativeNonPTLoadHolesDenied ||
     !proof.nativeStackGuardDenied ||
     !proof.nativeLinuxStackWritableNonExecutable ||
     proof.originalLdsoExecuted || proof.fexEntered ||
     proof.androidDeviceTested ||
     proof.originalModulesProtected!=3 ||
     proof.executablePages==0 || proof.writablePages==0 ||
     proof.nonePages==0)return 11;

  // Compare the *actual kernel VMA flags for every 4KiB page*,
  // including every inaccessible hole in all three 8MiB images.
  const auto maps=Areas();
  for(size_t i=0;i<3;++i) {
    const uint64_t moduleVA=sourcePlan.modules[i].nativeOwnedStart;
    for(size_t page=0;page<c7g::kModulePages;++page) {
      const uint64_t address=moduleVA+page*4096;
      const auto actual=RightsAt(maps,address);
      const auto wanted=Expected(sourcePlan.modules[i].rights[page]);
      if(actual!=wanted) {
        std::fprintf(stderr,
          "C3D7G_NATIVE_VMA_MISMATCH module=%zu page=%zu actual=%s expected=%s\n",
          i,page,actual.c_str(),wanted.c_str());
        return 12;
      }
    }
    if(!SourcePTLoadFileBytesPreserved(original,guest,i))
      return 13;
  }
  const auto* launch=guest.LaunchPlan();
  if(!launch)return 14;
  const uint64_t stackBase=launch->stack.guestBottom;
  if(RightsAt(maps,stackBase)!="---p")return 15;
  for(size_t page=1;page<16;++page) {
    if(RightsAt(maps,stackBase+page*4096)!="rw-p")return 16;
  }
  if(RightsAt(maps,launch->stack.guestRSP)!="rw-p")
    return 17;
  uint64_t startupArgc=0;
  std::memcpy(&startupArgc,
    reinterpret_cast<const void*>(static_cast<uintptr_t>(
      launch->stack.guestRSP)),sizeof(startupArgc));
  if(startupArgc!=1)return 18;
  const auto mainRIP=launch->guestMainEntry;
  const auto ldsoRIP=launch->guestInterpreterEntry;
  if(RightsAt(maps,mainRIP)!="r-xp" ||
     RightsAt(maps,ldsoRIP)!="r-xp")return 19;
  // Real original FEX executable-range resolver: enumerate every
  // original loader / main / libc PT_LOAD page, including every
  // guard and writable gap. This expands the previous 16-128 byte
  // original loader JIT-range limitation to the actual ELF RX plan.
  size_t resolved=0,denied=0,sourceLoaderPages=0,sourceLibcPages=0;
  for(size_t i=0;i<3;++i){
    const auto* mod=guest.Module(i);
    if(!mod)return 22;
    for(size_t page=0;page<c7g::kModulePages;++page){
      const uint64_t address=mod->chosenImageStart+page*4096;
      rx::Range first{},last{};
      const bool accepted=rx::ResolveOriginalSourceExecutableRange(
          guest,sourcePlan,proof,address,first);
      const bool acceptedEnd=rx::ResolveOriginalSourceExecutableRange(
          guest,sourcePlan,proof,address+4095,last);
      const auto rights=sourcePlan.modules[i].rights[page];
      const bool expected=rights==(c7g::kRead|c7g::kExecute);
      if(accepted!=expected || acceptedEnd!=expected)return 23;
      if(expected){
        if(!first.sourceVerifiedOriginalPTLoadRX ||
           !first.nativeGuestAddressIsOwned ||
           first.originalGNUInterpreterStartupCompleted ||
           first.originalRelocationsExecuted ||
           first.pageStart!=address || first.pageBytes!=4096 ||
           first.moduleIndex!=i ||
           last.pageStart!=address || last.pageBytes!=4096 ||
           last.moduleIndex!=i ||
           RightsAt(maps,address)!="r-xp")return 24;
        ++resolved;
        if(i==1)++sourceLoaderPages;
        if(i==2)++sourceLibcPages;
      }else {
        if(first.sourceVerifiedOriginalPTLoadRX ||
           first.nativeGuestAddressIsOwned || first.pageStart ||
           last.sourceVerifiedOriginalPTLoadRX ||
           RightsAt(maps,address)=="r-xp")return 25;
        ++denied;
      }
    }
  }
  if(resolved<10 || denied<10 || sourceLoaderPages<5 ||
     sourceLibcPages<5)return 26;
  const auto* sourceLdso=guest.Module(1);
  rx::Range originalEntry{},fake{},invalid{};
  if(!rx::ResolveOriginalSourceExecutableRange(
        guest,sourcePlan,proof,launch->guestInterpreterEntry,originalEntry) ||
     originalEntry.moduleIndex!=1 ||
     !originalEntry.sourceVerifiedOriginalPTLoadRX ||
     rx::ResolveOriginalSourceExecutableRange(
        guest,sourcePlan,proof,0,invalid) ||
     rx::ResolveOriginalSourceExecutableRange(
        guest,sourcePlan,proof,UINT64_MAX,invalid) ||
     rx::ResolveOriginalSourceExecutableRange(
        guest,sourcePlan,proof,launch->stack.guestRSP,invalid) ||
     rx::ResolveOriginalSourceExecutableRange(
        guest,sourcePlan,proof,stackBase,invalid) ||
     rx::ResolveOriginalSourceExecutableRange(
        guest,sourcePlan,proof,sourceLdso->chosenImageStart+
          c7b::kImageCapacity,invalid))return 27;
  auto broken=sourcePlan;
  broken.sourceShaVerified=false;
  if(rx::ResolveOriginalSourceExecutableRange(
       guest,broken,proof,launch->guestInterpreterEntry,fake))return 28;
  broken=sourcePlan;
  broken.modules[1].rights[
      (launch->guestInterpreterEntry-sourceLdso->chosenImageStart)/4096]|=
          c7g::kWrite;
  if(rx::ResolveOriginalSourceExecutableRange(
       guest,broken,proof,launch->guestInterpreterEntry,fake))return 29;
  auto unapplied=proof;
  unapplied.nativeNoWritableExecutablePage=false;
  if(rx::ResolveOriginalSourceExecutableRange(
       guest,sourcePlan,unapplied,launch->guestInterpreterEntry,fake))return 30;
  // Actual native guest original main-owned Linux x86 brk(12)
  // bridge. No native ::brk or host heap is changed.
  brk::OriginalGuestMainProgramBreak programBreak{};
  if(!programBreak.Install(guest,sourcePlan,proof) ||
     !programBreak.Ready() ||
     programBreak.Minimum()==0 ||
     programBreak.Current()!=programBreak.Minimum() ||
     programBreak.Limit()<=programBreak.Minimum() ||
     programBreak.Limit()-programBreak.Minimum()>1024*1024)return 32;
  const uint64_t initialBreak=programBreak.Minimum();
  if(RightsAt(maps,initialBreak)!="---p")return 33;
  kernix::g2e::c1::TrapClassification guestBrk{};
  guestBrk.trapBoundaryAuthenticated=true;
  guestBrk.sourceRegisterMappingChecked=true;
  guestBrk.guestNumber=kernix::g2e::c1::kBrk;
  guestBrk.category=kernix::g2e::c1::CallCategory::NeedsGuestKernel;
  auto result=programBreak.Dispatch(guestBrk);
  if(!result.authenticatedGuestBrk || !result.queriedOnly ||
     !result.originalMainOwnerRangeUsed ||
     result.nativeHostBrkOrSbrkCalled || result.originalPTLoadRightsModified ||
     result.guestReturn!=initialBreak ||
     RightsAt(Areas(),initialBreak)!="---p")return 34;
  // Revoke an untrusted x86 syscall trap before any host mprotect.
  guestBrk.sourceRegisterMappingChecked=false;
  if(programBreak.Dispatch(guestBrk).authenticatedGuestBrk)return 35;
  guestBrk.sourceRegisterMappingChecked=true;
  const uint64_t oldData=initialBreak;
  guestBrk.args[0]=initialBreak+257;
  result=programBreak.Dispatch(guestBrk);
  if(result.guestReturn!=initialBreak+257 ||
     !result.authenticatedGuestBrk ||
     !result.nativeGuestHeapPermissionsChanged ||
     RightsAt(Areas(),oldData)!="rw-p" ||
     RightsAt(Areas(),oldData+4096)!="---p" ||
     programBreak.Current()!=initialBreak+257)return 36;
  // Guest brk in its own program image may grow only in source
  // original PROT_NONE spare pages, never touching PT_LOAD RX/WX.
  guestBrk.args[0]=initialBreak+8193;
  result=programBreak.Dispatch(guestBrk);
  if(result.guestReturn!=initialBreak+8193 ||
     RightsAt(Areas(),oldData+4096)!="rw-p" ||
     RightsAt(Areas(),oldData+8192)!="rw-p" ||
     RightsAt(Areas(),oldData+12288)!="---p")return 37;
  const auto beforeDenied=programBreak.Current();
  guestBrk.args[0]=initialBreak-8;
  result=programBreak.Dispatch(guestBrk);
  if(result.guestReturn!=beforeDenied ||
     !result.growthDeniedWithoutNativeMemoryChange ||
     programBreak.Current()!=beforeDenied)return 38;
  guestBrk.args[0]=programBreak.Limit()+4096;
  result=programBreak.Dispatch(guestBrk);
  if(result.guestReturn!=beforeDenied ||
     !result.growthDeniedWithoutNativeMemoryChange ||
     programBreak.Current()!=beforeDenied)return 39;
  // Native shrink first discards then PROT_NONE seals pages. Final
  // grow must return zeroed pages, not stale original guest data.
  guestBrk.args[0]=initialBreak;
  result=programBreak.Dispatch(guestBrk);
  if(result.guestReturn!=initialBreak ||
     !result.nativeGuestHeapPermissionsChanged ||
     RightsAt(Areas(),oldData)!="---p" ||
     RightsAt(Areas(),oldData+8192)!="---p")return 40;
  guestBrk.args[0]=initialBreak+4096;
  result=programBreak.Dispatch(guestBrk);
  if(result.guestReturn!=initialBreak+4096 ||
     RightsAt(Areas(),oldData)!="rw-p")return 41;
  const auto* zeroed=reinterpret_cast<const uint8_t*>(
                        static_cast<uintptr_t>(oldData));
  for(size_t off=0;off<4096;++off)if(zeroed[off]!=0)return 42;
  // Finally restore all non-PTLOAD pages to PROT_NONE. No guest brk
  // data may survive as executable nor corrupt original source.
  guestBrk.args[0]=initialBreak;
  result=programBreak.Dispatch(guestBrk);
  if(result.guestReturn!=initialBreak ||
     RightsAt(Areas(),oldData)!="---p" ||
     RightsAt(Areas(),launch->guestInterpreterEntry)!="r-xp" ||
     RightsAt(Areas(),launch->guestMainEntry)!="r-xp")return 43;
  if(!guest.Release() || guest.WindowsHeld()!=0)return 20;
  // The former owner is released: never mprotect a stale guest VA
  // that might have been assigned to another native mapping.
  guestBrk.args[0]=initialBreak+4096;
  if(programBreak.Dispatch(guestBrk).authenticatedGuestBrk)return 44;
  if(rx::ResolveOriginalSourceExecutableRange(
       guest,sourcePlan,proof,launch->guestInterpreterEntry,invalid))return 31;
  const auto after=Areas();
  if(RightsAt(after,mainRIP)!="unmapped" ||
     RightsAt(after,ldsoRIP)!="unmapped" ||
     RightsAt(after,stackBase)!="unmapped")
    return 21;
  std::printf(
    "KERNIX_G0_NATIVE_GUEST_LINUX_X86_BRK12_ORIGINAL_MAIN_ELF_OWNED_PTLOAD_SPARE_RW_GROW_SHRINK_WX_PASS rx_pages=%zu denied_pages=%zu ldso_pages=%zu libc_pages=%zu"
    " source_sha256_three=1"
    " native_page_rights_verified_entire_three_8m_images=1"
    " original_file_backed_bytes_unchanged=1"
    " no_native_writable_executable_page=1"
    " original_entry_pages_rx=1"
    " non_ptload_pages_prot_none=1"
    " x86_original_stack_guard_prot_none=1"
    " real_linux_x86_initial_stack_rw_no_exec=1"
    " injected_mprotect_failure_unmaps_four_windows=1"
    " final_four_windows_released=1"
    " original_ldso_executed=0 fex=0 android_device=0 wine=0\n",resolved,denied,sourceLoaderPages,sourceLibcPages);
  return 0;
}
