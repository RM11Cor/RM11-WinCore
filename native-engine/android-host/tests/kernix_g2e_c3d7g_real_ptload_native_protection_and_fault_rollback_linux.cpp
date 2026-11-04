// SPDX-License-Identifier: MIT
// C3-D7G second Linux gate: actually mprotect the source-verified
// kernel-owned 4K guest image pages from exact PT_LOAD permission plan,
// enforce PROT_NONE ELF holes and stack guard, re-check every mapped
// original source PT_LOAD byte, and prove injected failure unmaps all.
// No FEX, original ld-linux instruction execution, or Android device test.
#include "kernix_g2e_c3d7g_native_pt_load_wx_apply_gate.h"
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
  if(!guest.Release() || guest.WindowsHeld()!=0)return 20;
  const auto after=Areas();
  if(RightsAt(after,mainRIP)!="unmapped" ||
     RightsAt(after,ldsoRIP)!="unmapped" ||
     RightsAt(after,stackBase)!="unmapped")
    return 21;
  std::puts(
    "KERNIX_G2EC3D7G_AUTHENTIC_THREE_X86_ELF_PTLOAD_NATIVE_4K_WX_AND_STACK_GUARD_LINUX_PASS"
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
    " original_ldso_executed=0 fex=0 android_device=0 wine=0");
  return 0;
}
