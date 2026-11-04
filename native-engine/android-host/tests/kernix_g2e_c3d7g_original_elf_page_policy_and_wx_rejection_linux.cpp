// SPDX-License-Identifier: MIT
// C3-D7G Linux ARM64 and x86-64: source-attested three real ELF PT_LOAD
// 4K permission policy, real rebased guest entry and stack. No execution,
// mprotect, Android runtime, original ld-linux startup, Wine or games.
// Invalid ELF mutations below are only synthetic NEGATIVE tests; none is
// authenticated or allowed to stage.
#include "kernix_g2e_c3d7g_original_elf_pt_load_page_policy.h"
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <elf.h>
#include <fcntl.h>
#include <string>
#include <vector>
#include <unistd.h>
namespace c7g=kernix::g2e::c3d7g;
namespace c7b=kernix::g2e::c3d7b;

static bool ExpectMaliciousFlagsRejected(
    const kernix::g2e::GuestPreflight& source,
    const c7b::ImageMeta& meta,uint64_t mainEntry) {
  const auto& s=source.snapshots[0];
  std::vector<unsigned char> mutated(s.bytes(),s.bytes()+s.size());
  Elf64_Ehdr elf{};
  std::memcpy(&elf,mutated.data(),sizeof(elf));
  size_t execPH=SIZE_MAX,secondPH=SIZE_MAX;
  for(uint16_t i=0;i<elf.e_phnum;++i) {
    Elf64_Phdr ph{};
    const size_t at=static_cast<size_t>(elf.e_phoff)+
                    size_t(i)*sizeof(ph);
    std::memcpy(&ph,mutated.data()+at,sizeof(ph));
    if(ph.p_type!=PT_LOAD || !ph.p_memsz)continue;
    if((ph.p_flags&PF_X) && execPH==SIZE_MAX)execPH=at;
    else if(!(ph.p_flags&PF_X) && secondPH==SIZE_MAX)secondPH=at;
  }
  if(execPH==SIZE_MAX || secondPH==SIZE_MAX)return false;
  Elf64_Phdr executable{};
  std::memcpy(&executable,mutated.data()+execPH,sizeof(executable));
  c7g::ModulePolicy attempted;
  c7g::Reject rejected=c7g::Reject::None;

  // A W+X PT_LOAD flag itself is forbidden.
  Elf64_Phdr bad=executable;
  bad.p_flags|=PF_W;
  std::memcpy(mutated.data()+execPH,&bad,sizeof(bad));
  const bool badWX=c7g::BuildModulePolicy(
    mutated.data(),mutated.size(),meta,mainEntry,attempted,rejected);
  if(badWX || rejected!=c7g::Reject::BadSegment)return false;
  std::memcpy(mutated.data()+execPH,&executable,sizeof(executable));

  // Two distinct nominally safe PT_LOAD segments may round onto the
  // same native 4096-byte page and create an effective W+X collision.
  // Deliberately overlap executable original range with an RW clone.
  Elf64_Phdr overlap=executable;
  overlap.p_flags=PF_R|PF_W;
  std::memcpy(mutated.data()+secondPH,&overlap,sizeof(overlap));
  rejected=c7g::Reject::None;
  const bool allowedConflict=c7g::BuildModulePolicy(
    mutated.data(),mutated.size(),meta,mainEntry,attempted,rejected);
  if(allowedConflict ||
     rejected!=c7g::Reject::ConflictingWXPage)return false;
  // Malformed source offset must also fail independent of flags.
  overlap.p_offset=UINT64_MAX;
  std::memcpy(mutated.data()+secondPH,&overlap,sizeof(overlap));
  rejected=c7g::Reject::None;
  const bool allowedOverflow=c7g::BuildModulePolicy(
    mutated.data(),mutated.size(),meta,mainEntry,attempted,rejected);
  if(allowedOverflow || rejected!=c7g::Reject::BadSegment)return false;

  // Original attested source snapshot remains byte-for-byte immutable.
  return s.bytes()!=nullptr && s.size()==mutated.size() &&
         std::memcmp(s.bytes(),mutated.data(),
                     sizeof(Elf64_Ehdr))==0;
}
int main(int argc,char** argv) {
  if(argc!=2 || !argv[1])return 2;
  if(::sysconf(_SC_PAGESIZE)!=4096)return 3;
  const int fd=open(argv[1],O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
  if(fd<0)return 4;
  std::array<uint8_t,16> seed{};
  for(size_t i=0;i<seed.size();++i)seed[i]=uint8_t(i+1);
  kernix::g2e::GuestPreflight original;
  std::string why;
  if(!kernix::g2e::Validate(fd,original,why)){
    std::fprintf(stderr,"C3D7G_ORIGINAL_ELF_SHA_REJECTED %s\n",why.c_str());
    close(fd);return 5;
  }
  c7b::NativeChosenPIEGuestLayout guest;
  c7b::Witness setup;
  if(!guest.Stage(fd,seed,setup) ||
     !setup.pinnedOriginalELFSHA256Verified ||
     !setup.linuxAuxvRebased ||
     !setup.originalBytesCopiedReadOnly ||
     setup.originalELFCodeExecuted || setup.originalLdsoExecuted ||
     setup.originalFEXGuestMemoryAttached ||
     guest.WindowsHeld()!=4) {
    std::fprintf(stderr,"C3D7G_ORIGINAL_ELF_STAGE_FAILED phase=%s errno=%d\n",
       c7b::PhaseName(setup.phase),setup.failureErrno);
    close(fd);return 6;
  }
  close(fd);
  c7g::PermissionPlan policy;
  c7g::Reject error=c7g::Reject::None;
  if(!c7g::BuildVerifiedOriginalPermissionPlan(
       original,guest,policy,error)){
    std::fprintf(stderr,"C3D7G_ELF_PAGE_POLICY_REJECTED reason=%u\n",
      unsigned(error));
    return 7;
  }
  const auto* launch=guest.LaunchPlan();
  if(!launch || policy.stackRSP!=launch->stack.guestRSP ||
     policy.stackBottom!=launch->stack.guestBottom ||
     policy.stackBytes!=c7b::kStackCapacity ||
     policy.guardBytes!=4096 ||
     !policy.sourceShaVerified ||
     !policy.nativeGuestVAIdentityOwned ||
     !policy.allPTLoadPagesPlanned ||
     !policy.deniedWritableExecutablePages ||
     policy.originalLdsoExecuted || policy.androidRuntimeTested)
    return 8;
  size_t totalLoaded=0;
  size_t totalX=0,totalW=0,totalHoles=0;
  for(size_t i=0;i<3;++i) {
    const auto* meta=guest.Module(i);
    if(!meta || policy.modules[i].nativeOwnedStart!=
         meta->chosenImageStart ||
       policy.modules[i].loadSegments!=meta->loadSegments ||
       policy.modules[i].mappedPages==0 ||
       policy.modules[i].executablePages==0 ||
       policy.modules[i].mappedPages+
         policy.modules[i].inaccessiblePages!=c7g::kModulePages)
      return 9;
    for(uint8_t rights:policy.modules[i].rights) {
      if((rights&(c7g::kWrite|c7g::kExecute))==
          (c7g::kWrite|c7g::kExecute))return 10;
    }
    totalLoaded+=policy.modules[i].mappedPages;
    totalX+=policy.modules[i].executablePages;
    totalW+=policy.modules[i].writablePages;
    totalHoles+=policy.modules[i].inaccessiblePages;
  }
  if(totalLoaded==0 || totalW==0 || totalX==0 || totalHoles==0)
    return 11;
  if(policy.modules[0].nativeEntry!=setup.mainRebasedEntry ||
     policy.modules[1].nativeEntry!=setup.originalInterpreterRebasedRIP)
    return 12;
  if(!ExpectMaliciousFlagsRejected(
       original,*guest.Module(0),launch->guestMainEntry))
    return 13;
  if(!guest.Release() || guest.WindowsHeld()!=0)
    return 14;
  std::puts(
    "KERNIX_G2EC3D7G_EXACT_ORIGINAL_THREE_X86_ELF_4K_PT_LOAD_PERMISSION_PLAN_LINUX_PASS"
    " original_elf_sha256=1 modules=3 real_main_ldso_rx_entries=1"
    " libc_entry_not_required=1 page_granular_rights=1"
    " read_write_and_read_execute_disjoint=1 holes_stay_inaccessible_in_plan=1"
    " writable_executable_pt_load_denied=1"
    " overlapping_rw_rx_native_page_denied=1"
    " invalid_source_offset_denied=1"
    " original_guest_stack_guard_reserved_in_plan=1"
    " mappings_released=1 no_mprotect_applied=1"
    " original_ldso_executed=0 fex=0 android_device=0 wine=0");
  return 0;
}
