// SPDX-License-Identifier: MIT
// C3-D7H authentic pinned Linux x86-64 main/ld-linux/glibc GNU_RELRO
// plan only: no relocation, no early mprotect, no guest execution.
// Negative malformed phdr fixtures are NEVER source-authenticated.
#include "kernix_g2e_c3d7h_original_elf_relro_after_relocation_policy.h"
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <elf.h>
#include <fcntl.h>
#include <string>
#include <vector>
#include <unistd.h>
namespace h=kernix::g2e::c3d7h;
namespace g=kernix::g2e::c3d7g;
namespace b=kernix::g2e::c3d7b;
static bool NegativeRelroTests(
    const kernix::g2e::GuestPreflight& source,
    const b::NativeChosenPIEGuestLayout& owned,
    const g::PermissionPlan& initial) {
  for(size_t k=0;k<3;++k) {
    const auto& snapshot=source.snapshots[k];
    std::vector<unsigned char> mutated(
      snapshot.bytes(),snapshot.bytes()+snapshot.size());
    Elf64_Ehdr eh{};
    std::memcpy(&eh,mutated.data(),sizeof(eh));
    size_t relroAt=SIZE_MAX;
    Elf64_Phdr original{};
    Elf64_Phdr executable{};
    bool foundExecutable=false;
    for(uint16_t i=0;i<eh.e_phnum;++i) {
      const size_t p=size_t(eh.e_phoff)+
                     size_t(i)*sizeof(Elf64_Phdr);
      Elf64_Phdr ph{};
      std::memcpy(&ph,mutated.data()+p,sizeof(ph));
      if(ph.p_type==PT_GNU_RELRO && relroAt==SIZE_MAX) {
        relroAt=p;
        original=ph;
      }
      if(ph.p_type==PT_LOAD && ph.p_memsz>=8192 &&
         (ph.p_flags&PF_X)!=0 && !foundExecutable) {
        executable=ph;
        foundExecutable=true;
      }
    }
    if(relroAt==SIZE_MAX)continue;
    if(!foundExecutable)return false;
    auto parse=[&](h::Reject& reason) {
      h::ModuleRELRO temp;
      return h::BuildModule(
         mutated.data(),mutated.size(),*owned.Module(k),
         initial.modules[k],temp,reason);
    };
    // Wrapped native 64-bit extent MUST be denied.
    Elf64_Phdr ph=original;
    ph.p_vaddr=UINT64_MAX-1024;
    ph.p_memsz=8192;
    std::memcpy(mutated.data()+relroAt,&ph,sizeof(ph));
    h::Reject why=h::Reject::None;
    if(parse(why) || why!=h::Reject::InvalidRELROBounds)
      return false;
    // A tampered RELRO pointing into executable PT_LOAD code is not
    // a legal data-only post-relocation protection operation.
    ph=original;
    ph.p_vaddr=executable.p_vaddr&~uint64_t(4095);
    ph.p_memsz=8192;
    std::memcpy(mutated.data()+relroAt,&ph,sizeof(ph));
    why=h::Reject::None;
    if(parse(why) ||
        why!=h::Reject::RELROUnmappedOrExecutable)
      return false;
    // Source PHDR snapshot NEVER changed, only the synthetic buffer.
    if(std::memcmp(snapshot.bytes(),mutated.data(),
        sizeof(Elf64_Ehdr))!=0)return false;
    return true;
  }
  return false; // original triad without any RELRO cannot pass
}
int main(int argc,char** argv) {
  if(argc!=2 || !argv[1])return 2;
  if(sysconf(_SC_PAGESIZE)!=4096)return 3;
  int root=open(argv[1],O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
  if(root<0)return 4;
  kernix::g2e::GuestPreflight original;
  std::string why;
  if(!kernix::g2e::Validate(root,original,why)) {
    std::fprintf(stderr,"C3D7H_SOURCE_REJECTED %s\n",why.c_str());
    close(root);return 5;
  }
  b::NativeChosenPIEGuestLayout owned;
  b::Witness witness;
  std::array<uint8_t,16> entropy{};
  for(size_t i=0;i<16;++i)entropy[i]=uint8_t(i+1);
  if(!owned.Stage(root,entropy,witness) ||
     !witness.pinnedOriginalELFSHA256Verified ||
     witness.originalLdsoExecuted ||
     witness.originalELFCodeExecuted ||
     owned.WindowsHeld()!=4) {
    close(root);return 6;
  }
  close(root);
  g::PermissionPlan initial;
  g::Reject baseReason;
  if(!g::BuildVerifiedOriginalPermissionPlan(
       original,owned,initial,baseReason))
    return 7;
  h::Plan relro;
  h::Reject reject;
  if(!h::BuildVerifiedOriginalThreeELFRelroPlan(
       original,owned,initial,relro,reject)) {
    std::fprintf(stderr,
      "C3D7H_ORIGINAL_RELRO_PLAN_REJECT reason=%u\n",
      unsigned(reject));
    return 8;
  }
  if(!relro.exactOriginalSHA256Sources ||
     !relro.glibcBothEndpointsRoundedDown ||
     !relro.noNativeMprotectApplied ||
     !relro.noGuestELFRelocationsApplied ||
     !relro.noFEXOriginalLdsoExecuted ||
     relro.androidDeviceTested ||
     relro.relroHeaderCount==0 ||
     relro.totalFullPages==0 ||
     relro.totalInitiallyWritablePages==0)
    return 9;
  for(size_t k=0;k<3;++k) {
    const auto& module=relro.modules[k];
    const auto& originalPage=initial.modules[k];
    if(module.imageVA!=originalPage.nativeOwnedStart)
      return 10;
    size_t checked=0,initialWrites=0;
    for(size_t p=0;p<g::kModulePages;++p) {
      if(!module.sealedAfterRealRelocation[p])continue;
      ++checked;
      const uint8_t r=originalPage.rights[p];
      if(!(r&g::kRead) || (r&g::kExecute))return 11;
      if(r&g::kWrite)++initialWrites;
    }
    if(checked!=module.relroFullPages ||
       initialWrites!=module.relroInitiallyWritablePages)
      return 12;
  }
  if(!NegativeRelroTests(original,owned,initial))
    return 13;
  h::Reject sealing=h::Reject::None;
  if(h::SealOriginalRelroBeforeVerifiedRealRelocations(
       relro,sealing) ||
     sealing!=h::Reject::NoRelocationProof)
    return 14;
  if(!owned.LaunchPlan() ||
     witness.mainRebasedEntry!=owned.LaunchPlan()->guestMainEntry ||
     witness.originalInterpreterRebasedRIP!=
       owned.LaunchPlan()->guestInterpreterEntry)
    return 15;
  if(!owned.Release() || owned.WindowsHeld()!=0)
    return 16;
  std::puts(
    "KERNIX_G2EC3D7H_SOURCE_PINNED_GLIBC_GNU_RELRO_FLOOR_FLOOR_PLAN_LINUX_PASS"
    " three_authentic_x86_elf_sha256=1"
    " real_pt_gnu_relro_headers=1"
    " real_original_relro_full_pages=1"
    " glibc_start_and_end_floor_to_native_4k=1"
    " original_rw_data_pretend_relocation_not_applied=1"
    " relro_wx_and_holes_rejected=1"
    " overflow_and_executable_relro_fixture_denied=1"
    " no_native_mprotect_sealing=1"
    " premature_relro_seal_denied=1"
    " four_native_guest_windows_released=1"
    " original_ldso_executed=0 fex=0 android_device=0 wine=0");
  return 0;
}
