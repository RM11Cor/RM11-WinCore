// SPDX-License-Identifier: MIT
// C3-D7B: REAL SHA-locked Linux x86_64 ET_DYN main + ld-linux + libc and
// x86_64 Linux AUXV stack rebased to 4 kernel-selected guest native VMAs.
// Linux-only data-stage test, NOT a FEX guest ld-linux runtime.
#include "kernix_g2e_c3d7b_kernel_selected_pie_guest_vas.h"
#include <array>
#include <cassert>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <string>
#include <sys/mman.h>
#include <unistd.h>

namespace c7=kernix::g2e::c3d7b;
static std::string RightsAt(uint64_t ptr) {
  std::ifstream maps("/proc/self/maps");
  std::string line;
  while(std::getline(maps,line)) {
    unsigned long long start=0,end=0;
    char flags[5]{};
    if(std::sscanf(line.c_str(),"%llx-%llx %4s",
                   &start,&end,flags)!=3)continue;
    if(ptr>=start && ptr<end)return std::string(flags);
  }
  return "unmapped";
}
int main(int argc,char** argv) {
  if(argc!=2)return 2;
  if(sysconf(_SC_PAGESIZE)!=4096) {
    std::puts("KERNIX_G2EC3D7B_NATIVE_NON4K_REJECTED");
    return 0;
  }
  int root=open(argv[1],O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
  if(root<0)return 3;
  std::array<uint8_t,16> entropy{};
  for(size_t i=0;i<16;++i)entropy[i]=static_cast<uint8_t>(i+1);
  {
    c7::NativeChosenPIEGuestLayout view;
    c7::Witness w;
    assert(!view.Stage(-1,entropy,w));
    assert(view.WindowsHeld()==0);
    assert(!view.Stage(root,entropy,w,2));
    assert(w.failureErrno==ECANCELED);
    assert(w.windowsReserved==2);
    assert(w.windowsReleasedOnFailure==2);
    assert(view.WindowsHeld()==0);
    assert(view.LaunchPlan()==nullptr);
  }
  {
    c7::NativeChosenPIEGuestLayout view;
    c7::Witness w;
    assert(view.Stage(root,entropy,w));
    assert(w.phase==c7::Phase::Complete);
    assert(w.imagesVerified==3);
    assert(w.windowsReserved==4);
    assert(w.pinnedOriginalELFSHA256Verified);
    assert(w.actualNativeKernel4K);
    assert(w.guestAddressEqualsOwnedHostPage);
    assert(w.originalBytesCopiedReadOnly);
    assert(w.linuxAuxvRebased);
    assert(!w.nativeExecutablePageGranted);
    assert(!w.originalFEXGuestMemoryAttached);
    assert(!w.originalLdsoExecuted);
    assert(!w.originalELFCodeExecuted);
    assert(view.WindowsHeld()==4);
    const auto* launch=view.LaunchPlan();
    assert(launch && launch->stackAndAuxvConsistent);
    assert(launch->guestVirtualAddressesValidated);
    assert(launch->dependencyObjectsChecked==3);
    assert(launch->guestInterpreterEntry==w.originalInterpreterRebasedRIP);
    assert(launch->guestMainEntry==w.mainRebasedEntry);
    assert(launch->stack.guestRSP==w.x86RebasedStackRSP);
    assert(launch->guestInterpreterEntry!=launch->guestMainEntry);
    assert(launch->guestMainEntry!=kernix::g2e::kC0MainTestVA);
    assert(launch->guestInterpreterEntry!=kernix::g2e::kC0LdsoTestVA);
    assert(launch->stack.guestBottom!=kernix::g2e::kC0StackTestVA);
    for(size_t i=0;i<3;++i) {
      const auto* image=view.Module(i);
      assert(image);
      assert(image->loadSegments>=2);
      assert(image->chosenImageStart!=0);
      assert(image->highestAlignedELFVA>image->lowestAlignedELFVA);
      assert(image->highestAlignedELFVA-
             image->lowestAlignedELFVA<=c7::kImageCapacity);
      assert(RightsAt(image->chosenImageStart)=="r--p");
      const auto* header=view.GuestReadOnlyBytes(
          i,image->chosenImageStart,16);
      assert(header && header[0]==0x7f && header[1]=='E' &&
             header[2]=='L' && header[3]=='F');
      assert(image->chosenImageStart>=0x10000);
      assert(image->chosenImageStart<c7::kImageCapacity+
             kernix::g2e::c1::kGuestUserLimit);
    }
    const auto* ldso=view.Module(1);
    assert(ldso);
    assert(launch->guestInterpreterEntry>=ldso->chosenImageStart);
    assert(launch->guestInterpreterEntry<
           ldso->chosenImageStart+c7::kImageCapacity);
    assert(view.GuestReadOnlyBytes(
        1,launch->guestInterpreterEntry,1)!=nullptr);
    assert(RightsAt(launch->guestInterpreterEntry)=="r--p");
    assert(RightsAt(launch->stack.guestBottom)=="r--p");
    assert(RightsAt(launch->stack.guestRSP)=="r--p");
    c7::Witness duplicate;
    assert(!view.Stage(root,entropy,duplicate));
    assert(duplicate.failureErrno==EINVAL);
    assert(view.WindowsHeld()==4);
    assert(view.Release());
    assert(view.WindowsHeld()==0);
    assert(RightsAt(launch->guestInterpreterEntry)=="unmapped");
    assert(view.LaunchPlan()==nullptr);
  }
  close(root);
  std::puts("KERNIX_G2EC3D7B_AUTHENTIC_THREE_X86_PIE_ET_DYN_GUEST_ASLR_REBASE_AND_AUXV_RO_LINUX_PASS modules=3 native_guest_identity_windows=4 kernel_page=4096 src_sha256=1 linux_ldso_entry_rebased=1 guest_stack_auxv_rebased=1 all_source_pages_host_ro=1 unmapped_on_release=1 original_ldso_executed=0 fex=0 android_device=0");
  return 0;
}
