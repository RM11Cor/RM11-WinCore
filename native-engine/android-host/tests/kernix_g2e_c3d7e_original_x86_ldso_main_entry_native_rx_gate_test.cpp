// SPDX-License-Identifier: MIT
// C3-D7E on native Linux ARM64 & x86_64: independently attest original
// SHA-256 locked x86 main and ld-linux *instruction* bytes at the real
// rebased PIE entry, temporarily PROT_RX then restore PROT_RO in owned
// native kernel-selected low canonical VMAs. No FEX, no guest exec.
#include "kernix_g2e_c3d7e_original_ldso_entry_rx_ownership.h"
#include <array>
#include <cassert>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <string>
#include <sys/mman.h>
#include <unistd.h>

namespace c7e=kernix::g2e::c3d7e;
namespace c7b=kernix::g2e::c3d7b;
static std::string PermissionsAt(uint64_t guest) {
  std::ifstream maps("/proc/self/maps");
  std::string row;
  while(std::getline(maps,row)) {
    unsigned long long lo=0,hi=0;
    char perms[5]{};
    if(std::sscanf(row.c_str(),"%llx-%llx %4s",
        &lo,&hi,perms)!=3)continue;
    if(guest>=lo && guest<hi)return std::string(perms);
  }
  return "unmapped";
}
int main(int argc,char** argv) {
  if(argc!=2 || !argv[1])return 2;
  if(::sysconf(_SC_PAGESIZE)!=4096)return 3;
  const int fd=::open(argv[1],O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
  if(fd<0)return 4;
  std::array<uint8_t,16> random{};
  for(size_t i=0;i<random.size();++i)
    random[i]=static_cast<uint8_t>(i+1);
  kernix::g2e::GuestPreflight original;
  std::string why;
  if(!kernix::g2e::Validate(fd,original,why)) {
    std::fprintf(stderr,"C3D7E_REJECT_PINNED_SOURCE %s\n",why.c_str());
    ::close(fd);return 5;
  }
  c7b::NativeChosenPIEGuestLayout guest;
  c7b::Witness witness;
  if(!guest.Stage(fd,random,witness) ||
     witness.phase!=c7b::Phase::Complete ||
     witness.imagesVerified!=3 ||
     !witness.pinnedOriginalELFSHA256Verified ||
     !witness.originalBytesCopiedReadOnly ||
     witness.originalELFCodeExecuted ||
     witness.originalLdsoExecuted ||
     witness.originalFEXGuestMemoryAttached ||
     guest.WindowsHeld()!=4) {
    std::fprintf(stderr,"C3D7E_REJECT_STAGE phase=%s errno=%d\n",
       c7b::PhaseName(witness.phase),witness.failureErrno);
    ::close(fd);return 6;
  }
  ::close(fd);
  const auto* launch=guest.LaunchPlan();
  if(!launch || launch->guestMainEntry!=witness.mainRebasedEntry ||
     launch->guestInterpreterEntry!=witness.originalInterpreterRebasedRIP)
    return 7;
  const uint64_t mainRIP=launch->guestMainEntry;
  const uint64_t interpRIP=launch->guestInterpreterEntry;
  assert(PermissionsAt(mainRIP)=="r--p");
  assert(PermissionsAt(interpRIP)=="r--p");
  c7e::EntryProof main{};
  c7e::EntryProof interpreter{};
  if(!c7e::VerifyOriginalGuestEntryAndTemporaryHostRX(
        guest,original,0,main)) {
    std::fprintf(stderr,"C3D7E_MAIN_ENTRY_DENIED errno=%d guest=%llx xseg=%zu\n",
      main.lastErrno,static_cast<unsigned long long>(main.guestRIP),
      main.executableSegments);
    return 8;
  }
  if(!c7e::VerifyOriginalGuestEntryAndTemporaryHostRX(
        guest,original,1,interpreter)) {
    std::fprintf(stderr,"C3D7E_LDSO_ENTRY_DENIED errno=%d guest=%llx xseg=%zu\n",
      interpreter.lastErrno,
      static_cast<unsigned long long>(interpreter.guestRIP),
      interpreter.executableSegments);
    return 9;
  }
  for(const c7e::EntryProof* w: {&main,&interpreter}) {
    assert(w->guestRIP!=0);
    assert(w->entrySourceELFVirtual!=0);
    assert(w->selectedImageBase!=0);
    assert(w->testedOriginalCodeBytes==16);
    assert(w->executableSegments>0);
    assert(w->entryIsInsideOriginalFileBackedRXSegment);
    assert(w->instructionBytesMatchOriginalSource);
    assert(w->kernelNativeRXTemporarilyEstablished);
    assert(w->nativeRORestored);
    assert(!w->originalGuestInstructionsExecuted);
    assert(!w->originalDynamicLinkerStarted);
    assert(!w->fexGuestRIPAssigned);
    assert(w->lastErrno==0);
  }
  assert(mainRIP!=interpRIP);
  assert(PermissionsAt(mainRIP)=="r--p");
  assert(PermissionsAt(interpRIP)=="r--p");
  assert(PermissionsAt(launch->stack.guestRSP)=="r--p");
  if(!guest.Release() || guest.WindowsHeld()!=0)return 10;
  if(PermissionsAt(mainRIP)!="unmapped" ||
     PermissionsAt(interpRIP)!="unmapped")return 11;
  std::puts("KERNIX_G2EC3D7E_REAL_ORIGINAL_PINNED_X86_MAIN_AND_LDSO_ENTRY_INSTRUCTION_BYTES_WX_LINUX_PASS main_entry_bytes=16 ldso_entry_bytes=16 source_sha256_locked=1 guest_RIP_rebased=1 native_guest_VA_kernel_chosen=1 native_RX_without_W=1 permission_restored_RO=1 maps_released=1 original_guest_elf_rip_executed=0 original_ldso_executed=0 fex=0 android_device=0 wine=0");
  return 0;
}
