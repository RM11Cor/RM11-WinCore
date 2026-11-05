// SPDX-License-Identifier: MIT
// Linux x86_64 & AArch64 CI: exact upstream pinned FEX x86 CPUState ABI,
// original SHA256 attested x86 Linux main/ld-linux/libc TLS 16/136/8,
// and fail-closed real FS/GS, DTV/TCB, IFUNC and ld-linux startup gate.
// NOT an actual FEX execution, not FEX guest live FS assignment.
#include "kernix_g2e_c3d7k_source_pinned_fex_fs_gs_cpu_state_abi_gate.h"
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <unistd.h>
namespace b=kernix::g2e::c3d7b;
namespace g=kernix::g2e::c3d7g;
namespace h=kernix::g2e::c3d7h;
namespace i=kernix::g2e::c3d7i;
namespace j=kernix::g2e::c3d7j;
namespace k=kernix::g2e::c3d7k;
int main(int argc,char** argv) {
  if(argc!=2 || !argv[1])return 2;
  if(sysconf(_SC_PAGESIZE)!=4096)return 3;
  const int fd=open(argv[1],O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
  if(fd<0)return 4;
  kernix::g2e::GuestPreflight source;
  std::string reason;
  if(!kernix::g2e::Validate(fd,source,reason)) {
    std::fprintf(stderr,"C3D7K_ORIGINAL_SOURCE_DENIED %s\n",reason.c_str());
    close(fd);return 5;
  }
  std::array<uint8_t,16> entropy{};
  for(size_t n=0;n<16;++n)entropy[n]=uint8_t(n+1);
  b::NativeChosenPIEGuestLayout guest;
  b::Witness stage;
  if(!guest.Stage(fd,entropy,stage) ||
     !stage.pinnedOriginalELFSHA256Verified ||
     stage.originalELFCodeExecuted ||
     stage.originalLdsoExecuted ||
     guest.WindowsHeld()!=4) {
    close(fd);return 6;
  }
  close(fd);
  g::PermissionPlan rights;
  g::Reject rr;
  if(!g::BuildVerifiedOriginalPermissionPlan(
       source,guest,rights,rr))return 7;
  h::Plan relro;
  h::Reject hr;
  if(!h::BuildVerifiedOriginalThreeELFRelroPlan(
       source,guest,rights,relro,hr))return 8;
  i::Plan dyn;
  i::Reject dr;
  if(!i::InspectOriginalThreeModules(
       source,guest,rights,relro,dyn,dr))return 9;
  j::TLSModel tls;
  j::DependencyGate deps;
  j::Reject jr;
  if(!j::BuildOriginalStaticTLSModel(
       source,guest,dyn,relro,tls,deps,jr))return 10;
  k::Witness witness;
  k::Reject why;
  if(!k::InspectSourcePinnedFEXGuestFSandGS(
       tls,deps,witness,why)) {
    std::fprintf(stderr,"C3D7K_ORIGINAL_FEX_CPUSTATE_ABI_REJECT reason=%u\n",
      unsigned(why));
    return 11;
  }
  if(!witness.exactFEXCpuStateLayoutCompiled ||
     !witness.originalLibcTLSVerified ||
     !witness.fsCachedAndGsCachedDistinct64BitFields ||
     !witness.independentIsolatedFEXStateFSAndGSReadback ||
     !witness.isolatedStateFSAndGSReturnedToZero ||
     witness.actualOriginalLibcTLSBytes!=136 ||
     witness.originalIFUNCResolversNotExecuted!=47 ||
     !witness.originalGuestCPUStateNotAttached ||
     witness.originalGuestFSBaseAssigned ||
     witness.originalGuestTCBOrDTVCreated ||
     witness.originalIFUNCResolversExecuted ||
     witness.originalLdsoExecuted ||
     witness.androidDeviceRuntimeTested ||
     witness.sourceFSBaseFieldOffset==
       witness.sourceGSBaseFieldOffset ||
     witness.sourceFSSelectorFieldOffset==
       witness.sourceGSSelectorFieldOffset)return 12;
  // A fake real FS-base proposal must NEVER be allowed by source-only
  // model, even when dependent runtime-completion flags are forged.
  const auto forbiddenHostOnlyTP=
      static_cast<uint64_t>(tls.modelThreadPointerIndex);
  if(k::AuthorizeLiveOriginalGuestFSBase(
       tls,witness,forbiddenHostOnlyTP,why) ||
     why!=k::Reject::HostOnlyTLSNeverGuestFSBase)return 13;
  if(k::AuthorizeLiveOriginalGuestFSBase(
       tls,witness,tls.originalGuestTLSVirtualAddress,why) ||
     why!=k::Reject::NoValidatedTCBDTV)return 14;
  j::DependencyGate forged=deps;
  forged.guestFSBaseAssigned=true;
  forged.realRelocationWritePerformed=true;
  if(k::InspectSourcePinnedFEXGuestFSandGS(
       tls,forged,witness,why) ||
     why!=k::Reject::OriginalTLSUnverified)return 15;
  if(!guest.Release() || guest.WindowsHeld()!=0)return 16;
  std::printf(
    "KERNIX_G2EC3D7K_REAL_SOURCE_PINNED_FEX_CPUSTATE_X86_FS_GS_TLS_ABI_BARRIER_LINUX_PASS"
    " original_three_sha256=1"
    " real_FEXCore_CPUState_fs_cached_64bit=1"
    " real_FEXCore_CPUState_gs_cached_64bit=1"
    " fs_gs_fields_distinct=1"
    " standalone_CPUState_readback_and_reset=1"
    " real_original_libc_tls_16_136_8=1"
    " original_47_ifunc_unexecuted=1"
    " reject_host_only_scratch_as_guest_fs=1"
    " reject_unverified_tcb_dtv=1"
    " reject_forged_real_guest_fs=1"
    " real_live_FEX_thread_attached=0"
    " real_guest_FS_GS_initialized=0"
    " actual_ldso_relocations=0"
    " original_ldso_guest_RIP_executed=0"
    " android_runtime=0 wine=0\n");
  return 0;
}
