// SPDX-License-Identifier: MIT
// C3-D7J: exact original Linux x86_64 libc PT_TLS initializer in a
// bounded host-only Variant II negative-TP scratch model, plus real
// unresolved IFUNC/IRELATIVE/FS/GS/TCB/DTV dependency gate.
// Runs on Linux x86_64 and AArch64; NO actual FEX, FS/GS, glibc
// relocations, original ld-linux entry, Android runtime, Wine or games.
#include "kernix_g2e_c3d7j_original_x86_static_tls_variant2_order_gate.h"
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
static int Fail(int stage) {
  std::fprintf(stderr,"C3D7J_FIRST_UNMET_CONDITION_STAGE=%d\\n",stage);
  return stage;
}
int main(int argc,char** argv) {
  if(argc!=2 || !argv[1])return 2;
  if(::sysconf(_SC_PAGESIZE)!=4096)return 3;
  const int fd=::open(argv[1],O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
  if(fd<0)return 4;
  kernix::g2e::GuestPreflight original;
  std::string reason;
  if(!kernix::g2e::Validate(fd,original,reason)) {
    std::fprintf(stderr,"C3D7J_ORIGINAL_SHA256_DENIED %s\n",reason.c_str());
    ::close(fd);return 5;
  }
  std::array<uint8_t,16> entropy{};
  for(size_t k=0;k<16;++k)entropy[k]=uint8_t(k+1);
  b::NativeChosenPIEGuestLayout guest;
  b::Witness witness;
  if(!guest.Stage(fd,entropy,witness) ||
     !witness.pinnedOriginalELFSHA256Verified ||
     witness.originalELFCodeExecuted ||
     witness.originalLdsoExecuted ||
     guest.WindowsHeld()!=4) {
    ::close(fd);return 6;
  }
  ::close(fd);
  g::PermissionPlan pages;
  g::Reject pgReason;
  if(!g::BuildVerifiedOriginalPermissionPlan(
      original,guest,pages,pgReason))return 7;
  h::Plan relro;
  h::Reject relroReason;
  if(!h::BuildVerifiedOriginalThreeELFRelroPlan(
      original,guest,pages,relro,relroReason))return 8;
  i::Plan relocation;
  i::Reject dynReason;
  if(!i::InspectOriginalThreeModules(
      original,guest,pages,relro,relocation,dynReason))return 9;
  j::TLSModel scratch;
  j::DependencyGate dependencies;
  j::Reject reject;
  if(!j::BuildOriginalStaticTLSModel(
      original,guest,relocation,relro,scratch,dependencies,reject)) {
    std::fprintf(stderr,"C3D7J_ORIGINAL_LIBC_TLS_REJECTED reason=%u\n",
      unsigned(reject));
    return 10;
  }
  const auto& libc=relocation.modules[2];
  if(scratch.originalModule!=2 ||
     scratch.originalGuestTLSVirtualAddress!=libc.tlsOriginalGuestVA ||
     scratch.originalInitializerBytes!=libc.tlsInitFileSize ||
     scratch.totalTLSMemoryBytes!=libc.tlsTotalMemorySize ||
     scratch.zeroFilledTBSSBytes!=
       libc.tlsTotalMemorySize-libc.tlsInitFileSize ||
     scratch.alignedStaticBlockBytes<libc.tlsTotalMemorySize ||
     scratch.alignedStaticBlockBytes%libc.tlsAlignment ||
     scratch.modelThreadPointerIndex!=j::kScratchBytes ||
     scratch.negativeTPRelativeStart>=0 ||
     size_t(-scratch.negativeTPRelativeStart)!=
       scratch.alignedStaticBlockBytes ||
     scratch.negativeTLSBlockStart+
       scratch.alignedStaticBlockBytes!=j::kScratchBytes ||
     !scratch.sourceInitializerMatchesOriginalELF ||
     !scratch.zeroFillMatchesOriginalPTTLSMemsz ||
     !scratch.x86VariantIIModelOnly ||
     !scratch.nativeHostFSGSRegistersUnchanged ||
     scratch.realGuestTCBInitialized ||
     scratch.realGuestDTVInitialized ||
     scratch.realGuestFSBaseAssigned ||
     scratch.originalLdsoExecuted)return Fail(11);
  // Verify the real immutable libc source ELF PT_TLS is reproduced in
  // exactly the first initFileSize model bytes; every TBSS and padding
  // byte MUST be zero. The source-backed guest TLS shadow stays RO.
  const auto* nativeSource=guest.GuestReadOnlyBytes(
      2,libc.tlsOriginalGuestVA,
      size_t(libc.tlsInitFileSize));
  if(!nativeSource ||
     std::memcmp(
       scratch.bytes.data()+scratch.negativeTLSBlockStart,
       nativeSource,scratch.originalInitializerBytes)!=0)
    return Fail(12);
  for(size_t k=scratch.negativeTLSBlockStart+
      scratch.originalInitializerBytes;
      k<j::kScratchBytes;++k) {
    if(scratch.bytes[k]!=0)return Fail(13);
  }
  for(size_t k=0;k<scratch.negativeTLSBlockStart;++k) {
    if(scratch.bytes[k]!=0)return Fail(14);
  }
  size_t sums=0,IFUNCs=0,relr=0,symbolic=0;
  for(const auto& module:relocation.modules) {
    sums+=module.relaEntries+module.pltRelaEntries;
    IFUNCs+=module.irelativeRelaEntries;
    relr+=module.relrTargets;
    symbolic+=module.symbolicRelaEntries;
  }
  if(!dependencies.authenticateThreeOriginalELFs ||
     !dependencies.linuxX86VariantIIInitializerModeled ||
     !dependencies.requiresGuestSymbolVersionResolution ||
     !dependencies.requiresRealGuestTCBAndDTV ||
     !dependencies.requiresActualGuestFSBase ||
     !dependencies.requiresRealIFUNCResolverGuestExecution ||
     !dependencies.requiresActualRelocationWrites ||
     !dependencies.requiresPostRelocationRELRO ||
     dependencies.anyOriginalX86InstructionExecuted ||
     dependencies.realRelocationWritePerformed ||
     dependencies.guestFSBaseAssigned ||
     dependencies.guestRelroApplied ||
     dependencies.androidDeviceTested ||
     dependencies.sourceOriginalIRelativeResolvers!=IFUNCs ||
     dependencies.sourceOriginalRelrTargets!=relr ||
     dependencies.sourceOriginalRelaAndPltEntries!=sums ||
     dependencies.sourceOriginalSymbolicRelaEntries!=symbolic ||
     dependencies.sourceOriginalTLSModules!=1 ||
     IFUNCs==0 || relr==0 || sums==0)
    return Fail(15);
  // Synthetic copies must fail closed without harming original guest
  // source. Spoofing a "completed" flag cannot enable any runtime
  // transition; there is no source-only RELRO authorization API.
  i::Plan altered=relocation;
  altered.modules[2].tlsAlignment=3;
  j::TLSModel negativeModel{};
  j::DependencyGate negativeDeps{};
  if(j::BuildOriginalStaticTLSModel(
      original,guest,altered,relro,
      negativeModel,negativeDeps,reject) ||
     reject!=j::Reject::InvalidTLS)return Fail(16);
  altered=relocation;
  altered.modules[2].tlsTotalMemorySize=UINT64_MAX;
  if(j::BuildOriginalStaticTLSModel(
      original,guest,altered,relro,
      negativeModel,negativeDeps,reject) ||
     reject!=j::Reject::OversizeTLS)return Fail(17);
  altered=relocation;
  altered.modules[2].tlsOriginalGuestVA+=8;
  if(j::BuildOriginalStaticTLSModel(
      original,guest,altered,relro,
      negativeModel,negativeDeps,reject) ||
     reject!=j::Reject::InvalidTLS)return Fail(18);
  altered=relocation;
  altered.originalELFRelocationsApplied=true;
  if(j::BuildOriginalStaticTLSModel(
      original,guest,altered,relro,
      negativeModel,negativeDeps,reject) ||
     reject!=j::Reject::SourceNotAttested)return Fail(19);
  j::DependencyGate forged=dependencies;
  forged.realRelocationWritePerformed=true;
  forged.guestFSBaseAssigned=true;
  forged.guestRelroApplied=true;
  if(j::AuthorizeOriginalLdsoRelocationOrRelroFromMetadataOnly(
      forged,reject) ||
     reject!=j::Reject::GuestRuntimeNotStarted)
    return Fail(20);
  if(!guest.Release() || guest.WindowsHeld()!=0)return Fail(21);
  std::printf(
    "KERNIX_G2EC3D7J_AUTHENTIC_LIBC_X86_VARIANT_II_TLS_AND_RELOCATION_DEPENDENCY_MODEL_LINUX_PASS"
    " original_three_sha256=1 original_tls_init_bytes=%zu"
    " tls_total_mem_bytes=%zu tls_aligned_bytes=%zu"
    " variant_ii_negative_tp_offset=%lld"
    " real_relr_targets=%zu real_irelative_resolvers=%zu"
    " all_tls_tbss_padding_zero=1"
    " invalid_tls_alignment_and_extent_denied=1"
    " forged_relocation_completion_cannot_unseal=1"
    " native_fs_gs_unchanged=1 guest_tcb_dtv_uninitialized=1"
    " guest_relocations_applied=0 real_original_ldso_rip_executed=0"
    " fex=0 android_runtime=0 wine=0\n",
    scratch.originalInitializerBytes,scratch.totalTLSMemoryBytes,
    scratch.alignedStaticBlockBytes,
    static_cast<long long>(scratch.negativeTPRelativeStart),
    relr,IFUNCs);
  return 0;
}
