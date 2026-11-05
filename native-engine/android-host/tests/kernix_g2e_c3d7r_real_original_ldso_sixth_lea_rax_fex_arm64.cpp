// SPDX-License-Identifier: MIT
// C3-D7R: six authentic source-pinned original ld-linux instructions,
// from MOV through second RIP-relative LEA, using real FEX Linux ARM64.
// Source and guest stack restoration. HLT before seventh SIMD MOVQ.
// Not Android handset, Wine, PE, games or complete glibc loader.
#define main kernix_c3d7r_c2_source_reference_main
#include "kernix_g2e_c2_original_fex_actual_syscall_trap_arm64.cpp"
#undef main
#include "kernix_g2e_c3d7e_original_ldso_entry_rx_ownership.h"
#include "kernix_g2e_c3d7g_native_pt_load_wx_apply_gate.h"
#include "kernix_g2e_c3d7n_original_ldso_call_source_target_gate.h"
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <elf.h>
#include <fcntl.h>
#include <fstream>
#include <optional>
#include <string>
#include <sys/mman.h>
#include <unistd.h>
#if !defined(__aarch64__) || !defined(KERNIX_G2EC2_ORIGINAL_FEX_LINUX_ARM64_CI)
#error C3D7R executes original ld-linux first x86 instruction Linux ARM64 CI only
#endif
namespace m=kernix::g2e;
namespace b=kernix::g2e::c3d7b;
namespace e=kernix::g2e::c3d7e;
namespace g=kernix::g2e::c3d7g;
namespace c7r {
static constexpr size_t kSourceBytes=16;
static constexpr size_t kTargetExecutableBytes=32; // covers crossing +16 sixth LEA and bounded seventh HLT
static constexpr size_t kOriginalTwoOpcodesBytes=8;
static constexpr size_t kOriginalENDBR64Bytes=4;
static constexpr size_t kOriginalFifthLEABytes=7;
static constexpr size_t kOriginalFifthEndOffset=kOriginalENDBR64Bytes+1+kOriginalFifthLEABytes;
static constexpr size_t kOriginalSixthLEABytes=7;
static constexpr size_t kNextInstructionOffset=kOriginalFifthEndOffset+kOriginalSixthLEABytes;
static constexpr uint8_t kInjectedHLT=0xf4;
static std::string RightsAt(uint64_t at) {
  std::ifstream in("/proc/self/maps");
  std::string line;
  while(std::getline(in,line)) {
    unsigned long long lo=0,hi=0;
    char permissions[5]{};
    if(std::sscanf(line.c_str(),"%llx-%llx %4s",
                   &lo,&hi,permissions)!=3)continue;
    if(at>=lo && at<hi)return std::string(permissions);
  }
  return "unmapped";
}
class DenyAllGuestSyscalls final : public FEXCore::HLE::SyscallHandler {
public:
  DenyAllGuestSyscalls(uint64_t rip,uint64_t target):rip_(rip),target_(target){}
  void HandleSyscall(FEXCore::Core::CpuStateFrame*) override {
    std::fputs("KERNIX_C3D7R_UNEXPECTED_GUEST_SYSCALL_DENIED\n",stderr);
    std::fflush(stderr);
    _exit(94);
  }
  FEXCore::HLE::ExecutableRangeInfo QueryGuestExecutableRange(
       FEXCore::Core::InternalThreadState*,uint64_t query) override {
    if(query>=rip_ && query<rip_+kSourceBytes)
      return {rip_,kSourceBytes,false};
    if(query>=target_ && query<target_+kTargetExecutableBytes)
      return {target_,kTargetExecutableBytes,false};
    return {0,0,false};
  }
  std::optional<FEXCore::ExecutableFileSectionInfo>
  LookupExecutableFileSection(
       FEXCore::Core::InternalThreadState*,uint64_t) override {
    return std::nullopt;
  }
private:
  uint64_t rip_;
  uint64_t target_;
};
// Pinned upstream LinuxEmulation ThreadManager::CreateThread() creates
// a guarded 4MiB *host-only* call-ret stack and initializes the
// JIT's native X25 using CpuState.callret_sp. Bare FEX CreateThread()
// doesn't allocate it: CALL will access address -16 and SIGSEGV.
// Exactly source-mirror the pinned ThreadManager allocation and SP.
class OriginalFEXGuardedCallRetStack final {
  void* ptr_=MAP_FAILED;
  size_t total_=0;
public:
  OriginalFEXGuardedCallRetStack()=default;
  OriginalFEXGuardedCallRetStack(
      const OriginalFEXGuardedCallRetStack&)=delete;
  OriginalFEXGuardedCallRetStack& operator=(
      const OriginalFEXGuardedCallRetStack&)=delete;
  ~OriginalFEXGuardedCallRetStack(){(void)Release();}
  static constexpr size_t kGuard=4096;
  static constexpr size_t kCallRetBytes=
    FEXCore::Core::InternalThreadState::CALLRET_STACK_SIZE;
  bool Reserve() noexcept {
    if(ptr_!=MAP_FAILED || kCallRetBytes<32768 ||
       (kCallRetBytes%4096)!=0 ||
       kCallRetBytes>SIZE_MAX-2*kGuard)return false;
    total_=kCallRetBytes+2*kGuard;
    void* raw=::mmap(nullptr,total_,PROT_NONE,
        MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    if(raw==MAP_FAILED) {total_=0;return false;}
    ptr_=raw;
    if(::mprotect(Base(),kCallRetBytes,
                  PROT_READ|PROT_WRITE)!=0) {
      (void)Release();return false;
    }
    return InitialSP()!=0 && Contains(InitialSP()-16,16);
  }
  void* Base() const noexcept {
    return ptr_==MAP_FAILED?nullptr:
       static_cast<void*>(static_cast<uint8_t*>(ptr_)+kGuard);
  }
  uint64_t InitialSP() const noexcept {
    return Base()?reinterpret_cast<uintptr_t>(Base())+
                    kCallRetBytes/4:0;
  }
  bool Contains(uint64_t at,size_t n) const noexcept {
    if(!Base() || at<reinterpret_cast<uintptr_t>(Base()))
      return false;
    const auto offset=at-reinterpret_cast<uintptr_t>(Base());
    return n<=kCallRetBytes &&
           offset<=kCallRetBytes-n;
  }
  bool Release() noexcept {
    if(ptr_==MAP_FAILED)return true;
    if(::munmap(ptr_,total_)!=0)return false;
    ptr_=MAP_FAILED;
    total_=0;
    return true;
  }
};
static bool OriginalFileBackedBytesRestored(
    const m::GuestPreflight& source,
    const b::NativeChosenPIEGuestLayout& guest) {
  for(size_t module=0;module<3;++module) {
    const auto& snap=source.snapshots[module];
    const auto* meta=guest.Module(module);
    if(!meta || !snap.bytes() || !snap.readOnlySnapshot())return false;
    Elf64_Ehdr eh{};
    std::memcpy(&eh,snap.bytes(),sizeof(eh));
    for(uint16_t k=0;k<eh.e_phnum;++k) {
      Elf64_Phdr ph{};
      std::memcpy(&ph,snap.bytes()+eh.e_phoff+
         size_t(k)*sizeof(ph),sizeof(ph));
      if(ph.p_type!=PT_LOAD || !ph.p_filesz)continue;
      if(ph.p_vaddr>UINT64_MAX-meta->loadBias)return false;
      const uint64_t va=meta->loadBias+ph.p_vaddr;
      const auto* staged=guest.GuestReadOnlyBytes(
         module,va,static_cast<size_t>(ph.p_filesz));
      if(!staged || std::memcmp(staged,
          snap.bytes()+ph.p_offset,
          static_cast<size_t>(ph.p_filesz))!=0)return false;
    }
  }
  return true;
}
} // namespace c7r

int main(int argc,char** argv) {
  if(argc!=2 || !argv[1])return 2;
  if(::sysconf(_SC_PAGESIZE)!=4096)return 3;
  const int fd=::open(argv[1],O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
  if(fd<0)return 4;
  m::GuestPreflight original;
  std::string why;
  if(!m::Validate(fd,original,why)) {
    std::fprintf(stderr,"C3D7R_ORIGINAL_SOURCE_SHA256_DENIED %s\n",why.c_str());
    ::close(fd);return 5;
  }
  std::array<uint8_t,16> entropy{};
  for(size_t z=0;z<entropy.size();++z)entropy[z]=uint8_t(z+1);
  b::NativeChosenPIEGuestLayout staged;
  b::Witness ready;
  if(!staged.Stage(fd,entropy,ready) ||
     ready.phase!=b::Phase::Complete ||
     !ready.pinnedOriginalELFSHA256Verified ||
     !ready.originalBytesCopiedReadOnly ||
     !ready.linuxAuxvRebased ||
     ready.originalLdsoExecuted || ready.originalELFCodeExecuted ||
     staged.WindowsHeld()!=4) {
    ::close(fd);return 6;
  }
  ::close(fd);
  const auto* plan=staged.LaunchPlan();
  if(!plan || !staged.Module(1))return 7;
  const uint64_t originalRIP=plan->guestInterpreterEntry;
  const uint64_t originalRSP=plan->stack.guestRSP;
  e::EntryProof sourceProof;
  if(!e::VerifyOriginalGuestEntryAndTemporaryHostRX(
        staged,original,1,sourceProof) ||
     !sourceProof.entryIsInsideOriginalFileBackedRXSegment ||
     !sourceProof.instructionBytesMatchOriginalSource ||
     !sourceProof.nativeRORestored ||
     sourceProof.guestRIP!=originalRIP)return 8;
  g::PermissionPlan sourceRights;
  g::Reject pageReject;
  if(!g::BuildVerifiedOriginalPermissionPlan(
       original,staged,sourceRights,pageReject))return 9;
  kernix::g2e::c3d7n::CallProof call;
  kernix::g2e::c3d7n::Reject callReject;
  if(!kernix::g2e::c3d7n::VerifyAuthenticLdsoSecondCallTarget(
       original,staged,sourceRights,call,callReject) ||
     call.originalEntry!=originalRIP ||
     call.originalGuestStartupRSP!=originalRSP ||
     call.originalReturnRIP!=originalRIP+c7r::kOriginalTwoOpcodesBytes) {
    std::fprintf(stderr,
      "C3D7R_ORIGINAL_SOURCE_CALL_TARGET_REJECT reason=%u\n",
      unsigned(callReject));
    return 10;
  }
  const uint64_t originalTarget=call.originalTarget;
  if(originalTarget==originalRIP ||
     call.originalTargetBytes[0]==c7r::kInjectedHLT)
    return 11;
  const auto* sourceEntry=staged.GuestReadOnlyBytes(
      1,originalRIP,c7r::kSourceBytes);
  if(!sourceEntry)return 9;
  std::array<uint8_t,c7r::kSourceBytes> originalSourceBytes{};
  std::memcpy(originalSourceBytes.data(),sourceEntry,
              originalSourceBytes.size());
  // Genuine entry bytes 48 89 e7 (mov rsp,rdi) and E8 rel32
  // (CALL) remain unchanged. Only the source-attested CALL target
  // receives a temporary 1-byte HLT in guest staging.
  if(std::memcmp(originalSourceBytes.data(),
                 call.originalEntryBytes.data(),16)!=0 ||
     (originalRIP&4095)>4096-c7r::kSourceBytes ||
     (originalTarget&4095)>4096-c7r::kSourceBytes)
    return 12;
  g::ApplyWitness nativePages;
  if(!g::ApplyOwnedOriginalPTLoadPagePermissions(
       staged,original,nativePages) ||
     !nativePages.originalPinnedSourceValidated ||
     !nativePages.nativeNoWritableExecutablePage ||
     !nativePages.nativeNonPTLoadHolesDenied ||
     !nativePages.nativeStackGuardDenied ||
     nativePages.originalModulesProtected!=3)
    return 12;
  if(c7r::RightsAt(originalRIP)!="r-xp" ||
     c7r::RightsAt(originalTarget)!="r-xp" ||
     c7r::RightsAt(originalRSP)!="rw-p" ||
     c7r::RightsAt(originalRSP-8)!="rw-p")
    return 13;

  // Original source-attested 20-byte target prefix, through sixth LEA
  // and first 0x66 prefix of the seventh original SIMD MOVQ.
  constexpr std::array<uint8_t,20> kOriginal20{
      0xf3,0x0f,0x1e,0xfa,0x55,0x48,0x8d,0x0d,0x14,0xfe,0xfd,0xff,
      0x48,0x8d,0x05,0xe5,0x90,0x01,0x00,0x66};
  const auto* source20=staged.GuestReadOnlyBytes(
      1,originalTarget,kOriginal20.size());
  if(!source20 ||
     std::memcmp(source20,kOriginal20.data(),kOriginal20.size())!=0) {
    std::fprintf(stderr,
      "C3D7R_SOURCE_TARGET_NOT_WHITELISTED first5=%02x%02x%02x%02x%02x\n",
      call.originalTargetBytes[0],call.originalTargetBytes[1],
      call.originalTargetBytes[2],call.originalTargetBytes[3],
      call.originalTargetBytes[4]);
    return 32;
  }
  const uint64_t targetPage=originalTarget&~uint64_t(4095);
  auto* targetByte=reinterpret_cast<uint8_t*>(
      static_cast<uintptr_t>(originalTarget));
  if(::mprotect(reinterpret_cast<void*>(
       static_cast<uintptr_t>(targetPage)),4096,PROT_READ|PROT_WRITE)!=0)
    return 14;
  targetByte[c7r::kNextInstructionOffset]=c7r::kInjectedHLT;
  if(::mprotect(reinterpret_cast<void*>(
       static_cast<uintptr_t>(targetPage)),4096,PROT_READ|PROT_EXEC)!=0)
    return 15;
  if(c7r::RightsAt(originalRIP)!="r-xp" ||
     c7r::RightsAt(originalTarget)!="r-xp" ||
     targetByte[c7r::kNextInstructionOffset]!=c7r::kInjectedHLT ||
      std::memcmp(targetByte,kOriginal20.data(),c7r::kNextInstructionOffset)!=0 ||
     std::memcmp(sourceEntry,call.originalEntryBytes.data(),c7r::kOriginalTwoOpcodesBytes)!=0)
    return 16;

  // Use source-backed authentic LEA displacement from instruction bytes
  // (target + 8) and actual rebased guest RIP. No synthetic address.
  std::int32_t leaDisp=0;
  std::memcpy(&leaDisp,call.originalTargetBytes.data()+8,sizeof(leaDisp));
  const uint64_t leaNextRIP=originalTarget+c7r::kOriginalFifthEndOffset;
  const uint64_t expectedLEAResult=
      leaNextRIP+static_cast<uint64_t>(static_cast<int64_t>(leaDisp));
  if(expectedLEAResult!=staged.Module(1)->loadBias)return 37;
  // Sixth authentic LEA RAX signed displacement at original +15.
  std::int32_t sixthDisp=0;
  std::memcpy(&sixthDisp,kOriginal20.data()+15,sizeof(sixthDisp));
  const uint64_t expectedRAX=
      originalTarget+c7r::kNextInstructionOffset+
      static_cast<uint64_t>(static_cast<int64_t>(sixthDisp));
  if(expectedRAX!=staged.Module(1)->loadBias+uint64_t{0x392d8})
    return 38;
  // Snapshot original guest stack slots before CALL (-8) and PUSH (-16).
  if(originalRSP<16 || c7r::RightsAt(originalRSP-16)!="rw-p" ||
     c7r::RightsAt(originalRSP-8)!="rw-p")return 33;
  std::array<uint8_t,16> originalGuestStackBytes{};
  std::memcpy(originalGuestStackBytes.data(),
    reinterpret_cast<const void*>(static_cast<uintptr_t>(originalRSP-16)),
    originalGuestStackBytes.size());
  FEXCore::Config::Initialize();
  FEXCore::Config::Load();
  FEXCore::Config::ReloadMetaLayer();
  FEXCore::Config::Set(FEXCore::Config::CONFIG_IS64BIT_MODE,"1");
  FEXCore::Config::Set(FEXCore::Config::CONFIG_MAXINST,"1");
  FEXCore::HostFeatures host{};
  host.DCacheLineLog2=4;
  host.ProcessFeatures.HostType=FEXCore::HostFeatures::HostTypeEnum::Linux;
  host.ProcessFeatures.Is64BitMode=1;
  host.ProcessPID=static_cast<uint32_t>(::getpid());
  host.CPUMIDRs.push_back(0);
  c7r::OriginalFEXGuardedCallRetStack callret;
  if(!callret.Reserve())return 17;
  auto ctx=FEXCore::Context::Context::CreateNewContext(host);
  if(!ctx)return 17;
  FEXCore::SignalDelegator signals{};
  c7r::DenyAllGuestSyscalls deny{originalRIP,originalTarget};
  ctx->SetSignalDelegator(&signals);
  ctx->SetSyscallHandler(&deny);
  ctx->EnableExitOnHLT();
  if(!ctx->InitCore())return 18;
  auto* thread=ctx->CreateThread();
  if(!thread || !thread->CurrentFrame)return 19;
  FEXCore::Core::CPUState::gdt_segment gdt[32]{};
  auto& cpu=thread->CurrentFrame->State;
  thread->CallRetStackBase=callret.Base();
  cpu.callret_sp=callret.InitialSP();
  if(!thread->CallRetStackBase ||
     !callret.Contains(cpu.callret_sp-16,16) ||
     cpu.callret_sp==0)return 19;
  cpu.segment_arrays[
      FEXCore::Core::CPUState::SEGMENT_ARRAY_INDEX_GDT]=gdt;
  cpu.segment_arrays[
      FEXCore::Core::CPUState::SEGMENT_ARRAY_INDEX_LDT]=gdt;
  cpu.cs_idx=FEXCore::Core::CPUState::DEFAULT_USER_CS<<3;
  auto* cs=FEXCore::Core::CPUState::GetSegmentFromIndex(cpu,cpu.cs_idx);
  FEXCore::Core::CPUState::SetGDTBase(cs,0);
  FEXCore::Core::CPUState::SetGDTLimit(cs,0xFFFFF);
  cs->L=1;cs->D=0;cpu.cs_cached=0;
  constexpr uint64_t sentinel=0x4b45524e49584d31ULL;
  constexpr uint64_t rbpWitness=0x4b45524e49585042ULL;
  constexpr uint64_t rcxWitness=0x4b45524e49584351ULL;
  constexpr uint64_t raxWitness=0x4b45524e49584158ULL;
  cpu.rip=originalRIP;
  cpu.gregs[FEXCore::X86State::REG_RSP]=originalRSP;
  cpu.gregs[FEXCore::X86State::REG_RDI]=sentinel;
  cpu.gregs[FEXCore::X86State::REG_RBP]=rbpWitness;
  cpu.gregs[FEXCore::X86State::REG_RCX]=rcxWitness;
  cpu.gregs[FEXCore::X86State::REG_RAX]=raxWitness;
  cpu.fs_cached=0;cpu.gs_cached=0;
  if(cpu.rip!=originalRIP ||
     cpu.gregs[FEXCore::X86State::REG_RSP]!=originalRSP ||
     cpu.gregs[FEXCore::X86State::REG_RDI]!=sentinel)
    return 20;
  std::fputs("KERNIX_C3D7R_BEGIN_SIX_REAL_ORIGINAL_LDSO_MOV_CALL_ENDBR64_PUSH_RBP_LEA_RCX_LEA_RAX_FEX_EXECUTETHREAD\n",stderr);
  std::fflush(stderr);
  ctx->ExecuteThread(thread);
  const uint64_t postRIP=cpu.rip;
  uint64_t pushedReturnRIP=0;
  uint64_t pushedRBP=0;
  if(c7r::RightsAt(originalRSP-8)!="rw-p")return 21;
  std::memcpy(&pushedReturnRIP,
     reinterpret_cast<const void*>(static_cast<uintptr_t>(originalRSP-8)),8);
  if(c7r::RightsAt(originalRSP-16)!="rw-p")return 34;
  std::memcpy(&pushedRBP,
     reinterpret_cast<const void*>(static_cast<uintptr_t>(originalRSP-16)),8);
  if(cpu.gregs[FEXCore::X86State::REG_RDI]!=originalRSP ||
     cpu.gregs[FEXCore::X86State::REG_RDI]==sentinel ||
     cpu.gregs[FEXCore::X86State::REG_RSP]!=originalRSP-16 ||
     cpu.gregs[FEXCore::X86State::REG_RBP]!=rbpWitness ||
     cpu.gregs[FEXCore::X86State::REG_RCX]!=expectedLEAResult ||
     cpu.gregs[FEXCore::X86State::REG_RCX]==rcxWitness ||
     cpu.gregs[FEXCore::X86State::REG_RAX]!=expectedRAX ||
     cpu.gregs[FEXCore::X86State::REG_RAX]==raxWitness ||
     pushedRBP!=rbpWitness ||
     pushedReturnRIP!=call.originalReturnRIP ||
     (postRIP!=originalTarget+c7r::kNextInstructionOffset &&
      postRIP!=originalTarget+c7r::kNextInstructionOffset+1)) {
    std::fprintf(stderr,
      "C3D7R_RIPREL_DIAG post=%llx stop=%llx rax=%llx expectedRAX=%llx rcx=%llx expectedRCX=%llx\n",
      static_cast<unsigned long long>(postRIP),
      static_cast<unsigned long long>(originalTarget+c7r::kNextInstructionOffset),
      static_cast<unsigned long long>(cpu.gregs[FEXCore::X86State::REG_RAX]),
      static_cast<unsigned long long>(expectedRAX),
      static_cast<unsigned long long>(cpu.gregs[FEXCore::X86State::REG_RCX]),
      static_cast<unsigned long long>(expectedLEAResult));
    std::fprintf(stderr,
      "C3D7R_POST_PUSH_STATE_REJECT src=%llx dst=%llx post=%llx rsp=%llx rdi=%llx ret=%llx expected=%llx\n",
      static_cast<unsigned long long>(originalRIP),
      static_cast<unsigned long long>(originalTarget),
      static_cast<unsigned long long>(postRIP),
      static_cast<unsigned long long>(
        cpu.gregs[FEXCore::X86State::REG_RSP]),
      static_cast<unsigned long long>(
        cpu.gregs[FEXCore::X86State::REG_RDI]),
      static_cast<unsigned long long>(pushedReturnRIP),
      static_cast<unsigned long long>(call.originalReturnRIP));
    return 21;
  }
  // Restore the sole target trap byte after FEX has exited.
  if(::mprotect(reinterpret_cast<void*>(
       static_cast<uintptr_t>(targetPage)),4096,PROT_READ|PROT_WRITE)!=0)
    return 22;
  targetByte[c7r::kNextInstructionOffset]=kOriginal20[c7r::kNextInstructionOffset];
  if(::mprotect(reinterpret_cast<void*>(
       static_cast<uintptr_t>(targetPage)),4096,PROT_READ|PROT_EXEC)!=0)
    return 23;
  if(c7r::RightsAt(originalRIP)!="r-xp" ||
     c7r::RightsAt(originalTarget)!="r-xp" ||
     std::memcmp(sourceEntry,call.originalEntryBytes.data(),16)!=0 ||
     std::memcmp(targetByte,kOriginal20.data(),kOriginal20.size())!=0 ||
     !c7r::OriginalFileBackedBytesRestored(original,staged) ||
     staged.WindowsHeld()!=4)return 24;
  // Restore stack byte-for-byte in the original owned guest stack VMA.
  if(c7r::RightsAt(originalRSP-16)!="rw-p")return 35;
  std::memcpy(reinterpret_cast<void*>(static_cast<uintptr_t>(originalRSP-16)),
      originalGuestStackBytes.data(),originalGuestStackBytes.size());
  if(std::memcmp(reinterpret_cast<const void*>(
      static_cast<uintptr_t>(originalRSP-16)),
      originalGuestStackBytes.data(),originalGuestStackBytes.size())!=0)return 36;
  // Destroy FEX context/thread while its call-ret map remains
  // alive; then release that host-only stack and the original VMAs.
  ctx.reset();
  if(!callret.Release())return 25;
  if(!staged.Release() || staged.WindowsHeld()!=0)return 26;
  std::puts(
    "KERNIX_G2EC3D7R_SOURCE_PINNED_FEX_SIX_REAL_ORIGINAL_LDSO_MOV_CALL_ENDBR64_PUSH_RBP_LEA_RCX_LEA_RAX_LINUX_ARM64_PASS"
    " original_three_sha256_locked=1"
    " original_entry_mov_rsp_rdi_and_rel32_call_executed=1"
    " genuine_source_call_target_endbr64_executed=1"
    " four_byte_endbr64_original_bytes_unchanged=1"
    " original_guest_startup_rsp_moved_to_rdi=1"
    " actual_call_rsp_decremented_by_eight=1"
    " call_return_rip_pushed_to_guest_stack=1"
    " genuine_fex_call_target_rip_after_endbr64_reached=1"
    " original_fourth_push_rbp_executed=1"
    " original_push_rbp_guest_stack_write_verified=1"
    " original_fifth_lea_rcx_executed=1"
    " authentic_lea_rcx_rebased_ldso_base_verified=1"
    " original_sixth_lea_rax_executed=1"
    " authentic_lea_rax_rebased_ldso_data_address_verified=1"
    " original_seventh_simd_movq_replaced_by_bounded_hlt=1"
    " original_seventh_simd_movq_executed=0"
    " guest_stack_original_16_bytes_restored=1"
    " unmodified_original_six_instructions_executed=1"
    " all_three_original_file_backed_ptload_bytes_restored=1"
    " source_elf_snapshots_unchanged=1"
    " native_ptload_WX_separated=1"
    " guarded_FEX_callret_stack_used_and_released=1"
    " guest_syscalls_forwarded=0"
    " original_guest_windows_released=1"
    " complete_dynamic_linker_startup=0"
    " relocations_ifunc_tls_completed=0"
    " android_device=0 wine=0");
  return 0;
}
