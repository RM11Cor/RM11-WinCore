// SPDX-License-Identifier: MIT
// C3-D8C0 opt-in Android/Bionic ARM64 physical-device probe.
// Replay first FOUR genuine x86_64 original ld-linux instructions
// MOV RDI,RSP; CALL rel32; ENDBR64; PUSH RBP through pinned real FEX,
// at original source SHA-locked PIE/ldso guest RIP and guarded stack.
// Strict app-private owner/flag input. No arbitrary EXE or guest syscall.
// Temporary test HLT ONLY at fifth original instruction in owned
// anonymous staged RX VMA, restore source and original guest 16-byte
// CALL/PUSH stack, native W^X, guarded FEX host callret and all VMAs.
// Not dynamic ld-linux startup, glibc relocations, Wine, games or FPS.
#include <FEXCore/Config/Config.h>
#include <FEXCore/Core/Context.h>
#include <FEXCore/Core/HostFeatures.h>
#include <FEXCore/Core/CoreState.h>
#include <FEXCore/Core/X86Enums.h>
#include <FEXCore/Core/SignalDelegator.h>
#include <FEXCore/Debug/InternalThreadState.h>
#include <FEXCore/HLE/SyscallHandler.h>
#include <FEXCore/Utils/AllocatorHooks.h>
#include <FEXCore/fextl/memory.h>
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
#if !defined(__ANDROID__) || !defined(__aarch64__)
#error C3-D8C0 is only for an opt-in real Android Bionic AArch64 child
#endif
namespace m=kernix::g2e;
namespace b=kernix::g2e::c3d7b;
namespace e=kernix::g2e::c3d7e;
namespace g=kernix::g2e::c3d7g;
namespace c7p {
static void Stage(const char* name) noexcept {
  std::fprintf(stderr,"KERNIX_C3D8C0_STAGE=%s\n",name);
  std::fflush(stderr);
}
static constexpr const char kFlag[]=
  "--kernix-c3d8c0-source-original-ldso-four-instructions-v1";
static bool ValidateAppPrivateOriginalRoot(const char* raw) {
  if(!raw || raw[0]!='/' || std::strlen(raw)>2048)return false;
  const std::string p(raw);
  if(p.find("..")!=std::string::npos ||
     p.find("//")!=std::string::npos ||
     !p.ends_with("/c3d8c0-original-guest"))return false;
  return p.starts_with(
       "/data/user/0/org.kernix.originalfexldso/files/") ||
       p.starts_with(
       "/data/data/org.kernix.originalfexldso/files/");
}
static constexpr size_t kSourceBytes=16;
static constexpr size_t kOriginalTwoOpcodesBytes=8;
static constexpr size_t kOriginalENDBR64Bytes=4;
static constexpr size_t kNextInstructionOffset=kOriginalENDBR64Bytes+1;
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
    std::fputs("KERNIX_C3D8C0_ANDROID_UNEXPECTED_GUEST_SYSCALL_DENIED\n",stderr);
    std::fflush(stderr);
    _exit(94);
  }
  FEXCore::HLE::ExecutableRangeInfo QueryGuestExecutableRange(
       FEXCore::Core::InternalThreadState*,uint64_t query) override {
    if(query>=rip_ && query<rip_+kSourceBytes)
      return {rip_,kSourceBytes,false};
    if(query>=target_ && query<target_+kSourceBytes)
      return {target_,kSourceBytes,false};
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
} // namespace c7p

int main(int argc,char** argv) {
  if(argc!=3 || !argv[1] || !argv[2] ||
     std::strcmp(argv[1],c7p::kFlag)!=0 ||
     !c7p::ValidateAppPrivateOriginalRoot(argv[2]))return 2;
  if(::sysconf(_SC_PAGESIZE)!=4096)return 3;
  const int fd=::open(argv[2],O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
  if(fd<0)return 4;
  m::GuestPreflight original;
  std::string why;
  if(!m::Validate(fd,original,why)) {
    std::fprintf(stderr,"C3D7P_ORIGINAL_SOURCE_SHA256_DENIED %s\n",why.c_str());
    ::close(fd);return 5;
  }
  c7p::Stage("ORIGINAL_ELF_SHA256_VALIDATED");
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
  c7p::Stage("ORIGINAL_GUEST_MEMORY_STAGING_VERIFIED");
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
     call.originalReturnRIP!=originalRIP+c7p::kOriginalTwoOpcodesBytes) {
    std::fprintf(stderr,
      "C3D7P_ORIGINAL_SOURCE_CALL_TARGET_REJECT reason=%u\n",
      unsigned(callReject));
    return 10;
  }
  c7p::Stage("ORIGINAL_LDSO_SOURCE_CALL_PROVED");
  const uint64_t originalTarget=call.originalTarget;
  if(originalTarget==originalRIP ||
     call.originalTargetBytes[0]==c7p::kInjectedHLT)
    return 11;
  const auto* sourceEntry=staged.GuestReadOnlyBytes(
      1,originalRIP,c7p::kSourceBytes);
  if(!sourceEntry)return 9;
  std::array<uint8_t,c7p::kSourceBytes> originalSourceBytes{};
  std::memcpy(originalSourceBytes.data(),sourceEntry,
              originalSourceBytes.size());
  // Genuine entry bytes 48 89 e7 (mov rsp,rdi) and E8 rel32
  // (CALL) remain unchanged. Only the source-attested CALL target
  // receives a temporary 1-byte HLT in guest staging.
  if(std::memcmp(originalSourceBytes.data(),
                 call.originalEntryBytes.data(),16)!=0 ||
     (originalRIP&4095)>4096-c7p::kSourceBytes ||
     (originalTarget&4095)>4096-c7p::kSourceBytes)
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
  if(c7p::RightsAt(originalRIP)!="r-xp" ||
     c7p::RightsAt(originalTarget)!="r-xp" ||
     c7p::RightsAt(originalRSP)!="rw-p" ||
     c7p::RightsAt(originalRSP-8)!="rw-p")
    return 13;

  c7p::Stage("NATIVE_SOURCE_PTLOAD_WX_AND_GUEST_STACK_GUARD_PASS");
  // Exact source-audited target: ENDBR64 + PUSH RBP + next LEA.
  constexpr std::array<uint8_t,12> kOriginal12{
      0xf3,0x0f,0x1e,0xfa,0x55,0x48,0x8d,0x0d,0x14,0xfe,0xfd,0xff};
  if(std::memcmp(call.originalTargetBytes.data(),
                 kOriginal12.data(),kOriginal12.size())!=0) {
    std::fprintf(stderr,
      "C3D7P_SOURCE_TARGET_NOT_WHITELISTED first5=%02x%02x%02x%02x%02x\n",
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
  targetByte[c7p::kNextInstructionOffset]=c7p::kInjectedHLT;
  if(::mprotect(reinterpret_cast<void*>(
       static_cast<uintptr_t>(targetPage)),4096,PROT_READ|PROT_EXEC)!=0)
    return 15;
  if(c7p::RightsAt(originalRIP)!="r-xp" ||
     c7p::RightsAt(originalTarget)!="r-xp" ||
     targetByte[c7p::kNextInstructionOffset]!=c7p::kInjectedHLT ||
      std::memcmp(targetByte,call.originalTargetBytes.data(),c7p::kNextInstructionOffset)!=0 ||
     std::memcmp(sourceEntry,call.originalEntryBytes.data(),c7p::kOriginalTwoOpcodesBytes)!=0)
    return 16;

  // Snapshot original guest stack slots before CALL (-8) and PUSH (-16).
  if(originalRSP<16 || c7p::RightsAt(originalRSP-16)!="rw-p" ||
     c7p::RightsAt(originalRSP-8)!="rw-p")return 33;
  std::array<uint8_t,16> originalGuestStackBytes{};
  std::memcpy(originalGuestStackBytes.data(),
    reinterpret_cast<const void*>(static_cast<uintptr_t>(originalRSP-16)),
    originalGuestStackBytes.size());
  c7p::Stage("ORIGINAL_X86_STACK_SNAPSHOT_COMPLETE");
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
  c7p::OriginalFEXGuardedCallRetStack callret;
  if(!callret.Reserve())return 17;
  c7p::Stage("GUARDED_HOST_CALLRET_STACK_READY");
  auto ctx=FEXCore::Context::Context::CreateNewContext(host);
  if(!ctx)return 17;
  FEXCore::SignalDelegator signals{};
  c7p::DenyAllGuestSyscalls deny{originalRIP,originalTarget};
  ctx->SetSignalDelegator(&signals);
  ctx->SetSyscallHandler(&deny);
  ctx->EnableExitOnHLT();
  if(!ctx->InitCore())return 18;
  c7p::Stage("REAL_FEX_CONTEXT_INITCORE_PASS");
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
  cpu.rip=originalRIP;
  cpu.gregs[FEXCore::X86State::REG_RSP]=originalRSP;
  cpu.gregs[FEXCore::X86State::REG_RDI]=sentinel;
  cpu.gregs[FEXCore::X86State::REG_RBP]=rbpWitness;
  cpu.fs_cached=0;cpu.gs_cached=0;
  if(cpu.rip!=originalRIP ||
     cpu.gregs[FEXCore::X86State::REG_RSP]!=originalRSP ||
     cpu.gregs[FEXCore::X86State::REG_RDI]!=sentinel)
    return 20;
  c7p::Stage("FEX_GUEST_THREAD_AND_CPUSTATE_READY");
  std::fputs("KERNIX_C3D8C0_ANDROID_BEGIN_FOUR_SOURCE_ORIGINAL_LDSO_INSTRUCTIONS_FEX_EXECUTETHREAD\n",stderr);
  std::fflush(stderr);
  ctx->ExecuteThread(thread);
  c7p::Stage("FEX_EXECUTETHREAD_RETURNED");
  const uint64_t postRIP=cpu.rip;
  uint64_t pushedReturnRIP=0;
  uint64_t pushedRBP=0;
  if(c7p::RightsAt(originalRSP-8)!="rw-p")return 21;
  std::memcpy(&pushedReturnRIP,
     reinterpret_cast<const void*>(static_cast<uintptr_t>(originalRSP-8)),8);
  if(c7p::RightsAt(originalRSP-16)!="rw-p")return 34;
  std::memcpy(&pushedRBP,
     reinterpret_cast<const void*>(static_cast<uintptr_t>(originalRSP-16)),8);
  if(cpu.gregs[FEXCore::X86State::REG_RDI]!=originalRSP ||
     cpu.gregs[FEXCore::X86State::REG_RDI]==sentinel ||
     cpu.gregs[FEXCore::X86State::REG_RSP]!=originalRSP-16 ||
     cpu.gregs[FEXCore::X86State::REG_RBP]!=rbpWitness ||
     pushedRBP!=rbpWitness ||
     pushedReturnRIP!=call.originalReturnRIP ||
     (postRIP!=originalTarget+c7p::kNextInstructionOffset &&
      postRIP!=originalTarget+c7p::kNextInstructionOffset+1)) {
    std::fprintf(stderr,
      "C3D7P_POST_PUSH_STATE_REJECT src=%llx dst=%llx post=%llx rsp=%llx rdi=%llx ret=%llx expected=%llx\n",
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
  c7p::Stage("ORIGINAL_GUEST_CALL_PUSH_RBP_AND_RETURN_RIP_PROVED");
  // Restore the sole target trap byte after FEX has exited.
  if(::mprotect(reinterpret_cast<void*>(
       static_cast<uintptr_t>(targetPage)),4096,PROT_READ|PROT_WRITE)!=0)
    return 22;
  targetByte[c7p::kNextInstructionOffset]=call.originalTargetBytes[c7p::kNextInstructionOffset];
  if(::mprotect(reinterpret_cast<void*>(
       static_cast<uintptr_t>(targetPage)),4096,PROT_READ|PROT_EXEC)!=0)
    return 23;
  if(c7p::RightsAt(originalRIP)!="r-xp" ||
     c7p::RightsAt(originalTarget)!="r-xp" ||
     std::memcmp(sourceEntry,call.originalEntryBytes.data(),16)!=0 ||
     std::memcmp(targetByte,call.originalTargetBytes.data(),16)!=0 ||
     !c7p::OriginalFileBackedBytesRestored(original,staged) ||
     staged.WindowsHeld()!=4)return 24;
  c7p::Stage("ORIGINAL_LDSO_SOURCE_BYTES_RESTORED");
  // Restore stack byte-for-byte in the original owned guest stack VMA.
  if(c7p::RightsAt(originalRSP-16)!="rw-p")return 35;
  std::memcpy(reinterpret_cast<void*>(static_cast<uintptr_t>(originalRSP-16)),
      originalGuestStackBytes.data(),originalGuestStackBytes.size());
  if(std::memcmp(reinterpret_cast<const void*>(
      static_cast<uintptr_t>(originalRSP-16)),
      originalGuestStackBytes.data(),originalGuestStackBytes.size())!=0)return 36;
  c7p::Stage("ORIGINAL_GUEST_STACK_16_BYTES_RESTORED");
  // Destroy FEX context/thread while its call-ret map remains
  // alive; then release that host-only stack and the original VMAs.
  ctx.reset();
  if(!callret.Release())return 25;
  if(!staged.Release() || staged.WindowsHeld()!=0)return 26;
  c7p::Stage("FEX_CONTEXT_GUEST_MEMORY_AND_HOST_STACK_RELEASED");
  std::puts("KERNIX_C3D8C0_ANDROID_DEVICE_SOURCE_ORIGINAL_LDSO_FOUR_FEX_INSTRUCTIONS_PASS");
  std::puts("ORIGINAL_THREE_X86_LINUX_ELF_SHA256_VERIFIED=1");
  std::puts("REAL_ANDROID_BIONIC_ARM64_FEX_CONTEXT_CREATED=1");
  std::puts("ORIGINAL_LDSO_MOV_RDI_RSP_EXECUTED=1");
  std::puts("ORIGINAL_LDSO_REL32_CALL_EXECUTED=1");
  std::puts("ORIGINAL_LDSO_ENDBR64_EXECUTED=1");
  std::puts("ORIGINAL_LDSO_PUSH_RBP_EXECUTED=1");
  std::puts("ORIGINAL_GUEST_CALL_RETURN_RIP_AND_RBP_STACK_VERIFIED=1");
  std::puts("SOURCE_FIFTH_LEA_REPLACED_BY_BOUNDED_HLT=1");
  std::puts("SOURCE_FIFTH_LEA_EXECUTED=0");
  std::puts("SOURCE_GUEST_AND_HOST_STACK_BYTES_RESTORED=1");
  std::puts("ORIGINAL_PTLOAD_RX_RW_WX_ENFORCED=1");
  std::puts("ALL_ORIGINAL_GUEST_WINDOWS_RELEASED=1");
  std::puts("GUEST_LINUX_SYSCALLS_FORWARDED=0");
  std::puts("COMPLETE_LDSO_DYNAMIC_LINKER_STARTUP=0");
  std::puts("WINE_OR_WINDOWS_PE_EXECUTED=0");
  return 0;
}
