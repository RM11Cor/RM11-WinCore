// SPDX-License-Identifier: MIT
// C3-D8C2 bounded real FEX original Linux ld-linux x86 18-instruction
// guest execution on Android/Bionic ARM64. Source locked first ten
// guest instructions plus original five GPR PUSHes, SUB RSP 0x88,
// MOV original RDI to stack local and aligned SSE MOVAPS 16-byte store.
// Verify complete 192-byte guest stack, original bytes, W^X and
// callret native guard and safe HLT before 19th original RDTSC.
// A green build is not device proof. No full ELF startup or games.
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
#error C3-D8C2 is an isolated Android Bionic AArch64 opt-in child only
#endif
namespace m=kernix::g2e;
namespace b=kernix::g2e::c3d7b;
namespace e=kernix::g2e::c3d7e;
namespace g=kernix::g2e::c3d7g;
namespace c8c2 {
static constexpr const char kFlag[]=
  "--kernix-c3d8c2-source-original-ldso-eighteen-instructions-v1";
static void Stage(const char* name) noexcept {
  std::fprintf(stderr,"KERNIX_C3D8C2_STAGE=%s\n",name);
  std::fflush(stderr);
}
static bool ValidateAppPrivateOriginalRoot(const char* raw) {
  if(!raw || raw[0]!='/' || std::strlen(raw)>2048)return false;
  const std::string p(raw);
  if(p.find("..")!=std::string::npos || p.find("//")!=std::string::npos ||
     !p.ends_with("/c3d8c2-original-guest"))return false;
  return p.starts_with("/data/user/0/org.kernix.originalfexldso18/files/") ||
         p.starts_with("/data/data/org.kernix.originalfexldso18/files/");
}
static constexpr size_t kSourceBytes=16;
static constexpr size_t kTargetExecutableBytes=128; // authentic local-area write sequence ends at +62, RDTSC HLT at +63
static constexpr size_t kOriginalTwoOpcodesBytes=8;
static constexpr size_t kOriginalENDBR64Bytes=4;
static constexpr size_t kOriginalFifthLEABytes=7;
static constexpr size_t kOriginalFifthEndOffset=kOriginalENDBR64Bytes+1+kOriginalFifthLEABytes;
static constexpr size_t kOriginalSixthLEABytes=7;
static constexpr size_t kOriginalSixthEndOffset=kOriginalFifthEndOffset+kOriginalSixthLEABytes;
static constexpr size_t kOriginalSeventhSIMDBytes=5;
static constexpr size_t kOriginalSeventhEndOffset=kOriginalSixthEndOffset+kOriginalSeventhSIMDBytes;
static constexpr size_t kOriginalEighthSIMDBytes=5;
static constexpr size_t kOriginalEighthEndOffset=kOriginalSeventhEndOffset+kOriginalEighthSIMDBytes;
static constexpr size_t kOriginalNinthSIMDBytes=4;
static constexpr size_t kOriginalNinthEndOffset=kOriginalEighthEndOffset+kOriginalNinthSIMDBytes;
static constexpr size_t kOriginalTenthMOVBytes=3;
static constexpr size_t kOriginalTenthEndOffset=kOriginalNinthEndOffset+kOriginalTenthMOVBytes;
static constexpr size_t kOriginalFivePushBytes=9; // 41 57 41 56 41 55 41 54 53
static constexpr size_t kOriginalFifteenthEndOffset=kOriginalTenthEndOffset+kOriginalFivePushBytes;
static constexpr size_t kOriginalSixteenthSUBBytes=7;
static constexpr size_t kOriginalSeventeenthMOVBytes=7;
static constexpr size_t kOriginalEighteenthMOVAPSBytes=4;
static constexpr size_t kNextInstructionOffset=kOriginalFifteenthEndOffset+
  kOriginalSixteenthSUBBytes+kOriginalSeventeenthMOVBytes+kOriginalEighteenthMOVAPSBytes;
static constexpr size_t kGuestSavedSlotCount=7; // CALL, RBP, five GPR PUSHes
static constexpr size_t kLocalAreaBytes=0x88;
static constexpr size_t kGuestStackBytes=kGuestSavedSlotCount*sizeof(uint64_t)+kLocalAreaBytes;
static_assert(kGuestStackBytes==192 && kNextInstructionOffset==63);
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
    std::fputs("KERNIX_C3D8C2_UNEXPECTED_GUEST_SYSCALL_DENIED\n",stderr);
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
} // namespace c8c2

int main(int argc,char** argv) {
  if(argc!=3 || !argv[1] || !argv[2] ||
     std::strcmp(argv[1],c8c2::kFlag)!=0 ||
     !c8c2::ValidateAppPrivateOriginalRoot(argv[2]))return 2;
  if(::sysconf(_SC_PAGESIZE)!=4096)return 3;
  const int fd=::open(argv[2],O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
  if(fd<0)return 4;
  m::GuestPreflight original;
  std::string why;
  if(!m::Validate(fd,original,why)) {
    std::fprintf(stderr,"C3D8C2_ORIGINAL_SOURCE_SHA256_DENIED %s\n",why.c_str());
    ::close(fd);return 5;
  }
  c8c2::Stage("ORIGINAL_ELF_SHA256_VERIFIED");
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
  c8c2::Stage("ORIGINAL_GUEST_OWNED_VM_STAGING_READY");
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
     call.originalReturnRIP!=originalRIP+c8c2::kOriginalTwoOpcodesBytes) {
    std::fprintf(stderr,
      "C3D8C2_ORIGINAL_SOURCE_CALL_TARGET_REJECT reason=%u\n",
      unsigned(callReject));
    return 10;
  }
  c8c2::Stage("ORIGINAL_LDSO_CALL_AND_ENTRY_VERIFIED");
  const uint64_t originalTarget=call.originalTarget;
  if(originalTarget==originalRIP ||
     call.originalTargetBytes[0]==c8c2::kInjectedHLT)
    return 11;
  const auto* sourceEntry=staged.GuestReadOnlyBytes(
      1,originalRIP,c8c2::kSourceBytes);
  if(!sourceEntry)return 9;
  std::array<uint8_t,c8c2::kSourceBytes> originalSourceBytes{};
  std::memcpy(originalSourceBytes.data(),sourceEntry,
              originalSourceBytes.size());
  // Genuine entry bytes 48 89 e7 (mov rsp,rdi) and E8 rel32
  // (CALL) remain unchanged. Only the source-attested CALL target
  // receives a temporary 1-byte HLT in guest staging.
  if(std::memcmp(originalSourceBytes.data(),
                 call.originalEntryBytes.data(),16)!=0 ||
     (originalRIP&4095)>4096-c8c2::kSourceBytes ||
     (originalTarget&4095)>4096-c8c2::kSourceBytes)
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
  if(c8c2::RightsAt(originalRIP)!="r-xp" ||
     c8c2::RightsAt(originalTarget)!="r-xp" ||
     c8c2::RightsAt(originalRSP)!="rw-p" ||
     c8c2::RightsAt(originalRSP-8)!="rw-p")
    return 13;

  // Original immutable SHA-verified Linux x86-64 ldso code source:
  // 0x2020d 48 81 ec 88 00 00 00 sub rsp,0x88
  // 0x20214 48 89 bd 78 ff ff ff mov [rbp-0x88],rdi
  // 0x2021b 0f 29 4d 80 movaps [rbp-0x80],xmm1
  // 0x2021f 0f 31 rdtsc (NOT EXECUTED: only first opcode byte HLT).
  c8c2::Stage("ORIGINAL_NATIVE_PTLOAD_WX_ENFORCED");
  constexpr std::array<uint8_t,64> kOriginal64{
    0xf3,0x0f,0x1e,0xfa,0x55,
    0x48,0x8d,0x0d,0x14,0xfe,0xfd,0xff,
    0x48,0x8d,0x05,0xe5,0x90,0x01,0x00,
    0x66,0x48,0x0f,0x6e,0xc9,
    0x66,0x48,0x0f,0x6e,0xd0,
    0x66,0x0f,0x6c,0xca,
    0x48,0x89,0xe5,
    0x41,0x57,0x41,0x56,0x41,0x55,0x41,0x54,0x53,
    0x48,0x81,0xec,0x88,0x00,0x00,0x00,
    0x48,0x89,0xbd,0x78,0xff,0xff,0xff,
    0x0f,0x29,0x4d,0x80,
    0x0f};
  static_assert(kOriginal64.size()==c8c2::kNextInstructionOffset+1);
  const auto* source64=staged.GuestReadOnlyBytes(
      1,originalTarget,kOriginal64.size());
  if(!source64 ||
      std::memcmp(source64,kOriginal64.data(),kOriginal64.size())!=0) {
    std::fprintf(stderr,
      "C3D8C2_SOURCE_TARGET_NOT_WHITELISTED first5=%02x%02x%02x%02x%02x\n",
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
  targetByte[c8c2::kNextInstructionOffset]=c8c2::kInjectedHLT;
  if(::mprotect(reinterpret_cast<void*>(
       static_cast<uintptr_t>(targetPage)),4096,PROT_READ|PROT_EXEC)!=0)
    return 15;
  if(c8c2::RightsAt(originalRIP)!="r-xp" ||
     c8c2::RightsAt(originalTarget)!="r-xp" ||
     targetByte[c8c2::kNextInstructionOffset]!=c8c2::kInjectedHLT ||
      std::memcmp(targetByte,kOriginal64.data(),c8c2::kNextInstructionOffset)!=0 ||
     std::memcmp(sourceEntry,call.originalEntryBytes.data(),c8c2::kOriginalTwoOpcodesBytes)!=0)
    return 16;

  // Use source-backed authentic LEA displacement from instruction bytes
  // (target + 8) and actual rebased guest RIP. No synthetic address.
  std::int32_t leaDisp=0;
  std::memcpy(&leaDisp,call.originalTargetBytes.data()+8,sizeof(leaDisp));
  const uint64_t leaNextRIP=originalTarget+c8c2::kOriginalFifthEndOffset;
  const uint64_t expectedLEAResult=
      leaNextRIP+static_cast<uint64_t>(static_cast<int64_t>(leaDisp));
  if(expectedLEAResult!=staged.Module(1)->loadBias)return 37;
  // Sixth authentic LEA RAX signed displacement at original +15.
  std::int32_t sixthDisp=0;
  std::memcpy(&sixthDisp,kOriginal64.data()+15,sizeof(sixthDisp));
  const uint64_t expectedRAX=
      originalTarget+c8c2::kOriginalSixthEndOffset+
      static_cast<uint64_t>(static_cast<int64_t>(sixthDisp));
  if(expectedRAX!=staged.Module(1)->loadBias+uint64_t{0x392d8})
    return 38;
  c8c2::Stage("ORIGINAL_LDSO_EIGHTEEN_SOURCE_BYTES_AND_RIPREL_ADDR_VERIFIED");
  // Snapshot all 192 bytes including the 136-byte new stack-local area
  // before any FEX execution. MOVAPS must be 16-byte aligned.
  if((originalRSP & uint64_t{15})!=0 ||
     originalRSP<c8c2::kGuestStackBytes ||
     c8c2::RightsAt(originalRSP-c8c2::kGuestStackBytes)!="rw-p" ||
     c8c2::RightsAt(originalRSP-1)!="rw-p")return 33;
  std::array<uint8_t,c8c2::kGuestStackBytes> originalGuestStackBytes{};
  std::memcpy(originalGuestStackBytes.data(),
    reinterpret_cast<const void*>(static_cast<uintptr_t>(
      originalRSP-c8c2::kGuestStackBytes)),
    originalGuestStackBytes.size());
  c8c2::Stage("ORIGINAL_GUEST_192BYTE_STACK_SNAPSHOT_READY");
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
  c8c2::OriginalFEXGuardedCallRetStack callret;
  if(!callret.Reserve())return 17;
  c8c2::Stage("NATIVE_FEX_CALLRET_GUARDED_STACK_READY");
  auto ctx=FEXCore::Context::Context::CreateNewContext(host);
  if(!ctx)return 17;
  FEXCore::SignalDelegator signals{};
  c8c2::DenyAllGuestSyscalls deny{originalRIP,originalTarget};
  ctx->SetSignalDelegator(&signals);
  ctx->SetSyscallHandler(&deny);
  ctx->EnableExitOnHLT();
  if(!ctx->InitCore())return 18;
  c8c2::Stage("REAL_FEX_CONTEXT_INITCORE_PASS");
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
  constexpr uint64_t r15Witness=0x4b45524e58000015ULL;
  constexpr uint64_t r14Witness=0x4b45524e58000014ULL;
  constexpr uint64_t r13Witness=0x4b45524e58000013ULL;
  constexpr uint64_t r12Witness=0x4b45524e58000012ULL;
  constexpr uint64_t rbxWitness=0x4b45524e58000b0bULL;
  constexpr uint64_t rcxWitness=0x4b45524e49584351ULL;
  constexpr uint64_t raxWitness=0x4b45524e49584158ULL;
  constexpr uint64_t xmm1LowWitness=0x5a51f00daaaabbbbULL;
  constexpr uint64_t xmm1HighWitness=0x5a51c00dccccddddULL;
  constexpr uint64_t xmm2LowWitness=0x5a52f00deeeeffffULL;
  constexpr uint64_t xmm2HighWitness=0x5a52c00d11112222ULL;
  cpu.rip=originalRIP;
  cpu.gregs[FEXCore::X86State::REG_RSP]=originalRSP;
  cpu.gregs[FEXCore::X86State::REG_RDI]=sentinel;
  cpu.gregs[FEXCore::X86State::REG_RBP]=rbpWitness;
  cpu.gregs[FEXCore::X86State::REG_R15]=r15Witness;
  cpu.gregs[FEXCore::X86State::REG_R14]=r14Witness;
  cpu.gregs[FEXCore::X86State::REG_R13]=r13Witness;
  cpu.gregs[FEXCore::X86State::REG_R12]=r12Witness;
  cpu.gregs[FEXCore::X86State::REG_RBX]=rbxWitness;
  cpu.gregs[FEXCore::X86State::REG_RCX]=rcxWitness;
  cpu.gregs[FEXCore::X86State::REG_RAX]=raxWitness;
  // Pin to exact upstream FEXCore CPUState::XMMRegs::SSE layout.
  // MOVQ r64 -> XMM1 must set low qword and zero high qword,
  // while leaving unrelated XMM2 unchanged.
  static_assert(sizeof(cpu.xmm.sse.data[1])==2*sizeof(uint64_t));
  cpu.xmm.sse.data[1][0]=xmm1LowWitness;
  cpu.xmm.sse.data[1][1]=xmm1HighWitness;
  cpu.xmm.sse.data[2][0]=xmm2LowWitness;
  cpu.xmm.sse.data[2][1]=xmm2HighWitness;
  cpu.fs_cached=0;cpu.gs_cached=0;
  if(cpu.rip!=originalRIP ||
     cpu.gregs[FEXCore::X86State::REG_RSP]!=originalRSP ||
     cpu.gregs[FEXCore::X86State::REG_RDI]!=sentinel)
    return 20;
  c8c2::Stage("REAL_FEX_THREAD_GUEST_CPUSTATE_READY");
  std::fputs("KERNIX_C3D8C2_ANDROID_BEGIN_EIGHTEEN_REAL_ORIGINAL_LDSO_LOCAL_FRAME_SIMD_FEX_EXECUTETHREAD\n",stderr);
  std::fflush(stderr);
  ctx->ExecuteThread(thread);
  c8c2::Stage("FEX_EXECUTETHREAD_RETURNED");
  const uint64_t postRIP=cpu.rip;
  // Source-order witness slots: guest stack grows down eight bytes
  // for each original CALL/PUSH. Verify by actual copied guest bytes.
  std::array<uint64_t,c8c2::kGuestSavedSlotCount> saved{};
  if(c8c2::RightsAt(originalRSP-c8c2::kGuestStackBytes)!="rw-p" ||
     c8c2::RightsAt(originalRSP-1)!="rw-p")return 21;
  for(size_t i=0;i<saved.size();++i) {
    const uint64_t slot=originalRSP-8*static_cast<uint64_t>(i+1);
    std::memcpy(&saved[i],reinterpret_cast<const void*>(
       static_cast<uintptr_t>(slot)),sizeof(saved[i]));
  }
  const std::array<uint64_t,7> expectedSaved{
    call.originalReturnRIP,rbpWitness,
    r15Witness,r14Witness,r13Witness,r12Witness,rbxWitness};
  bool stackWitnessesMatch=true;
  for(size_t i=0;i<saved.size();++i)
    if(saved[i]!=expectedSaved[i])stackWitnessesMatch=false;
  // Independently inspect original instructions' real in-memory writes.
  // Original source 17th MOV stores source guest startup RSP from RDI.
  // Original 18th MOVAPS stores source-authentic packed XMM1 128 bits.
  const uint64_t localRDIAt=originalRSP-16-c8c2::kLocalAreaBytes;
  const uint64_t localXMMAt=originalRSP-16-0x80;
  if((localXMMAt&uint64_t{15})!=0 ||
     c8c2::RightsAt(localRDIAt)!="rw-p" ||
     c8c2::RightsAt(localXMMAt)!="rw-p")return 39;
  uint64_t storedRDI=0;
  std::array<uint64_t,2> storedXMM{};
  std::memcpy(&storedRDI,reinterpret_cast<const void*>(
    static_cast<uintptr_t>(localRDIAt)),sizeof(storedRDI));
  std::memcpy(storedXMM.data(),reinterpret_cast<const void*>(
    static_cast<uintptr_t>(localXMMAt)),sizeof(storedXMM));
  const bool localsMatch=
    storedRDI==originalRSP &&
    storedXMM[0]==expectedLEAResult &&
    storedXMM[1]==expectedRAX;
  if(cpu.gregs[FEXCore::X86State::REG_RDI]!=originalRSP ||
     cpu.gregs[FEXCore::X86State::REG_RDI]==sentinel ||
     cpu.gregs[FEXCore::X86State::REG_RSP]!=originalRSP-c8c2::kGuestStackBytes ||
     !localsMatch ||
     cpu.gregs[FEXCore::X86State::REG_RBP]!=originalRSP-16 ||
     cpu.gregs[FEXCore::X86State::REG_R15]!=r15Witness ||
     cpu.gregs[FEXCore::X86State::REG_R14]!=r14Witness ||
     cpu.gregs[FEXCore::X86State::REG_R13]!=r13Witness ||
     cpu.gregs[FEXCore::X86State::REG_R12]!=r12Witness ||
     cpu.gregs[FEXCore::X86State::REG_RBX]!=rbxWitness ||
     cpu.gregs[FEXCore::X86State::REG_RBP]==rbpWitness ||
     cpu.gregs[FEXCore::X86State::REG_RCX]!=expectedLEAResult ||
     cpu.gregs[FEXCore::X86State::REG_RCX]==rcxWitness ||
     cpu.gregs[FEXCore::X86State::REG_RAX]!=expectedRAX ||
     cpu.gregs[FEXCore::X86State::REG_RAX]==raxWitness ||
     cpu.xmm.sse.data[1][0]!=expectedLEAResult ||
     cpu.xmm.sse.data[1][0]==xmm1LowWitness ||
     cpu.xmm.sse.data[1][1]!=expectedRAX ||
     cpu.xmm.sse.data[1][1]==xmm1HighWitness ||
     cpu.xmm.sse.data[2][0]!=expectedRAX ||
     cpu.xmm.sse.data[2][0]==xmm2LowWitness ||
     cpu.xmm.sse.data[2][1]!=0 ||
     !stackWitnessesMatch ||
     (postRIP!=originalTarget+c8c2::kNextInstructionOffset &&
      postRIP!=originalTarget+c8c2::kNextInstructionOffset+1)) {
    std::fprintf(stderr,
      "C3D8C2_SIMD_DIAG xmm1lo=%llx expected=%llx xmm1hi=%llx xmm2lo=%llx xmm2hi=%llx\\n",
      static_cast<unsigned long long>(cpu.xmm.sse.data[1][0]),
      static_cast<unsigned long long>(expectedLEAResult),
      static_cast<unsigned long long>(cpu.xmm.sse.data[1][1]),
      static_cast<unsigned long long>(cpu.xmm.sse.data[2][0]),
      static_cast<unsigned long long>(cpu.xmm.sse.data[2][1]));
    std::fprintf(stderr,
      "C3D8C2_RIPREL_DIAG post=%llx stop=%llx rax=%llx expectedRAX=%llx rcx=%llx expectedRCX=%llx\n",
      static_cast<unsigned long long>(postRIP),
      static_cast<unsigned long long>(originalTarget+c8c2::kNextInstructionOffset),
      static_cast<unsigned long long>(cpu.gregs[FEXCore::X86State::REG_RAX]),
      static_cast<unsigned long long>(expectedRAX),
      static_cast<unsigned long long>(cpu.gregs[FEXCore::X86State::REG_RCX]),
      static_cast<unsigned long long>(expectedLEAResult));
    std::fprintf(stderr,
      "C3D8C2_LOCAL_FRAME_DIAG ok=%d rdi=%llx wanted=%llx xmmlo=%llx wantedlo=%llx xmmhi=%llx wantedhi=%llx\n",
      int(localsMatch),
      static_cast<unsigned long long>(storedRDI),
      static_cast<unsigned long long>(originalRSP),
      static_cast<unsigned long long>(storedXMM[0]),
      static_cast<unsigned long long>(expectedLEAResult),
      static_cast<unsigned long long>(storedXMM[1]),
      static_cast<unsigned long long>(expectedRAX));
    std::fprintf(stderr,
      "C3D8C2_MULTI_PUSH_DIAG match=%d rsp=%llx expected=%llx "
      "slots_ret_rbp_r15_r14_r13_r12_rbx=%llx,%llx,%llx,%llx,%llx,%llx,%llx\n",
      int(stackWitnessesMatch),
      static_cast<unsigned long long>(cpu.gregs[FEXCore::X86State::REG_RSP]),
      static_cast<unsigned long long>(originalRSP-c8c2::kGuestStackBytes),
      static_cast<unsigned long long>(saved[0]),
      static_cast<unsigned long long>(saved[1]),
      static_cast<unsigned long long>(saved[2]),
      static_cast<unsigned long long>(saved[3]),
      static_cast<unsigned long long>(saved[4]),
      static_cast<unsigned long long>(saved[5]),
      static_cast<unsigned long long>(saved[6]));
    std::fprintf(stderr,
      "C3D8C2_POST_PUSH_STATE_REJECT src=%llx dst=%llx post=%llx rsp=%llx rdi=%llx ret=%llx expected=%llx\n",
      static_cast<unsigned long long>(originalRIP),
      static_cast<unsigned long long>(originalTarget),
      static_cast<unsigned long long>(postRIP),
      static_cast<unsigned long long>(
        cpu.gregs[FEXCore::X86State::REG_RSP]),
      static_cast<unsigned long long>(
        cpu.gregs[FEXCore::X86State::REG_RDI]),
      static_cast<unsigned long long>(saved[0]),
      static_cast<unsigned long long>(call.originalReturnRIP));
    return 21;
  }
  c8c2::Stage("ORIGINAL_18_GPR_PUSHES_192BYTE_FRAME_AND_SSE_STORES_VERIFIED");
  // Restore the sole target trap byte after FEX has exited.
  if(::mprotect(reinterpret_cast<void*>(
       static_cast<uintptr_t>(targetPage)),4096,PROT_READ|PROT_WRITE)!=0)
    return 22;
  targetByte[c8c2::kNextInstructionOffset]=kOriginal64[c8c2::kNextInstructionOffset];
  if(::mprotect(reinterpret_cast<void*>(
       static_cast<uintptr_t>(targetPage)),4096,PROT_READ|PROT_EXEC)!=0)
    return 23;
  if(c8c2::RightsAt(originalRIP)!="r-xp" ||
     c8c2::RightsAt(originalTarget)!="r-xp" ||
     std::memcmp(sourceEntry,call.originalEntryBytes.data(),16)!=0 ||
     std::memcmp(targetByte,kOriginal64.data(),kOriginal64.size())!=0 ||
     !c8c2::OriginalFileBackedBytesRestored(original,staged) ||
     staged.WindowsHeld()!=4)return 24;
  c8c2::Stage("ORIGINAL_LDSO_SOURCE_PTLOAD_BYTES_RESTORED");
  // Restore 192 bytes including new local area and all saved registers.
  if(c8c2::RightsAt(originalRSP-c8c2::kGuestStackBytes)!="rw-p" ||
     c8c2::RightsAt(originalRSP-1)!="rw-p")return 35;
  std::memcpy(reinterpret_cast<void*>(static_cast<uintptr_t>(
      originalRSP-c8c2::kGuestStackBytes)),
      originalGuestStackBytes.data(),originalGuestStackBytes.size());
  if(std::memcmp(reinterpret_cast<const void*>(
      static_cast<uintptr_t>(originalRSP-c8c2::kGuestStackBytes)),
      originalGuestStackBytes.data(),originalGuestStackBytes.size())!=0)return 36;
  c8c2::Stage("ORIGINAL_GUEST_STACK_192_BYTES_RESTORED");
  // Destroy FEX context/thread while its call-ret map remains
  // alive; then release that host-only stack and the original VMAs.
  ctx.reset();
  if(!callret.Release())return 25;
  if(!staged.Release() || staged.WindowsHeld()!=0)return 26;
  c8c2::Stage("REAL_FEX_GUEST_AND_NATIVE_VM_RESOURCES_RELEASED");
  std::puts("KERNIX_C3D8C2_ANDROID_DEVICE_SOURCE_ORIGINAL_LDSO_EIGHTEEN_FEX_INSTRUCTIONS_PASS");
  std::puts("ORIGINAL_THREE_X86_LINUX_ELF_SHA256_VERIFIED=1");
  std::puts("REAL_ANDROID_BIONIC_ARM64_FEX_CONTEXT_CREATED=1");
  std::puts("ORIGINAL_LDSO_FIRST_TEN_SOURCE_X86_LEA_SIMD_OPS_VERIFIED=1");
  std::puts("ORIGINAL_LDSO_SOURCE_GPR_PUSH_R15_EXECUTED=1");
  std::puts("ORIGINAL_LDSO_SOURCE_GPR_PUSH_R14_EXECUTED=1");
  std::puts("ORIGINAL_LDSO_SOURCE_GPR_PUSH_R13_EXECUTED=1");
  std::puts("ORIGINAL_LDSO_SOURCE_GPR_PUSH_R12_EXECUTED=1");
  std::puts("ORIGINAL_LDSO_SOURCE_GPR_PUSH_RBX_EXECUTED=1");
  std::puts("ORIGINAL_SEVEN_CALL_PUSH_STACK_SLOTS_AND_VALUES_VERIFIED=1");
  std::puts("ORIGINAL_SOURCE_SUB_RSP_0X88_FRAME_EXECUTED=1");
  std::puts("ORIGINAL_SOURCE_MOV_GUEST_LOCAL_RDI_EXECUTED=1");
  std::puts("ORIGINAL_SOURCE_MOVAPS_GUEST_LOCAL_XMM1_EXECUTED=1");
  std::puts("ORIGINAL_LOCAL_RDI_AND_PACKED_SSE_LANES_VERIFIED=1");
  std::puts("ORIGINAL_MOVAPS_GUEST_LOCAL_ALIGNMENT_16_VERIFIED=1");
  std::puts("GUEST_RSP_EQUALS_ORIGINAL_RSP_MINUS_192=1");
  std::puts("SOURCE_NINETEENTH_RDTSC_REPLACED_BY_BOUNDED_HLT=1");
  std::puts("SOURCE_NINETEENTH_RDTSC_EXECUTED=0");
  std::puts("SOURCE_GUEST_192_STACK_AND_HOST_STACK_RESTORED=1");
  std::puts("ORIGINAL_PTLOAD_RX_RW_WX_ENFORCED=1");
  std::puts("ALL_ORIGINAL_GUEST_WINDOWS_RELEASED=1");
  std::puts("GUEST_LINUX_SYSCALLS_FORWARDED=0");
  std::puts("COMPLETE_LDSO_DYNAMIC_LINKER_STARTUP=0");
  std::puts("WINE_OR_WINDOWS_PE_EXECUTED=0");
  return 0;
}
