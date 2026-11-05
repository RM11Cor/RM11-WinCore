// SPDX-License-Identifier: MIT
// C3-D8C3: source-locked FEX Android ARM64 executes 21 original
// ld-linux x86 instructions, including first authentic RW PT_LOAD
// DATA byte update AND byte ptr [RIP+disp32],0xdf and LEA RSI of
// another source-authentic ldso data pointer, after original RDTSC.
// Bit5 set transiently in ONLY the owned anonymous staged RW guest
// data byte as a negative/positive test witness. After executing
// the genuine source x86 instruction, require bit5 cleared and all
// other bits preserved, then restore the exact original byte.
// Independent exact source-derived signed RIP displacement target;
// final HLT at original 22nd MOV R8D first byte ONLY in staging.
// Keep original 192-byte guest stack, verified RX/RW separation, and
// all source snapshots intact. NOT Android/glibc startup/Wine/games.
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
#error C3-D8C3 isolated user-opt-in Android Bionic AArch64 only
#endif
namespace m=kernix::g2e;
namespace b=kernix::g2e::c3d7b;
namespace e=kernix::g2e::c3d7e;
namespace g=kernix::g2e::c3d7g;
namespace c8c3 {
static constexpr const char kFlag[] =
  "--kernix-c3d8c3-source-original-ldso-21-instructions-v1";
static void Stage(const char* name) noexcept {
  std::fprintf(stderr,"KERNIX_C3D8C3_STAGE=%s\n",name);
  std::fflush(stderr);
}
static bool ValidateAppPrivateOriginalRoot(const char* raw) {
  if(!raw || raw[0]!='/' || std::strlen(raw)>2048)return false;
  const std::string path(raw);
  if(path.find("..")!=std::string::npos ||
     path.find("//")!=std::string::npos ||
     !path.ends_with("/c3d8c3-original-guest"))return false;
  return path.starts_with("/data/user/0/org.kernix.originalfexldso21/files/") ||
         path.starts_with("/data/data/org.kernix.originalfexldso21/files/");
}
static constexpr size_t kSourceBytes=16;
static constexpr size_t kTargetExecutableBytes=128; // includes original RDTSC at +63..64 and source-verified HLT at +65
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
static constexpr size_t kOriginalNineteenthRDTSCBytes=2;
static constexpr size_t kOriginalTwentiethANDBytes=7;
static constexpr size_t kOriginalTwentyFirstLEABytes=7;
static constexpr size_t kOriginalTwentiethStartOffset=kOriginalFifteenthEndOffset+
  kOriginalSixteenthSUBBytes+kOriginalSeventeenthMOVBytes+
  kOriginalEighteenthMOVAPSBytes+kOriginalNineteenthRDTSCBytes;
static constexpr size_t kOriginalTwentyFirstStartOffset=kOriginalTwentiethStartOffset+kOriginalTwentiethANDBytes;
static constexpr size_t kNextInstructionOffset=kOriginalTwentyFirstStartOffset+kOriginalTwentyFirstLEABytes;
static constexpr size_t kGuestSavedSlotCount=7; // CALL, RBP, five GPR PUSHes
static constexpr size_t kLocalAreaBytes=0x88;
static constexpr size_t kGuestStackBytes=kGuestSavedSlotCount*sizeof(uint64_t)+kLocalAreaBytes;
static_assert(kGuestStackBytes==192 && kOriginalTwentiethStartOffset==65 && kNextInstructionOffset==79);
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
    std::fputs("KERNIX_C3D8C3_UNEXPECTED_GUEST_SYSCALL_DENIED\n",stderr);
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
} // namespace c8c3

int main(int argc,char** argv) {
  if(argc!=3 || !argv[1] || !argv[2] ||
     std::strcmp(argv[1],c8c3::kFlag)!=0 ||
     !c8c3::ValidateAppPrivateOriginalRoot(argv[2]))return 2;
  if(::sysconf(_SC_PAGESIZE)!=4096)return 3;
  const int fd=::open(argv[2],O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
  if(fd<0)return 4;
  m::GuestPreflight original;
  std::string why;
  if(!m::Validate(fd,original,why)) {
    std::fprintf(stderr,"C3D8C3_ORIGINAL_SOURCE_SHA256_DENIED %s\n",why.c_str());
    ::close(fd);return 5;
  }
  std::array<uint8_t,16> entropy{};
  c8c3::Stage("ORIGINAL_THREE_SOURCE_ELF_SHA256_VALIDATED");
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
  c8c3::Stage("ORIGINAL_GUEST_VM_AND_STACK_OWNED");
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
     call.originalReturnRIP!=originalRIP+c8c3::kOriginalTwoOpcodesBytes) {
    std::fprintf(stderr,
      "C3D8C3_ORIGINAL_SOURCE_CALL_TARGET_REJECT reason=%u\n",
      unsigned(callReject));
    return 10;
  }
  const uint64_t originalTarget=call.originalTarget;
  c8c3::Stage("ORIGINAL_LDSO_SOURCE_CALL_RIP_VERIFIED");
  if(originalTarget==originalRIP ||
     call.originalTargetBytes[0]==c8c3::kInjectedHLT)
    return 11;
  const auto* sourceEntry=staged.GuestReadOnlyBytes(
      1,originalRIP,c8c3::kSourceBytes);
  if(!sourceEntry)return 9;
  std::array<uint8_t,c8c3::kSourceBytes> originalSourceBytes{};
  std::memcpy(originalSourceBytes.data(),sourceEntry,
              originalSourceBytes.size());
  // Genuine entry bytes 48 89 e7 (mov rsp,rdi) and E8 rel32
  // (CALL) remain unchanged. Only the source-attested CALL target
  // receives a temporary 1-byte HLT in guest staging.
  if(std::memcmp(originalSourceBytes.data(),
                 call.originalEntryBytes.data(),16)!=0 ||
     (originalRIP&4095)>4096-c8c3::kSourceBytes ||
     (originalTarget&4095)>4096-c8c3::kSourceBytes)
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
  if(c8c3::RightsAt(originalRIP)!="r-xp" ||
     c8c3::RightsAt(originalTarget)!="r-xp" ||
     c8c3::RightsAt(originalRSP)!="rw-p" ||
     c8c3::RightsAt(originalRSP-8)!="rw-p")
    return 13;

  // Source audit from exact SHA-pinned original x86 ld-linux:
  // 0x20221: 80 25 de 8b 01 00 df AND byte [RIP+0x18bde],0xdf
  //           destination ELF VA 0x38e06, original RW data PT_LOAD.
  // 0x20228: 48 8d 35 c1 88 01 00 LEA RSI,[RIP+0x188c1]
  //           destination ELF VA 0x38af0.
  // 0x2022f: 41 b8 ff ff ff 6f MOV R8D,0x6fffffff, NOT executed.
  constexpr std::array<uint8_t,80> kOriginal80{
  c8c3::Stage("ORIGINAL_RX_RW_PTLOAD_WX_SEPARATED");
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
    0x0f,0x31,
    0x80,0x25,0xde,0x8b,0x01,0x00,0xdf,
    0x48,0x8d,0x35,0xc1,0x88,0x01,0x00,
    0x41};
  static_assert(kOriginal80.size()==c8c3::kNextInstructionOffset+1);
  const auto* source80=staged.GuestReadOnlyBytes(
      1,originalTarget,kOriginal80.size());
  if(!source80 ||
      std::memcmp(source80,kOriginal80.data(),kOriginal80.size())!=0) {
    std::fprintf(stderr,
      "C3D8C3_SOURCE_TARGET_NOT_WHITELISTED first5=%02x%02x%02x%02x%02x\n",
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
  targetByte[c8c3::kNextInstructionOffset]=c8c3::kInjectedHLT;
  if(::mprotect(reinterpret_cast<void*>(
       static_cast<uintptr_t>(targetPage)),4096,PROT_READ|PROT_EXEC)!=0)
    return 15;
  if(c8c3::RightsAt(originalRIP)!="r-xp" ||
     c8c3::RightsAt(originalTarget)!="r-xp" ||
     targetByte[c8c3::kNextInstructionOffset]!=c8c3::kInjectedHLT ||
      std::memcmp(targetByte,kOriginal80.data(),c8c3::kNextInstructionOffset)!=0 ||
     std::memcmp(sourceEntry,call.originalEntryBytes.data(),c8c3::kOriginalTwoOpcodesBytes)!=0)
    return 16;

  // Use source-backed authentic LEA displacement from instruction bytes
  // (target + 8) and actual rebased guest RIP. No synthetic address.
  std::int32_t leaDisp=0;
  std::memcpy(&leaDisp,call.originalTargetBytes.data()+8,sizeof(leaDisp));
  const uint64_t leaNextRIP=originalTarget+c8c3::kOriginalFifthEndOffset;
  const uint64_t expectedLEAResult=
      leaNextRIP+static_cast<uint64_t>(static_cast<int64_t>(leaDisp));
  if(expectedLEAResult!=staged.Module(1)->loadBias)return 37;
  // Sixth authentic LEA RAX signed displacement at original +15.
  std::int32_t sixthDisp=0;
  std::memcpy(&sixthDisp,kOriginal80.data()+15,sizeof(sixthDisp));
  const uint64_t expectedRAX=
      originalTarget+c8c3::kOriginalSixthEndOffset+
      static_cast<uint64_t>(static_cast<int64_t>(sixthDisp));
  if(expectedRAX!=staged.Module(1)->loadBias+uint64_t{0x392d8})
    return 38;
  // Independently derive both new RIP-relative data addresses from
  // source-backed signed disp32 encodings, not hand-selected pointers.
  std::int32_t andRel=0, leaRSIRel=0;
  std::memcpy(&andRel,kOriginal80.data()+c8c3::kOriginalTwentiethStartOffset+2,sizeof(andRel));
  std::memcpy(&leaRSIRel,kOriginal80.data()+c8c3::kOriginalTwentyFirstStartOffset+3,sizeof(leaRSIRel));
  const uint64_t guestANDAt=originalTarget+c8c3::kOriginalTwentyFirstStartOffset+
      static_cast<uint64_t>(static_cast<int64_t>(andRel));
  const uint64_t expectedRSI=originalTarget+c8c3::kNextInstructionOffset+
      static_cast<uint64_t>(static_cast<int64_t>(leaRSIRel));
  if(guestANDAt!=staged.Module(1)->loadBias+uint64_t{0x38e06} ||
     expectedRSI!=staged.Module(1)->loadBias+uint64_t{0x38af0} ||
     c8c3::RightsAt(guestANDAt)!="rw-p" ||
     c8c3::RightsAt(expectedRSI)=="unmapped")return 40;
  // Change only one bit of one RW byte in our disposable guest VMA,
  c8c3::Stage("ORIGINAL_21_SOURCE_BYTES_AND_RW_RIPREL_TARGET_VERIFIED");
  // NOT the original SHA-locked source file; require the real AND
  // clears it without affecting the other seven bits.
  auto* const guestANDByte=reinterpret_cast<uint8_t*>(
      static_cast<uintptr_t>(guestANDAt));
  const uint8_t originalGuestANDByte=*guestANDByte;
  const uint8_t guestANDSeed=static_cast<uint8_t>(originalGuestANDByte|0x20u);
  const uint8_t expectedGuestANDByte=static_cast<uint8_t>(guestANDSeed&0xdfu);
  if(guestANDSeed==expectedGuestANDByte)return 41;
  *guestANDByte=guestANDSeed;
  // Snapshot all 192 bytes including the 136-byte new stack-local area
  c8c3::Stage("OWNED_ORIGINAL_GUEST_RW_DATA_BIT5_SEEDED");
  // before any FEX execution. MOVAPS must be 16-byte aligned.
  if((originalRSP & uint64_t{15})!=0 ||
     originalRSP<c8c3::kGuestStackBytes ||
     c8c3::RightsAt(originalRSP-c8c3::kGuestStackBytes)!="rw-p" ||
     c8c3::RightsAt(originalRSP-1)!="rw-p")return 33;
  std::array<uint8_t,c8c3::kGuestStackBytes> originalGuestStackBytes{};
  std::memcpy(originalGuestStackBytes.data(),
    reinterpret_cast<const void*>(static_cast<uintptr_t>(
      originalRSP-c8c3::kGuestStackBytes)),
    originalGuestStackBytes.size());
  FEXCore::Config::Initialize();
  c8c3::Stage("ORIGINAL_GUEST_192_BYTE_STACK_SNAPSHOTTED");
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
  c8c3::OriginalFEXGuardedCallRetStack callret;
  if(!callret.Reserve())return 17;
  c8c3::Stage("GUARDED_NATIVE_FEX_CALLRET_READY");
  auto ctx=FEXCore::Context::Context::CreateNewContext(host);
  if(!ctx)return 17;
  FEXCore::SignalDelegator signals{};
  c8c3::DenyAllGuestSyscalls deny{originalRIP,originalTarget};
  ctx->SetSignalDelegator(&signals);
  ctx->SetSyscallHandler(&deny);
  ctx->EnableExitOnHLT();
  if(!ctx->InitCore())return 18;
  c8c3::Stage("ORIGINAL_ANDROID_FEX_CONTEXT_INITCORE_PASS");
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
  constexpr uint64_t rdxWitness=0x4b45524e49584458ULL;
  constexpr uint64_t rsiWitness=0x4b45524e49585349ULL;
  constexpr uint64_t r8Witness=0x4b45524e49583838ULL;
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
  cpu.gregs[FEXCore::X86State::REG_RDX]=rdxWitness;
  cpu.gregs[FEXCore::X86State::REG_RSI]=rsiWitness;
  cpu.gregs[FEXCore::X86State::REG_R8]=r8Witness;
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
  std::fputs("KERNIX_C3D8C3_BEGIN_TWENTYONE_REAL_ORIGINAL_LDSO_WITH_RW_DATA_AND_LEA_RSI_FEX_EXECUTETHREAD\n",stderr);
  std::fflush(stderr);
  c8c3::Stage("REAL_ORIGINAL_FEX_EXECUTETHREAD_ENTER");
  ctx->ExecuteThread(thread);
  const uint64_t postRIP=cpu.rip;
  c8c3::Stage("REAL_ORIGINAL_FEX_EXECUTETHREAD_RETURNED");
  // x86 RDTSC architecture returns a 64-bit virtual TSC as zero-
  // extended low32 in EAX/RAX and high32 in EDX/RDX. Source-specific
  // TSC scaling and guest temporal monotonicity remain separate gates.
  const uint64_t tscEAX=cpu.gregs[FEXCore::X86State::REG_RAX];
  const uint64_t tscEDX=cpu.gregs[FEXCore::X86State::REG_RDX];
  const uint64_t guestTSC=(tscEDX<<32)|tscEAX;
  const bool rdtscRegisterProof=
      tscEAX<=UINT32_MAX && tscEDX<=UINT32_MAX &&
      guestTSC!=0 && tscEAX!=expectedRAX &&
      tscEDX!=rdxWitness;
  const uint8_t postANDByte=*guestANDByte;
  const bool originalRWDataUpdatedCorrectly=
      postANDByte==expectedGuestANDByte &&
      postANDByte!=guestANDSeed;
  // Source-order witness slots: guest stack grows down eight bytes
  // for each original CALL/PUSH. Verify by actual copied guest bytes.
  std::array<uint64_t,c8c3::kGuestSavedSlotCount> saved{};
  if(c8c3::RightsAt(originalRSP-c8c3::kGuestStackBytes)!="rw-p" ||
     c8c3::RightsAt(originalRSP-1)!="rw-p")return 21;
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
  const uint64_t localRDIAt=originalRSP-16-c8c3::kLocalAreaBytes;
  const uint64_t localXMMAt=originalRSP-16-0x80;
  if((localXMMAt&uint64_t{15})!=0 ||
     c8c3::RightsAt(localRDIAt)!="rw-p" ||
     c8c3::RightsAt(localXMMAt)!="rw-p")return 39;
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
     cpu.gregs[FEXCore::X86State::REG_RSP]!=originalRSP-c8c3::kGuestStackBytes ||
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
     !rdtscRegisterProof ||
     !originalRWDataUpdatedCorrectly ||
     cpu.gregs[FEXCore::X86State::REG_RSI]!=expectedRSI ||
     cpu.gregs[FEXCore::X86State::REG_RSI]==rsiWitness ||
     cpu.gregs[FEXCore::X86State::REG_R8]!=r8Witness ||
     cpu.xmm.sse.data[1][0]!=expectedLEAResult ||
     cpu.xmm.sse.data[1][0]==xmm1LowWitness ||
     cpu.xmm.sse.data[1][1]!=expectedRAX ||
     cpu.xmm.sse.data[1][1]==xmm1HighWitness ||
     cpu.xmm.sse.data[2][0]!=expectedRAX ||
     cpu.xmm.sse.data[2][0]==xmm2LowWitness ||
     cpu.xmm.sse.data[2][1]!=0 ||
     !stackWitnessesMatch ||
     (postRIP!=originalTarget+c8c3::kNextInstructionOffset &&
      postRIP!=originalTarget+c8c3::kNextInstructionOffset+1)) {
    std::fprintf(stderr,
      "C3D8C3_SIMD_DIAG xmm1lo=%llx expected=%llx xmm1hi=%llx xmm2lo=%llx xmm2hi=%llx\\n",
      static_cast<unsigned long long>(cpu.xmm.sse.data[1][0]),
      static_cast<unsigned long long>(expectedLEAResult),
      static_cast<unsigned long long>(cpu.xmm.sse.data[1][1]),
      static_cast<unsigned long long>(cpu.xmm.sse.data[2][0]),
      static_cast<unsigned long long>(cpu.xmm.sse.data[2][1]));
    std::fprintf(stderr,
      "C3D8C3_RIPREL_DIAG post=%llx stop=%llx rax=%llx expectedRAX=%llx rcx=%llx expectedRCX=%llx\n",
      static_cast<unsigned long long>(postRIP),
      static_cast<unsigned long long>(originalTarget+c8c3::kNextInstructionOffset),
      static_cast<unsigned long long>(cpu.gregs[FEXCore::X86State::REG_RAX]),
      static_cast<unsigned long long>(expectedRAX),
      static_cast<unsigned long long>(cpu.gregs[FEXCore::X86State::REG_RCX]),
      static_cast<unsigned long long>(expectedLEAResult));
    std::fprintf(stderr,
      "C3D8C3_GUEST_LDSO_RW_DATA_DIAG guestVA=%llx original=%02x seed=%02x post=%02x expected=%02x good=%d rsi=%llx wantedRSI=%llx\n",
      static_cast<unsigned long long>(guestANDAt),
      unsigned(originalGuestANDByte),unsigned(guestANDSeed),
      unsigned(postANDByte),unsigned(expectedGuestANDByte),
      int(originalRWDataUpdatedCorrectly),
      static_cast<unsigned long long>(cpu.gregs[FEXCore::X86State::REG_RSI]),
      static_cast<unsigned long long>(expectedRSI));
    std::fprintf(stderr,
      "C3D8C3_RDTSC_DIAG eax=%llx edx=%llx combined=%llx proof=%d previous_rax=%llx seeded_rdx=%llx\n",
      static_cast<unsigned long long>(tscEAX),
      static_cast<unsigned long long>(tscEDX),
      static_cast<unsigned long long>(guestTSC),
      int(rdtscRegisterProof),
      static_cast<unsigned long long>(expectedRAX),
      static_cast<unsigned long long>(rdxWitness));
    std::fprintf(stderr,
      "C3D8C3_LOCAL_FRAME_DIAG ok=%d rdi=%llx wanted=%llx xmmlo=%llx wantedlo=%llx xmmhi=%llx wantedhi=%llx\n",
      int(localsMatch),
      static_cast<unsigned long long>(storedRDI),
      static_cast<unsigned long long>(originalRSP),
      static_cast<unsigned long long>(storedXMM[0]),
      static_cast<unsigned long long>(expectedLEAResult),
      static_cast<unsigned long long>(storedXMM[1]),
      static_cast<unsigned long long>(expectedRAX));
    std::fprintf(stderr,
      "C3D8C3_MULTI_PUSH_DIAG match=%d rsp=%llx expected=%llx "
      "slots_ret_rbp_r15_r14_r13_r12_rbx=%llx,%llx,%llx,%llx,%llx,%llx,%llx\n",
      int(stackWitnessesMatch),
      static_cast<unsigned long long>(cpu.gregs[FEXCore::X86State::REG_RSP]),
      static_cast<unsigned long long>(originalRSP-c8c3::kGuestStackBytes),
      static_cast<unsigned long long>(saved[0]),
      static_cast<unsigned long long>(saved[1]),
      static_cast<unsigned long long>(saved[2]),
      static_cast<unsigned long long>(saved[3]),
      static_cast<unsigned long long>(saved[4]),
      static_cast<unsigned long long>(saved[5]),
      static_cast<unsigned long long>(saved[6]));
    std::fprintf(stderr,
      "C3D8C3_POST_PUSH_STATE_REJECT src=%llx dst=%llx post=%llx rsp=%llx rdi=%llx ret=%llx expected=%llx\n",
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
  // Restore the sole target trap byte after FEX has exited.
  c8c3::Stage("RDTSC_AND_RW_BIT5_AND_REBASED_RSI_PROOFS_PASS");
  if(::mprotect(reinterpret_cast<void*>(
       static_cast<uintptr_t>(targetPage)),4096,PROT_READ|PROT_WRITE)!=0)
    return 22;
  targetByte[c8c3::kNextInstructionOffset]=kOriginal80[c8c3::kNextInstructionOffset];
  if(::mprotect(reinterpret_cast<void*>(
       static_cast<uintptr_t>(targetPage)),4096,PROT_READ|PROT_EXEC)!=0)
    return 23;
  // Restore the only originally staged writable ELF data byte after
  c8c3::Stage("ORIGINAL_SOURCE_OPCODE_HLT_BYTE_RESTORED");
  // the real x86 guest update, BEFORE source-backed byte restoration gate.
  if(c8c3::RightsAt(guestANDAt)!="rw-p")return 42;
  *guestANDByte=originalGuestANDByte;
  if(*guestANDByte!=originalGuestANDByte)return 43;
  if(c8c3::RightsAt(originalRIP)!="r-xp" ||
     c8c3::RightsAt(originalTarget)!="r-xp" ||
     std::memcmp(sourceEntry,call.originalEntryBytes.data(),16)!=0 ||
     std::memcmp(targetByte,kOriginal80.data(),kOriginal80.size())!=0 ||
     !c8c3::OriginalFileBackedBytesRestored(original,staged) ||
     staged.WindowsHeld()!=4)return 24;
  // Restore 192 bytes including new local area and all saved registers.
  c8c3::Stage("GUEST_RW_ORIGINAL_SOURCE_DATA_BYTE_RESTORED");
  if(c8c3::RightsAt(originalRSP-c8c3::kGuestStackBytes)!="rw-p" ||
     c8c3::RightsAt(originalRSP-1)!="rw-p")return 35;
  std::memcpy(reinterpret_cast<void*>(static_cast<uintptr_t>(
      originalRSP-c8c3::kGuestStackBytes)),
      originalGuestStackBytes.data(),originalGuestStackBytes.size());
  if(std::memcmp(reinterpret_cast<const void*>(
      static_cast<uintptr_t>(originalRSP-c8c3::kGuestStackBytes)),
      originalGuestStackBytes.data(),originalGuestStackBytes.size())!=0)return 36;
  // Destroy FEX context/thread while its call-ret map remains
  c8c3::Stage("ORIGINAL_GUEST_192_BYTE_STACK_RESTORED");
  // alive; then release that host-only stack and the original VMAs.
  ctx.reset();
  if(!callret.Release())return 25;
  if(!staged.Release() || staged.WindowsHeld()!=0)return 26;
  c8c3::Stage("ALL_NATIVE_FEX_AND_GUEST_VM_RESOURCES_RELEASED");
  std::puts("KERNIX_C3D8C3_ANDROID_DEVICE_SOURCE_ORIGINAL_LDSO_21_FEX_INSTRUCTIONS_PASS");
  std::puts("ORIGINAL_THREE_X86_LINUX_ELF_SHA256_VERIFIED=1");
  std::puts("REAL_ANDROID_BIONIC_ARM64_FEX_CONTEXT_CREATED=1");
  std::puts("ORIGINAL_FIRST_EIGHTEEN_SOURCE_X86_OPS_VERIFIED=1");
  std::puts("ORIGINAL_NINETEENTH_RDTSC_EXECUTED=1");
  std::puts("GUEST_RDTSC_EAX_EDX_32BIT_RESULT_VERIFIED=1");
  std::puts("GUEST_COMBINED_TSC_NONZERO=1");
  std::puts("ORIGINAL_TWENTIETH_AND_GUEST_RW_DATA_EXECUTED=1");
  std::puts("ORIGINAL_AND_SOURCE_DERIVED_RW_ADDRESS_VERIFIED=1");
  std::puts("ORIGINAL_AND_RW_BIT5_CLEARED_OTHER_BITS_PRESERVED=1");
  std::puts("ORIGINAL_TWENTY_FIRST_LEA_RSI_EXECUTED=1");
  std::puts("ORIGINAL_LEA_RSI_REBASED_LOADER_POINTER_VERIFIED=1");
  std::puts("ORIGINAL_SEVEN_CALL_PUSH_STACK_WITNESSES_VERIFIED=1");
  std::puts("ORIGINAL_GUEST_MOVAPS_AND_LOCAL_RDI_VERIFIED=1");
  std::puts("ORIGINAL_GUEST_RW_DATA_BYTE_RESTORED=1");
  std::puts("SOURCE_TWENTY_SECOND_MOV_R8D_REPLACED_BY_BOUNDED_HLT=1");
  std::puts("SOURCE_TWENTY_SECOND_MOV_R8D_EXECUTED=0");
  std::puts("SOURCE_GUEST_192_STACK_AND_HOST_STACK_RESTORED=1");
  std::puts("ORIGINAL_THREE_FILE_BACKED_PTLOAD_BYTES_RESTORED=1");
  std::puts("ORIGINAL_PTLOAD_RX_RW_WX_ENFORCED=1");
  std::puts("ALL_ORIGINAL_GUEST_WINDOWS_RELEASED=1");
  std::puts("GUEST_LINUX_SYSCALLS_FORWARDED=0");
  std::puts("COMPLETE_LDSO_DYNAMIC_LINKER_STARTUP=0");
  std::puts("WINE_OR_WINDOWS_PE_EXECUTED=0");
  return 0;
}
