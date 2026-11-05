// SPDX-License-Identifier: MIT
// C3-D7AC: real source-pinned FEX Linux ARM64 executes 28 original
// ld-linux x86 instructions, including first authentic RW PT_LOAD
// DATA byte update AND byte ptr [RIP+disp32],0xdf and LEA RSI of
// another source-authentic ldso data pointer, after original RDTSC.
// Bit5 set transiently in ONLY the owned anonymous staged RW guest
// data byte as a negative/positive test witness. After executing
// the genuine source x86 instruction, require bit5 cleared and all
// other bits preserved, then restore the exact original byte.
// Independent exact source-derived signed RIP displacement target;
// final HLT at original 29th MOV guest RW first byte ONLY in staging.
// Keep original 192-byte guest stack, verified RX/RW separation, and
// all source snapshots intact. NOT Android/glibc startup/Wine/games.
#define main kernix_c3d7ac_c2_source_reference_main
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
#error C3D7AC executes original ld-linux first x86 instruction Linux ARM64 CI only
#endif
namespace m=kernix::g2e;
namespace b=kernix::g2e::c3d7b;
namespace e=kernix::g2e::c3d7e;
namespace g=kernix::g2e::c3d7g;
namespace c7ac {
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
static constexpr size_t kOriginalTwentySecondMOVR8Bytes=6;
static constexpr size_t kOriginalTwentyThirdMOVR9Bytes=6;
static constexpr size_t kOriginalTwentyFourthSHLRDXBytes=4;
static constexpr size_t kOriginalTwentyFifthMOVRWBytes=7;
static constexpr size_t kOriginalTwentySixthMOVR14Bytes=3;
static constexpr size_t kOriginalTwentySeventhORRAXRDXBytes=3;
static constexpr size_t kOriginalTwentyEighthLEARDXBytes=7;
static constexpr size_t kOriginalTwentiethStartOffset=kOriginalFifteenthEndOffset+
  kOriginalSixteenthSUBBytes+kOriginalSeventeenthMOVBytes+
  kOriginalEighteenthMOVAPSBytes+kOriginalNineteenthRDTSCBytes;
static constexpr size_t kOriginalTwentyFirstStartOffset=kOriginalTwentiethStartOffset+kOriginalTwentiethANDBytes;
static constexpr size_t kOriginalTwentyFifthStartOffset=kOriginalTwentyFirstStartOffset+
  kOriginalTwentyFirstLEABytes+kOriginalTwentySecondMOVR8Bytes+
  kOriginalTwentyThirdMOVR9Bytes+kOriginalTwentyFourthSHLRDXBytes;
static constexpr size_t kOriginalTwentyFifthEndOffset=kOriginalTwentyFifthStartOffset+
  kOriginalTwentyFifthMOVRWBytes;
static constexpr size_t kOriginalTwentyEighthStartOffset=kOriginalTwentyFifthEndOffset+
  kOriginalTwentySixthMOVR14Bytes+kOriginalTwentySeventhORRAXRDXBytes;
static constexpr size_t kNextInstructionOffset=kOriginalTwentyEighthStartOffset+
  kOriginalTwentyEighthLEARDXBytes;
static constexpr size_t kGuestSavedSlotCount=7; // CALL, RBP, five GPR PUSHes
static constexpr size_t kLocalAreaBytes=0x88;
static constexpr size_t kGuestStackBytes=kGuestSavedSlotCount*sizeof(uint64_t)+kLocalAreaBytes;
static_assert(kGuestStackBytes==192 && kOriginalTwentiethStartOffset==65 && kOriginalTwentyFifthStartOffset==95 && kOriginalTwentyFifthEndOffset==102 && kOriginalTwentyEighthStartOffset==108 && kNextInstructionOffset==115);
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
    std::fputs("KERNIX_C3D7AC_UNEXPECTED_GUEST_SYSCALL_DENIED\n",stderr);
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
} // namespace c7ac

int main(int argc,char** argv) {
  if(argc!=2 || !argv[1])return 2;
  if(::sysconf(_SC_PAGESIZE)!=4096)return 3;
  const int fd=::open(argv[1],O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
  if(fd<0)return 4;
  m::GuestPreflight original;
  std::string why;
  if(!m::Validate(fd,original,why)) {
    std::fprintf(stderr,"C3D7AC_ORIGINAL_SOURCE_SHA256_DENIED %s\n",why.c_str());
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
     call.originalReturnRIP!=originalRIP+c7ac::kOriginalTwoOpcodesBytes) {
    std::fprintf(stderr,
      "C3D7AC_ORIGINAL_SOURCE_CALL_TARGET_REJECT reason=%u\n",
      unsigned(callReject));
    return 10;
  }
  const uint64_t originalTarget=call.originalTarget;
  if(originalTarget==originalRIP ||
     call.originalTargetBytes[0]==c7ac::kInjectedHLT)
    return 11;
  const auto* sourceEntry=staged.GuestReadOnlyBytes(
      1,originalRIP,c7ac::kSourceBytes);
  if(!sourceEntry)return 9;
  std::array<uint8_t,c7ac::kSourceBytes> originalSourceBytes{};
  std::memcpy(originalSourceBytes.data(),sourceEntry,
              originalSourceBytes.size());
  // Genuine entry bytes 48 89 e7 (mov rsp,rdi) and E8 rel32
  // (CALL) remain unchanged. Only the source-attested CALL target
  // receives a temporary 1-byte HLT in guest staging.
  if(std::memcmp(originalSourceBytes.data(),
                 call.originalEntryBytes.data(),16)!=0 ||
     (originalRIP&4095)>4096-c7ac::kSourceBytes ||
     (originalTarget&4095)>4096-c7ac::kSourceBytes)
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
  if(c7ac::RightsAt(originalRIP)!="r-xp" ||
     c7ac::RightsAt(originalTarget)!="r-xp" ||
     c7ac::RightsAt(originalRSP)!="rw-p" ||
     c7ac::RightsAt(originalRSP-8)!="rw-p")
    return 13;

  // Source audit from exact SHA-pinned original x86 ld-linux:
  // 0x20221: 80 25 de 8b 01 00 df AND byte [RIP+0x18bde],0xdf
  //           destination ELF VA 0x38e06, original RW data PT_LOAD.
  // 0x20228: 48 8d 35 c1 88 01 00 LEA RSI,[RIP+0x188c1]
  //           destination ELF VA 0x38af0.
  // 0x2022f: 41 b8 ff ff ff 6f MOV R8D,0x6fffffff, executed.
  // 0x20235: 41 b9 29 00 00 70 MOV R9D,0x70000029, executed.
  // 0x2023b: 48 c1 e2 20 SHL RDX,0x20, after original RDTSC, executed.
  // 0x2023f: 48 89 0d 6a 88 01 00 original 25th MOV [RIP+0x1886a],RCX
  //           actual original source RW qword ELF VA 0x38ab0, executed.
  // 0x20246 49 89 ce authentic 26th MOV R14,RCX executed.
  // 0x20249 48 09 d0 authentic 27th OR RAX,RDX combines source RDTSC executed.
  // 0x2024c 48 8d 15 05 7c 01 00 authentic 28th LEA RDX,[RIP+0x17c05]
  //        rebased original source ELF VA 0x37e58 executed.
  // 0x20253 48 89 05 06 78 01 00 authentic 29th MOV RW guest not executed.
  constexpr std::array<uint8_t,c7ac::kNextInstructionOffset+1> kOriginal116{
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
    0x41,0xb8,0xff,0xff,0xff,0x6f,
    0x41,0xb9,0x29,0x00,0x00,0x70,
    0x48,0xc1,0xe2,0x20,
    0x48,0x89,0x0d,0x6a,0x88,0x01,0x00,
    0x49,0x89,0xce,
    0x48,0x09,0xd0,
    0x48,0x8d,0x15,0x05,0x7c,0x01,0x00,
    0x48};
  static_assert(kOriginal116.size()==c7ac::kNextInstructionOffset+1);
  const auto* source116=staged.GuestReadOnlyBytes(
      1,originalTarget,kOriginal116.size());
  if(!source116 ||
      std::memcmp(source116,kOriginal116.data(),kOriginal116.size())!=0) {
    std::fprintf(stderr,
      "C3D7AC_SOURCE_TARGET_NOT_WHITELISTED first5=%02x%02x%02x%02x%02x\n",
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
  targetByte[c7ac::kNextInstructionOffset]=c7ac::kInjectedHLT;
  if(::mprotect(reinterpret_cast<void*>(
       static_cast<uintptr_t>(targetPage)),4096,PROT_READ|PROT_EXEC)!=0)
    return 15;
  if(c7ac::RightsAt(originalRIP)!="r-xp" ||
     c7ac::RightsAt(originalTarget)!="r-xp" ||
     targetByte[c7ac::kNextInstructionOffset]!=c7ac::kInjectedHLT ||
      std::memcmp(targetByte,kOriginal116.data(),c7ac::kNextInstructionOffset)!=0 ||
     std::memcmp(sourceEntry,call.originalEntryBytes.data(),c7ac::kOriginalTwoOpcodesBytes)!=0)
    return 16;

  // Use source-backed authentic LEA displacement from instruction bytes
  // (target + 8) and actual rebased guest RIP. No synthetic address.
  std::int32_t leaDisp=0;
  std::memcpy(&leaDisp,call.originalTargetBytes.data()+8,sizeof(leaDisp));
  const uint64_t leaNextRIP=originalTarget+c7ac::kOriginalFifthEndOffset;
  const uint64_t expectedLEAResult=
      leaNextRIP+static_cast<uint64_t>(static_cast<int64_t>(leaDisp));
  if(expectedLEAResult!=staged.Module(1)->loadBias)return 37;
  // Sixth authentic LEA RAX signed displacement at original +15.
  std::int32_t sixthDisp=0;
  std::memcpy(&sixthDisp,kOriginal116.data()+15,sizeof(sixthDisp));
  const uint64_t expectedRAX=
      originalTarget+c7ac::kOriginalSixthEndOffset+
      static_cast<uint64_t>(static_cast<int64_t>(sixthDisp));
  if(expectedRAX!=staged.Module(1)->loadBias+uint64_t{0x392d8})
    return 38;
  // Independently derive both new RIP-relative data addresses from
  // source-backed signed disp32 encodings, not hand-selected pointers.
  std::int32_t andRel=0, leaRSIRel=0;
  std::memcpy(&andRel,kOriginal116.data()+c7ac::kOriginalTwentiethStartOffset+2,sizeof(andRel));
  std::memcpy(&leaRSIRel,kOriginal116.data()+c7ac::kOriginalTwentyFirstStartOffset+3,sizeof(leaRSIRel));
  const uint64_t guestANDAt=originalTarget+c7ac::kOriginalTwentyFirstStartOffset+
      static_cast<uint64_t>(static_cast<int64_t>(andRel));
  const uint64_t expectedRSI=originalTarget+c7ac::kOriginalTwentyFirstStartOffset+
      c7ac::kOriginalTwentyFirstLEABytes+
      static_cast<uint64_t>(static_cast<int64_t>(leaRSIRel));
  if(guestANDAt!=staged.Module(1)->loadBias+uint64_t{0x38e06} ||
     expectedRSI!=staged.Module(1)->loadBias+uint64_t{0x38af0} ||
     c7ac::RightsAt(guestANDAt)!="rw-p" ||
     c7ac::RightsAt(expectedRSI)=="unmapped")return 40;
  // Source-original 28th RIP-relative LEA independently verified
  // against its OWN next RIP (+115), not the 25th MOV next RIP (+102).
  std::int32_t source28LEARDXRel=0;
  std::memcpy(&source28LEARDXRel,kOriginal116.data()+
       c7ac::kOriginalTwentyEighthStartOffset+3,sizeof(source28LEARDXRel));
  const uint64_t expectedRDX=
       originalTarget+c7ac::kNextInstructionOffset+
       static_cast<uint64_t>(static_cast<int64_t>(source28LEARDXRel));
  if(expectedRDX!=staged.Module(1)->loadBias+uint64_t{0x37e58} ||
     c7ac::RightsAt(expectedRDX)=="unmapped")return 49;
  // Authenticate 25th original MOV [RIP+disp32],RCX from the actual
  // immutably sourced opcodes. This is an 8-byte RW guest write, not
  // an injected test instruction. Its original ELF VA is 0x38ab0.
  std::int32_t movRWRel=0;
  std::memcpy(&movRWRel,kOriginal116.data()+
     c7ac::kOriginalTwentyFifthStartOffset+3,sizeof(movRWRel));
  const uint64_t guestQWORDAt=
      originalTarget+c7ac::kOriginalTwentyFifthEndOffset+
      static_cast<uint64_t>(static_cast<int64_t>(movRWRel));
  if(guestQWORDAt!=staged.Module(1)->loadBias+uint64_t{0x38ab0} ||
     guestQWORDAt+sizeof(uint64_t)>staged.Module(1)->loadBias+uint64_t{0x39000} ||
     c7ac::RightsAt(guestQWORDAt)!="rw-p" ||
     c7ac::RightsAt(guestQWORDAt+sizeof(uint64_t)-1)!="rw-p" ||
     (guestANDAt>=guestQWORDAt && guestANDAt<guestQWORDAt+sizeof(uint64_t)))
    return 44;
  const auto* guestQWORDBytes=reinterpret_cast<const void*>(
      static_cast<uintptr_t>(guestQWORDAt));
  std::array<uint8_t,8> originalGuestQWORDBytes{};
  std::memcpy(originalGuestQWORDBytes.data(),guestQWORDBytes,
              originalGuestQWORDBytes.size());
  constexpr uint64_t guestQWORDSentinel=0x5a4b45524e495858ULL;
  if(guestQWORDSentinel==expectedLEAResult)return 45;
  std::memcpy(reinterpret_cast<void*>(static_cast<uintptr_t>(guestQWORDAt)),
     &guestQWORDSentinel,sizeof(guestQWORDSentinel));
  uint64_t seededQWORD=0;
  std::memcpy(&seededQWORD,guestQWORDBytes,sizeof(seededQWORD));
  if(seededQWORD!=guestQWORDSentinel)return 46;
  // Change only one bit of one RW byte in our disposable guest VMA,
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
  // before any FEX execution. MOVAPS must be 16-byte aligned.
  if((originalRSP & uint64_t{15})!=0 ||
     originalRSP<c7ac::kGuestStackBytes ||
     c7ac::RightsAt(originalRSP-c7ac::kGuestStackBytes)!="rw-p" ||
     c7ac::RightsAt(originalRSP-1)!="rw-p")return 33;
  std::array<uint8_t,c7ac::kGuestStackBytes> originalGuestStackBytes{};
  std::memcpy(originalGuestStackBytes.data(),
    reinterpret_cast<const void*>(static_cast<uintptr_t>(
      originalRSP-c7ac::kGuestStackBytes)),
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
  c7ac::OriginalFEXGuardedCallRetStack callret;
  if(!callret.Reserve())return 17;
  auto ctx=FEXCore::Context::Context::CreateNewContext(host);
  if(!ctx)return 17;
  FEXCore::SignalDelegator signals{};
  c7ac::DenyAllGuestSyscalls deny{originalRIP,originalTarget};
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
  constexpr uint64_t r9Witness=0x4b45524e49583939ULL;
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
  cpu.gregs[FEXCore::X86State::REG_R9]=r9Witness;
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
  std::fputs("KERNIX_C3D7AC_BEGIN_TWENTYEIGHT_REAL_ORIGINAL_LDSO_R14_OR_TSC_LEA_RDX_FEX_EXECUTETHREAD\n",stderr);
  std::fflush(stderr);
  ctx->ExecuteThread(thread);
  const uint64_t postRIP=cpu.rip;
  // 27th source-original OR merges guest RDTSC EAX low with EDX
  // shifted by source 24th. 28th LEA subsequently overwrites RDX.
  const uint64_t guestTSC=cpu.gregs[FEXCore::X86State::REG_RAX];
  const uint64_t sourceR14=cpu.gregs[FEXCore::X86State::REG_R14];
  const uint64_t sourceRDX=cpu.gregs[FEXCore::X86State::REG_RDX];
  const bool sourceNewGPRProof=
      sourceR14==expectedLEAResult && sourceR14!=r14Witness &&
      sourceRDX==expectedRDX && sourceRDX!=rdxWitness &&
      guestTSC!=0 && guestTSC!=expectedRAX &&
      cpu.gregs[FEXCore::X86State::REG_R8]==0x6fffffffULL &&
      cpu.gregs[FEXCore::X86State::REG_R9]==0x70000029ULL &&
      cpu.gregs[FEXCore::X86State::REG_R8]!=r8Witness &&
      cpu.gregs[FEXCore::X86State::REG_R9]!=r9Witness;
  uint64_t postGuestQWORD=0;
  std::memcpy(&postGuestQWORD,guestQWORDBytes,sizeof(postGuestQWORD));
  const bool sourceTwentyFifthMOVRWQWORDProven=
      postGuestQWORD==expectedLEAResult &&
      postGuestQWORD!=guestQWORDSentinel;
  const uint8_t postANDByte=*guestANDByte;
  const bool originalRWDataUpdatedCorrectly=
      postANDByte==expectedGuestANDByte &&
      postANDByte!=guestANDSeed;
  // Source-order witness slots: guest stack grows down eight bytes
  // for each original CALL/PUSH. Verify by actual copied guest bytes.
  std::array<uint64_t,c7ac::kGuestSavedSlotCount> saved{};
  if(c7ac::RightsAt(originalRSP-c7ac::kGuestStackBytes)!="rw-p" ||
     c7ac::RightsAt(originalRSP-1)!="rw-p")return 21;
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
  const uint64_t localRDIAt=originalRSP-16-c7ac::kLocalAreaBytes;
  const uint64_t localXMMAt=originalRSP-16-0x80;
  if((localXMMAt&uint64_t{15})!=0 ||
     c7ac::RightsAt(localRDIAt)!="rw-p" ||
     c7ac::RightsAt(localXMMAt)!="rw-p")return 39;
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
     cpu.gregs[FEXCore::X86State::REG_RSP]!=originalRSP-c7ac::kGuestStackBytes ||
     !localsMatch ||
     cpu.gregs[FEXCore::X86State::REG_RBP]!=originalRSP-16 ||
     cpu.gregs[FEXCore::X86State::REG_R15]!=r15Witness ||
     cpu.gregs[FEXCore::X86State::REG_R14]!=expectedLEAResult ||
     cpu.gregs[FEXCore::X86State::REG_R14]==r14Witness ||
     cpu.gregs[FEXCore::X86State::REG_R13]!=r13Witness ||
     cpu.gregs[FEXCore::X86State::REG_R12]!=r12Witness ||
     cpu.gregs[FEXCore::X86State::REG_RBX]!=rbxWitness ||
     cpu.gregs[FEXCore::X86State::REG_RBP]==rbpWitness ||
     cpu.gregs[FEXCore::X86State::REG_RCX]!=expectedLEAResult ||
     cpu.gregs[FEXCore::X86State::REG_RCX]==rcxWitness ||
     !sourceNewGPRProof ||
     !originalRWDataUpdatedCorrectly ||
     !sourceTwentyFifthMOVRWQWORDProven ||
     cpu.gregs[FEXCore::X86State::REG_RSI]!=expectedRSI ||
     cpu.gregs[FEXCore::X86State::REG_RSI]==rsiWitness ||
     cpu.gregs[FEXCore::X86State::REG_R8]!=0x6fffffffULL ||
     cpu.gregs[FEXCore::X86State::REG_R9]!=0x70000029ULL ||
     cpu.xmm.sse.data[1][0]!=expectedLEAResult ||
     cpu.xmm.sse.data[1][0]==xmm1LowWitness ||
     cpu.xmm.sse.data[1][1]!=expectedRAX ||
     cpu.xmm.sse.data[1][1]==xmm1HighWitness ||
     cpu.xmm.sse.data[2][0]!=expectedRAX ||
     cpu.xmm.sse.data[2][0]==xmm2LowWitness ||
     cpu.xmm.sse.data[2][1]!=0 ||
     !stackWitnessesMatch ||
     (postRIP!=originalTarget+c7ac::kNextInstructionOffset &&
      postRIP!=originalTarget+c7ac::kNextInstructionOffset+1)) {
    std::fprintf(stderr,
      "C3D7AC_SIMD_DIAG xmm1lo=%llx expected=%llx xmm1hi=%llx xmm2lo=%llx xmm2hi=%llx\\n",
      static_cast<unsigned long long>(cpu.xmm.sse.data[1][0]),
      static_cast<unsigned long long>(expectedLEAResult),
      static_cast<unsigned long long>(cpu.xmm.sse.data[1][1]),
      static_cast<unsigned long long>(cpu.xmm.sse.data[2][0]),
      static_cast<unsigned long long>(cpu.xmm.sse.data[2][1]));
    std::fprintf(stderr,
      "C3D7AC_RIPREL_DIAG post=%llx stop=%llx rax=%llx expectedRAX=%llx rcx=%llx expectedRCX=%llx\n",
      static_cast<unsigned long long>(postRIP),
      static_cast<unsigned long long>(originalTarget+c7ac::kNextInstructionOffset),
      static_cast<unsigned long long>(cpu.gregs[FEXCore::X86State::REG_RAX]),
      static_cast<unsigned long long>(expectedRAX),
      static_cast<unsigned long long>(cpu.gregs[FEXCore::X86State::REG_RCX]),
      static_cast<unsigned long long>(expectedLEAResult));
    std::fprintf(stderr,
      "C3D7AC_TWENTY_FIFTH_RW_QWORD_DIAG guestVA=%llx post=%llx expectedRCX=%llx seed=%llx ok=%d\n",
      static_cast<unsigned long long>(guestQWORDAt),
      static_cast<unsigned long long>(postGuestQWORD),
      static_cast<unsigned long long>(expectedLEAResult),
      static_cast<unsigned long long>(guestQWORDSentinel),
      int(sourceTwentyFifthMOVRWQWORDProven));
    std::fprintf(stderr,
      "C3D7AC_GUEST_LDSO_RW_DATA_DIAG guestVA=%llx original=%02x seed=%02x post=%02x expected=%02x good=%d rsi=%llx wantedRSI=%llx\n",
      static_cast<unsigned long long>(guestANDAt),
      unsigned(originalGuestANDByte),unsigned(guestANDSeed),
      unsigned(postANDByte),unsigned(expectedGuestANDByte),
      int(originalRWDataUpdatedCorrectly),
      static_cast<unsigned long long>(cpu.gregs[FEXCore::X86State::REG_RSI]),
      static_cast<unsigned long long>(expectedRSI));
    std::fprintf(stderr,
      "C3D7AC_26TO28_REGISTER_DIAG r14=%llx wanted=%llx rdx=%llx wanted=%llx tsc=%llx proof=%d\n",
      static_cast<unsigned long long>(sourceR14),
      static_cast<unsigned long long>(expectedLEAResult),
      static_cast<unsigned long long>(sourceRDX),
      static_cast<unsigned long long>(expectedRDX),
      static_cast<unsigned long long>(guestTSC),int(sourceNewGPRProof));
    std::fprintf(stderr,
      "C3D7AC_LOCAL_FRAME_DIAG ok=%d rdi=%llx wanted=%llx xmmlo=%llx wantedlo=%llx xmmhi=%llx wantedhi=%llx\n",
      int(localsMatch),
      static_cast<unsigned long long>(storedRDI),
      static_cast<unsigned long long>(originalRSP),
      static_cast<unsigned long long>(storedXMM[0]),
      static_cast<unsigned long long>(expectedLEAResult),
      static_cast<unsigned long long>(storedXMM[1]),
      static_cast<unsigned long long>(expectedRAX));
    std::fprintf(stderr,
      "C3D7AC_MULTI_PUSH_DIAG match=%d rsp=%llx expected=%llx "
      "slots_ret_rbp_r15_r14_r13_r12_rbx=%llx,%llx,%llx,%llx,%llx,%llx,%llx\n",
      int(stackWitnessesMatch),
      static_cast<unsigned long long>(cpu.gregs[FEXCore::X86State::REG_RSP]),
      static_cast<unsigned long long>(originalRSP-c7ac::kGuestStackBytes),
      static_cast<unsigned long long>(saved[0]),
      static_cast<unsigned long long>(saved[1]),
      static_cast<unsigned long long>(saved[2]),
      static_cast<unsigned long long>(saved[3]),
      static_cast<unsigned long long>(saved[4]),
      static_cast<unsigned long long>(saved[5]),
      static_cast<unsigned long long>(saved[6]));
    std::fprintf(stderr,
      "C3D7AC_POST_PUSH_STATE_REJECT src=%llx dst=%llx post=%llx rsp=%llx rdi=%llx ret=%llx expected=%llx\n",
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
  if(::mprotect(reinterpret_cast<void*>(
       static_cast<uintptr_t>(targetPage)),4096,PROT_READ|PROT_WRITE)!=0)
    return 22;
  targetByte[c7ac::kNextInstructionOffset]=kOriginal116[c7ac::kNextInstructionOffset];
  if(::mprotect(reinterpret_cast<void*>(
       static_cast<uintptr_t>(targetPage)),4096,PROT_READ|PROT_EXEC)!=0)
    return 23;
  // Restore the authentic 25th MOV's complete guest RW qword before
  // checking all source PT_LOAD and original guest stack snapshots.
  if(c7ac::RightsAt(guestQWORDAt)!="rw-p" ||
     c7ac::RightsAt(guestQWORDAt+sizeof(uint64_t)-1)!="rw-p")return 47;
  std::memcpy(reinterpret_cast<void*>(static_cast<uintptr_t>(guestQWORDAt)),
      originalGuestQWORDBytes.data(),originalGuestQWORDBytes.size());
  if(std::memcmp(guestQWORDBytes,originalGuestQWORDBytes.data(),
                 originalGuestQWORDBytes.size())!=0)return 48;
  // Restore the only originally staged writable ELF data byte after
  // the real x86 guest update, BEFORE source-backed byte restoration gate.
  if(c7ac::RightsAt(guestANDAt)!="rw-p")return 42;
  *guestANDByte=originalGuestANDByte;
  if(*guestANDByte!=originalGuestANDByte)return 43;
  if(c7ac::RightsAt(originalRIP)!="r-xp" ||
     c7ac::RightsAt(originalTarget)!="r-xp" ||
     std::memcmp(sourceEntry,call.originalEntryBytes.data(),16)!=0 ||
     std::memcmp(targetByte,kOriginal116.data(),kOriginal116.size())!=0 ||
     !c7ac::OriginalFileBackedBytesRestored(original,staged) ||
     staged.WindowsHeld()!=4)return 24;
  // Restore 192 bytes including new local area and all saved registers.
  if(c7ac::RightsAt(originalRSP-c7ac::kGuestStackBytes)!="rw-p" ||
     c7ac::RightsAt(originalRSP-1)!="rw-p")return 35;
  std::memcpy(reinterpret_cast<void*>(static_cast<uintptr_t>(
      originalRSP-c7ac::kGuestStackBytes)),
      originalGuestStackBytes.data(),originalGuestStackBytes.size());
  if(std::memcmp(reinterpret_cast<const void*>(
      static_cast<uintptr_t>(originalRSP-c7ac::kGuestStackBytes)),
      originalGuestStackBytes.data(),originalGuestStackBytes.size())!=0)return 36;
  // Destroy FEX context/thread while its call-ret map remains
  // alive; then release that host-only stack and the original VMAs.
  ctx.reset();
  if(!callret.Release())return 25;
  if(!staged.Release() || staged.WindowsHeld()!=0)return 26;
  std::puts(
    "KERNIX_G2EC3D7AC_SOURCE_PINNED_FEX_TWENTYEIGHT_REAL_ORIGINAL_LDSO_R14_OR_TSC_LEA_RDX_LINUX_ARM64_PASS"
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
    " original_seventh_movq_xmm1_rcx_executed=1"
    " xmm1_low_qword_equals_original_rebased_rcx=1"
    " original_eighth_movq_xmm2_rax_executed=1"
    " xmm2_low_qword_equals_original_rebased_rax=1"
    " xmm2_high_qword_zeroed=1"
    " original_ninth_punpcklqdq_xmm1_xmm2_executed=1"
    " original_ninth_xmm1_upper64_equals_rebased_rax=1"
    " original_ninth_xmm1_lower64_equals_rebased_rcx=1"
    " original_ninth_xmm2_preserved=1"
    " original_tenth_mov_rbp_rsp_executed=1"
    " guest_frame_pointer_rbp_equals_post_push_rsp=1"
    " original_pushed_rbp_witness_retained_on_stack=1"
    " original_eleventh_push_r15_executed=1"
    " original_twelfth_push_r14_executed=1"
    " original_thirteenth_push_r13_executed=1"
    " original_fourteenth_push_r12_executed=1"
    " original_fifteenth_push_rbx_executed=1"
    " all_five_original_gpr_witnesses_saved_in_exact_guest_stack_order=1"
    " original_ret_rbp_and_five_push_guest_stack_slots_verified=1"
    " guest_rsp_decremented_by_fifty_six_bytes=1"
    " original_sixteenth_sub_rsp_0x88_executed=1"
    " original_seventeenth_mov_stack_local_rdi_executed=1"
    " original_eighteenth_movaps_stack_local_xmm1_executed=1"
    " guest_stack_local_original_rdi_source_value_verified=1"
    " guest_stack_local_original_xmm1_low_high_64_verified=1"
    " movaps_guest_store_16byte_alignment_verified=1"
    " guest_final_rsp_equals_original_rsp_minus_192=1"
    " original_nineteenth_rdtsc_executed=1"
    " original_rdtsc_eax_edx_combined_by_original_or_rax_rdx=1"
    " combined_guest_tsc_nonzero=1"
    " original_local_stack_memory_preserved_after_rdtsc=1"
    " original_twentieth_and_guest_ldso_rw_data_executed=1"
    " original_twentieth_and_source_derived_guest_rw_va=1"
    " original_twentieth_and_bit5_cleared_other_bits_preserved=1"
    " original_twentieth_guest_rw_source_byte_restored=1"
    " original_twenty_first_lea_rsi_source_pointer_executed=1"
    " original_twenty_first_rsi_rebased_ldso_va_verified=1"
    " original_twenty_second_mov_r8d_source_immediate_executed=1"
    " original_twenty_third_mov_r9d_source_immediate_executed=1"
    " original_twenty_fourth_shl_rdx_32_from_rdtsc_executed=1"
    " original_twenty_fifth_mov_guest_rw_qword_source_rcx_executed=1"
    " original_twenty_fifth_guest_rw_qword_post_equals_rebased_source_rcx=1"
    " original_twenty_fifth_guest_rw_qword_original_eight_bytes_restored=1"
    " original_twenty_sixth_mov_r14_rcx_executed=1"
    " original_twenty_sixth_r14_equals_rebased_ldso_base=1"
    " original_twenty_seventh_or_rax_rdx_executed=1"
    " original_twenty_seventh_rax_contains_combined_rdtsc=1"
    " original_twenty_eighth_lea_rdx_riprel_executed=1"
    " original_twenty_eighth_rdx_equals_source_rebased_0x37e58=1"
    " original_twenty_ninth_mov_guest_rw_replaced_by_bounded_hlt=1"
    " original_twenty_ninth_mov_guest_rw_executed=0"
    " guest_stack_original_192_bytes_restored=1"
    " unmodified_original_twentyeight_instructions_executed=1"
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
