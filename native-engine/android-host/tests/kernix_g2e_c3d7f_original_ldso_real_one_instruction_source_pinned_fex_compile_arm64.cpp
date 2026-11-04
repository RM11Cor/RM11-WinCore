// SPDX-License-Identifier: MIT
// C3-D7F: source-pinned upstream FEXCore executes actual x86-64 instructions
// with data addresses that are also the Linux kernel-chosen *rebased guest*
// PIE main-ELF and original Linux x86-64 initial AUXV stack VAs.
// Linux ARM64 bounded *one original ld-linux instruction FEX compile* gate.
// Original guest RIP is passed to JIT CompileRIPCount(max=1), but guest code
// is NOT EXECUTED. No ld-linux init/syscalls, Wine, Windows or Android proof.
#define main kernix_c3d7f_c2_source_reference_main
#include "kernix_g2e_c2_original_fex_actual_syscall_trap_arm64.cpp"
#undef main
#include "kernix_g2e_c3d7e_original_ldso_entry_rx_ownership.h"
// Audit ONLY source-pinned FEX code cache to distinguish actual JIT code
// emission from a void CompileRIPCount() API returning without a block.
#include "Interface/Core/LookupCache.h"
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <limits>
#include <optional>
#include <sys/mman.h>
#include <unistd.h>
#if !defined(__aarch64__) || !defined(KERNIX_G2EC2_ORIGINAL_FEX_LINUX_ARM64_CI)
#error C3-D7F actual source-pinned original FEX runs on Linux AArch64
#endif
namespace c7f {
// Source comes from the real original ld-linux ELF file-backed entry.
// Never generate synthetic x86 instructions for this gate.
inline constexpr size_t kOriginalEntryFetchBytes=16;
class NativePage final {
  void* owned_=MAP_FAILED;
  size_t bytes_=0;
public:
  NativePage()=default;
  NativePage(const NativePage&)=delete;
  NativePage& operator=(const NativePage&)=delete;
  ~NativePage(){ if(owned_!=MAP_FAILED) ::munmap(owned_,bytes_); }
  bool Create(uintptr_t hint,size_t n,int permissions) noexcept {
    if(owned_!=MAP_FAILED || !n)return false;
    void* p=::mmap(reinterpret_cast<void*>(hint),n,permissions,
                   MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    if(p==MAP_FAILED)return false;
    if(!kernix::g2e::c1::GuestRange(
        reinterpret_cast<uintptr_t>(p),n)) {
      ::munmap(p,n);return false;
    }
    owned_=p;bytes_=n;
    return true;
  }
  void* get() const noexcept {
    return owned_==MAP_FAILED?nullptr:owned_;
  }
  uintptr_t base() const noexcept {
    return reinterpret_cast<uintptr_t>(get());
  }
};
class NoSyscall final : public FEXCore::HLE::SyscallHandler {
public:
  explicit NoSyscall(uintptr_t base):code_(base){}
  void HandleSyscall(FEXCore::Core::CpuStateFrame*) override {
    std::fputs("KERNIX_C3D7F_UNEXPECTED_GUEST_SYSCALL_DENIED\n",stderr);
    _exit(94);
  }
  FEXCore::HLE::ExecutableRangeInfo QueryGuestExecutableRange(
      FEXCore::Core::InternalThreadState*,uint64_t guestVA) override {
    if(guestVA>=code_ && guestVA<code_+kOriginalEntryFetchBytes)
      return {code_,kOriginalEntryFetchBytes,false};
    return {0,0,false};
  }
  std::optional<FEXCore::ExecutableFileSectionInfo>
  LookupExecutableFileSection(
      FEXCore::Core::InternalThreadState*,uint64_t) override {
    return std::nullopt;
  }
private:
  uintptr_t code_=0;
};
} // namespace c7f


int main(int argc,char** argv) {
  if(argc!=2 || !argv[1])return 2;
  if(::sysconf(_SC_PAGESIZE)!=4096)return 3;
  const int fd=::open(argv[1],O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
  if(fd<0)return 4;
  std::array<uint8_t,16> entropy{};
  for(size_t i=0;i<entropy.size();++i)
    entropy[i]=static_cast<uint8_t>(i+1);
  kernix::g2e::GuestPreflight source;
  std::string reason;
  if(!kernix::g2e::Validate(fd,source,reason)) {
    std::fprintf(stderr,"C3D7F_ORIGINAL_PINNED_ELFS_REJECTED %s\n",reason.c_str());
    ::close(fd);return 5;
  }
  kernix::g2e::c3d7b::NativeChosenPIEGuestLayout stage;
  kernix::g2e::c3d7b::Witness prepared;
  if(!stage.Stage(fd,entropy,prepared) ||
     !prepared.pinnedOriginalELFSHA256Verified ||
     !prepared.linuxAuxvRebased ||
     prepared.originalELFCodeExecuted || prepared.originalLdsoExecuted ||
     prepared.originalFEXGuestMemoryAttached ||
     prepared.nativeExecutablePageGranted ||
     prepared.phase!=kernix::g2e::c3d7b::Phase::Complete ||
     stage.WindowsHeld()!=4) {
    std::fprintf(stderr,"C3D7F_NATIVE_GUEST_VA_REBASE_FAILED phase=%s errno=%d\n",
      kernix::g2e::c3d7b::PhaseName(prepared.phase),prepared.failureErrno);
    ::close(fd);return 6;
  }
  ::close(fd);
  const auto* plan=stage.LaunchPlan();
  if(!plan || plan->guestInterpreterEntry!=prepared.originalInterpreterRebasedRIP ||
     plan->stack.guestRSP!=prepared.x86RebasedStackRSP)
    return 7;
  const uint64_t interpreterRIP=plan->guestInterpreterEntry;
  const uint64_t initialStackRSP=plan->stack.guestRSP;
  kernix::g2e::c3d7e::EntryProof ldso{};
  if(!kernix::g2e::c3d7e::VerifyOriginalGuestEntryAndTemporaryHostRX(
       stage,source,1,ldso) ||
     ldso.guestRIP!=interpreterRIP ||
     !ldso.instructionBytesMatchOriginalSource ||
     !ldso.nativeRORestored ||
     !ldso.entryIsInsideOriginalFileBackedRXSegment ||
     ldso.originalGuestInstructionsExecuted || ldso.fexGuestRIPAssigned)
    return 8;
  std::array<uint8_t,c7f::kOriginalEntryFetchBytes> originalBytes{};
  const auto* entry=stage.GuestReadOnlyBytes(
       1,interpreterRIP,originalBytes.size());
  if(!entry)return 9;
  std::memcpy(originalBytes.data(),entry,originalBytes.size());

  FEXCore::Config::Initialize();
  FEXCore::Config::Load();
  FEXCore::Config::ReloadMetaLayer();
  FEXCore::Config::Set(FEXCore::Config::CONFIG_IS64BIT_MODE,"1");
  FEXCore::Config::Set(FEXCore::Config::CONFIG_MAXINST,"1");
  if(!FEXCore::Config::GetConv<bool>(
     FEXCore::Config::CONFIG_IS64BIT_MODE).value_or(false))
    return 10;
  FEXCore::HostFeatures features{};
  features.DCacheLineLog2=4;
  features.ProcessFeatures.HostType=FEXCore::HostFeatures::HostTypeEnum::Linux;
  features.ProcessFeatures.Is64BitMode=1;
  features.ProcessPID=static_cast<uint32_t>(::getpid());
  features.CPUMIDRs.push_back(0);
  auto context=FEXCore::Context::Context::CreateNewContext(features);
  if(!context)return 11;
  FEXCore::SignalDelegator signals{};
  c7f::NoSyscall denySyscalls{static_cast<uintptr_t>(interpreterRIP)};
  context->SetSignalDelegator(&signals);
  context->SetSyscallHandler(&denySyscalls);
  context->EnableExitOnHLT();
  if(!context->InitCore())return 12;
  auto* thread=context->CreateThread();
  if(!thread || !thread->CurrentFrame)return 13;

  FEXCore::Core::CPUState::gdt_segment gdt[32]{};
  auto& cpu=thread->CurrentFrame->State;
  cpu.segment_arrays[
    FEXCore::Core::CPUState::SEGMENT_ARRAY_INDEX_GDT]=gdt;
  cpu.segment_arrays[
    FEXCore::Core::CPUState::SEGMENT_ARRAY_INDEX_LDT]=gdt;
  cpu.cs_idx=FEXCore::Core::CPUState::DEFAULT_USER_CS<<3;
  auto* seg=FEXCore::Core::CPUState::GetSegmentFromIndex(cpu,cpu.cs_idx);
  FEXCore::Core::CPUState::SetGDTBase(seg,0);
  FEXCore::Core::CPUState::SetGDTLimit(seg,0xFFFFF);
  seg->L=1;seg->D=0;cpu.cs_cached=0;
  cpu.rip=interpreterRIP;
  cpu.gregs[FEXCore::X86State::REG_RSP]=initialStackRSP;
  if(cpu.rip!=interpreterRIP ||
     cpu.gregs[FEXCore::X86State::REG_RSP]!=initialStackRSP)return 14;

  // This compiles original x86 machine-code bytes from the authentic
  // ld-linux PT_INTERP entry with max ONE instruction. It does NOT enter
  // ExecuteThread. Source-pinned FEX compilation may reject unsupported
  // original instructions; such a rejection is failure, not execution proof.
  std::fputs("KERNIX_C3D7F_ORIGINAL_LDSO_FIRST_INSTRUCTION_FEX_TRANSLATE_BEGIN\n",stderr);
  std::fflush(stderr);
  context->CompileRIPCount(thread,interpreterRIP,1);
  const uintptr_t compiledHostBlock=
    thread->LookupCache ?
       thread->LookupCache->FindBlock(thread,interpreterRIP) : 0;
  if(!compiledHostBlock) {
    std::fputs("KERNIX_C3D7F_ORIGINAL_LDSO_NO_COMPILED_HOST_BLOCK_FAIL_CLOSED\n",stderr);
    return 16;
  }
  std::fputs("KERNIX_C3D7F_ORIGINAL_LDSO_FIRST_INSTRUCTION_FEX_TRANSLATE_RETURNED\n",stderr);
  std::fflush(stderr);
  if(cpu.rip!=interpreterRIP ||
     cpu.gregs[FEXCore::X86State::REG_RSP]!=initialStackRSP ||
     std::memcmp(entry,originalBytes.data(),originalBytes.size())!=0 ||
     stage.WindowsHeld()!=4)
    return 15;
  // No explicit FEX guest-thread destruction here: context+thread lifetime
  // remains valid while owned original VMAs are alive. The OS destroys the
  // entire isolated CI process after the short 1-inst compile gate.
  // Avoid asserting that returning from CompileRIPCount means executing code.
  std::puts(
    "KERNIX_G2EC3D7F_SOURCE_PINNED_FEX_ORIGINAL_X86_LDSO_ONE_INSTRUCTION_JIT_TRANSLATION_LINUX_ARM64_PASS"
    " original_ldso_sha256=1 original_guest_ldso_RIP_in_file_backed_rx=1"
    " guest_RSP_original_startup_stack=1 original_entry_16_bytes_unchanged=1"
    " fex_CompileRIPCount_one_instruction_returned=1 original_ldso_RIP_host_JIT_cache_block_nonzero=1"
    " fex_ExecuteThread_called=0 original_ldso_entered=0"
    " original_guest_instruction_executed=0 android_runtime=0 wine=0");
  return 0;
}
