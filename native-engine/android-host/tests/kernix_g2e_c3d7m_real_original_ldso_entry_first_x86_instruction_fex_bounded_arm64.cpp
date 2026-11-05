// SPDX-License-Identifier: MIT
// KERNIX C3-D7M: Linux ARM64 bounded REAL ORIGINAL source-pinned
// x86_64 ld-linux PT_INTERP e_entry FIRST machine instruction executed
// by unchanged upstream FEXCore. Instruction #2 is replaced with an
// injected HLT byte in an original-owned anonymous guest staging VMA.
// Source ELF snapshots never modified; one guest byte restored and
// ALL three original file-backed PT_LOAD byte sequences verified.
// This does NOT start ld-linux, relocate ELF, handle Linux syscalls,
// initialize actual TLS/IFUNC or execute Windows games.
// Real Linux ARM64 CI ONLY; no Android handset runtime claim.
#define main kernix_c3d7m_c2_source_reference_main
#include "kernix_g2e_c2_original_fex_actual_syscall_trap_arm64.cpp"
#undef main
#include "kernix_g2e_c3d7e_original_ldso_entry_rx_ownership.h"
#include "kernix_g2e_c3d7g_native_pt_load_wx_apply_gate.h"
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
#error C3D7M executes original ld-linux first x86 instruction Linux ARM64 CI only
#endif
namespace m=kernix::g2e;
namespace b=kernix::g2e::c3d7b;
namespace e=kernix::g2e::c3d7e;
namespace g=kernix::g2e::c3d7g;
namespace c7m {
static constexpr size_t kSourceBytes=16;
static constexpr size_t kFirstOpcodeBytes=3;
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
  explicit DenyAllGuestSyscalls(uint64_t rip):rip_(rip){}
  void HandleSyscall(FEXCore::Core::CpuStateFrame*) override {
    std::fputs("KERNIX_C3D7M_UNEXPECTED_GUEST_SYSCALL_DENIED\n",stderr);
    std::fflush(stderr);
    _exit(94);
  }
  FEXCore::HLE::ExecutableRangeInfo QueryGuestExecutableRange(
       FEXCore::Core::InternalThreadState*,uint64_t query) override {
    if(query>=rip_ && query<rip_+kSourceBytes)
      return {rip_,kSourceBytes,false};
    return {0,0,false};
  }
  std::optional<FEXCore::ExecutableFileSectionInfo>
  LookupExecutableFileSection(
       FEXCore::Core::InternalThreadState*,uint64_t) override {
    return std::nullopt;
  }
private:
  uint64_t rip_;
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
} // namespace c7m

int main(int argc,char** argv) {
  if(argc!=2 || !argv[1])return 2;
  if(::sysconf(_SC_PAGESIZE)!=4096)return 3;
  const int fd=::open(argv[1],O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
  if(fd<0)return 4;
  m::GuestPreflight original;
  std::string why;
  if(!m::Validate(fd,original,why)) {
    std::fprintf(stderr,"C3D7M_ORIGINAL_SOURCE_SHA256_DENIED %s\n",why.c_str());
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
  const auto* sourceEntry=staged.GuestReadOnlyBytes(
      1,originalRIP,c7m::kSourceBytes);
  if(!sourceEntry)return 9;
  std::array<uint8_t,c7m::kSourceBytes> originalSourceBytes{};
  std::memcpy(originalSourceBytes.data(),sourceEntry,
              originalSourceBytes.size());
  // Source-verified glibc ld-linux first instruction:
  // 48 89 e7 = mov %rsp,%rdi. If original bytes differ,
  // FAIL CLOSED rather than guessing x86 instruction length.
  if(originalSourceBytes[0]!=0x48 || originalSourceBytes[1]!=0x89 ||
     originalSourceBytes[2]!=0xe7 || originalSourceBytes[3]!=0xe8) {
    std::fprintf(stderr,
      "C3D7M_FIRST_SOURCE_OPCODE_NOT_WHITELISTED "
      "first8=%02x%02x%02x%02x%02x%02x%02x%02x\n",
      originalSourceBytes[0],originalSourceBytes[1],
      originalSourceBytes[2],originalSourceBytes[3],
      originalSourceBytes[4],originalSourceBytes[5],
      originalSourceBytes[6],originalSourceBytes[7]);
    return 10;
  }
  if((originalRIP&4095)>4096-c7m::kSourceBytes)return 11;
  g::ApplyWitness nativePages;
  if(!g::ApplyOwnedOriginalPTLoadPagePermissions(
       staged,original,nativePages) ||
     !nativePages.originalPinnedSourceValidated ||
     !nativePages.nativeNoWritableExecutablePage ||
     !nativePages.nativeNonPTLoadHolesDenied ||
     !nativePages.nativeStackGuardDenied ||
     nativePages.originalModulesProtected!=3)
    return 12;
  if(c7m::RightsAt(originalRIP)!="r-xp" ||
     c7m::RightsAt(originalRSP)!="rw-p")
    return 13;

  // Only the following x86 opcode is HLT; first authentic bytes
  // and the original guest entry RIP stay unchanged. On any stage,
  // no native page simultaneously has write AND execute rights.
  const uint64_t page=originalRIP&~uint64_t(4095);
  auto* entry=reinterpret_cast<unsigned char*>(
      static_cast<uintptr_t>(originalRIP));
  if(::mprotect(reinterpret_cast<void*>(
       static_cast<uintptr_t>(page)),4096,PROT_READ|PROT_WRITE)!=0)
    return 14;
  entry[c7m::kFirstOpcodeBytes]=c7m::kInjectedHLT;
  if(::mprotect(reinterpret_cast<void*>(
       static_cast<uintptr_t>(page)),4096,PROT_READ|PROT_EXEC)!=0)
    return 15;
  if(c7m::RightsAt(originalRIP)!="r-xp" ||
     std::memcmp(entry,originalSourceBytes.data(),
                 c7m::kFirstOpcodeBytes)!=0 ||
     entry[c7m::kFirstOpcodeBytes]!=c7m::kInjectedHLT)
    return 16;

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
  auto ctx=FEXCore::Context::Context::CreateNewContext(host);
  if(!ctx)return 17;
  FEXCore::SignalDelegator signals{};
  c7m::DenyAllGuestSyscalls deny{originalRIP};
  ctx->SetSignalDelegator(&signals);
  ctx->SetSyscallHandler(&deny);
  ctx->EnableExitOnHLT();
  if(!ctx->InitCore())return 18;
  auto* thread=ctx->CreateThread();
  if(!thread || !thread->CurrentFrame)return 19;
  FEXCore::Core::CPUState::gdt_segment gdt[32]{};
  auto& cpu=thread->CurrentFrame->State;
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
  cpu.rip=originalRIP;
  cpu.gregs[FEXCore::X86State::REG_RSP]=originalRSP;
  cpu.gregs[FEXCore::X86State::REG_RDI]=sentinel;
  cpu.fs_cached=0;cpu.gs_cached=0;
  if(cpu.rip!=originalRIP ||
     cpu.gregs[FEXCore::X86State::REG_RSP]!=originalRSP ||
     cpu.gregs[FEXCore::X86State::REG_RDI]!=sentinel)
    return 20;
  std::fputs("KERNIX_C3D7M_BEGIN_REAL_ORIGINAL_LDSO_FIRST_INSTRUCTION_FEX_EXECUTETHREAD\n",stderr);
  std::fflush(stderr);
  ctx->ExecuteThread(thread);
  const uint64_t postRIP=cpu.rip;
  if(cpu.gregs[FEXCore::X86State::REG_RDI]!=originalRSP ||
     cpu.gregs[FEXCore::X86State::REG_RDI]==sentinel ||
     cpu.gregs[FEXCore::X86State::REG_RSP]!=originalRSP ||
     (postRIP!=originalRIP+c7m::kFirstOpcodeBytes &&
      postRIP!=originalRIP+c7m::kFirstOpcodeBytes+1)) {
    std::fprintf(stderr,
      "C3D7M_EXECUTION_POSTSTATE_FAIL original=%llx rip=%llx rsp=%llx rdi=%llx\n",
      static_cast<unsigned long long>(originalRIP),
      static_cast<unsigned long long>(postRIP),
      static_cast<unsigned long long>(
        cpu.gregs[FEXCore::X86State::REG_RSP]),
      static_cast<unsigned long long>(
        cpu.gregs[FEXCore::X86State::REG_RDI]));
    return 21;
  }
  if(::mprotect(reinterpret_cast<void*>(
       static_cast<uintptr_t>(page)),4096,PROT_READ|PROT_WRITE)!=0)
    return 22;
  entry[c7m::kFirstOpcodeBytes]=
      originalSourceBytes[c7m::kFirstOpcodeBytes];
  if(::mprotect(reinterpret_cast<void*>(
       static_cast<uintptr_t>(page)),4096,PROT_READ|PROT_EXEC)!=0)
    return 23;
  if(c7m::RightsAt(originalRIP)!="r-xp" ||
     std::memcmp(entry,originalSourceBytes.data(),
                 originalSourceBytes.size())!=0 ||
     !c7m::OriginalFileBackedBytesRestored(original,staged) ||
     staged.WindowsHeld()!=4)return 24;
  if(!staged.Release() || staged.WindowsHeld()!=0)return 25;
  std::puts(
    "KERNIX_G2EC3D7M_SOURCE_PINNED_FEX_REAL_ORIGINAL_LDSO_ENTRY_FIRST_X86_MOV_RSP_RDI_LINUX_ARM64_PASS"
    " original_three_sha256_locked=1"
    " original_ldso_source_first_three_bytes_unchanged=1"
    " original_ldso_rebased_entry_RIP_entered_in_ExecuteThread=1"
    " original_x86_mov_rsp_to_rdi_executed=1"
    " original_x86_guest_stack_RSP_preserved=1"
    " second_instruction_replaced_with_bounded_HLT=1"
    " original_pinned_elf_source_snapshots_never_modified=1"
    " all_three_original_guest_file_PTLOAD_bytes_restored=1"
    " genuine_native_PTLOAD_WX_permissions_used=1"
    " no_guest_linux_syscalls_forwarded=1"
    " native_guest_windows_released=1"
    " complete_dynamic_linker_startup=0"
    " relocations_ifunc_tls_completed=0"
    " android_device=0 wine=0");
  return 0;
}
