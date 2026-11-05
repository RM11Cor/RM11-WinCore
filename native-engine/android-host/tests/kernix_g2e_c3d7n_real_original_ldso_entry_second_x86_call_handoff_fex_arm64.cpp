// SPDX-License-Identifier: MIT
// KERNIX C3-D7N: Linux ARM64 bounded REAL ORIGINAL source-pinned
// x86_64 ld-linux PT_INTERP e_entry FIRST machine instruction executed
// by unchanged upstream FEXCore. Instruction #2 is replaced with an
// injected HLT byte in an original-owned anonymous guest staging VMA.
// Source ELF snapshots never modified; one guest byte restored and
// ALL three original file-backed PT_LOAD byte sequences verified.
// This does NOT start ld-linux, relocate ELF, handle Linux syscalls,
// initialize actual TLS/IFUNC or execute Windows games.
// Real Linux ARM64 CI ONLY; no Android handset runtime claim.
#define main kernix_c3d7n_c2_source_reference_main
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
#error C3D7N executes original ld-linux first x86 instruction Linux ARM64 CI only
#endif
namespace m=kernix::g2e;
namespace b=kernix::g2e::c3d7b;
namespace e=kernix::g2e::c3d7e;
namespace g=kernix::g2e::c3d7g;
namespace c7n {
static constexpr size_t kSourceBytes=16;
static constexpr size_t kFirstOpcodeBytes=3;
static constexpr size_t kCallOpcodeBytes=5;
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
    std::fputs("KERNIX_C3D7N_UNEXPECTED_GUEST_SYSCALL_DENIED\n",stderr);
    std::fflush(stderr);
    _exit(94);
  }
  FEXCore::HLE::ExecutableRangeInfo QueryGuestExecutableRange(
       FEXCore::Core::InternalThreadState*,uint64_t query) override {
    if(query>=rip_ && query<rip_+kSourceBytes)
      return {rip_,kSourceBytes,false};
    if(query>=target_ && query<target_+1)
      return {target_,1,false};
    return {0,0,false};
  }
  std::optional<FEXCore::ExecutableFileSectionInfo>
  LookupExecutableFileSection(
       FEXCore::Core::InternalThreadState*,uint64_t) override {
    return std::nullopt;
  }
private:
  uint64_t rip_,target_;
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
} // namespace c7n

int main(int argc,char** argv) {
  if(argc!=2 || !argv[1])return 2;
  if(::sysconf(_SC_PAGESIZE)!=4096)return 3;
  const int fd=::open(argv[1],O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
  if(fd<0)return 4;
  m::GuestPreflight original;
  std::string why;
  if(!m::Validate(fd,original,why)) {
    std::fprintf(stderr,"C3D7N_ORIGINAL_SOURCE_SHA256_DENIED %s\n",why.c_str());
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
      1,originalRIP,c7n::kSourceBytes);
  if(!sourceEntry)return 9;
  std::array<uint8_t,c7n::kSourceBytes> originalSourceBytes{};
  std::memcpy(originalSourceBytes.data(),sourceEntry,
              originalSourceBytes.size());
  // Source-verified glibc ld-linux first instruction:
  // 48 89 e7 = mov %rsp,%rdi. If original bytes differ,
  // FAIL CLOSED rather than guessing x86 instruction length.
  if(originalSourceBytes[0]!=0x48 || originalSourceBytes[1]!=0x89 ||
     originalSourceBytes[2]!=0xe7 || originalSourceBytes[3]!=0xe8) {
    std::fprintf(stderr,
      "C3D7N_FIRST_SOURCE_OPCODE_NOT_WHITELISTED "
      "first8=%02x%02x%02x%02x%02x%02x%02x%02x\n",
      originalSourceBytes[0],originalSourceBytes[1],
      originalSourceBytes[2],originalSourceBytes[3],
      originalSourceBytes[4],originalSourceBytes[5],
      originalSourceBytes[6],originalSourceBytes[7]);
    return 10;
  }
  if((originalRIP&4095)>4096-c7n::kSourceBytes)return 11;
  // Decode authentic E8 signed rel32, preserving both original opcodes.
  int32_t rel32=0;
  std::memcpy(&rel32,originalSourceBytes.data()+4,sizeof(rel32));
  const uint64_t returnRIP=originalRIP+8;
  const int64_t sum=int64_t(returnRIP)+int64_t(rel32);
  if(sum<=0)return 26;
  const uint64_t targetRIP=uint64_t(sum);
  const auto* image=staged.Module(1);
  if(!image || targetRIP<image->chosenImageStart ||
     targetRIP-image->chosenImageStart >
       b::kImageCapacity-c7n::kSourceBytes ||
     (targetRIP&4095)>4096-c7n::kSourceBytes ||
     targetRIP==originalRIP)return 27;
  // The target must be authentic source-backed ld-linux executable.
  const auto& source=original.snapshots[1];
  Elf64_Ehdr eh{};
  std::memcpy(&eh,source.bytes(),sizeof(eh));
  const uint8_t* originalTarget=nullptr;
  for(uint16_t p=0;p<eh.e_phnum;++p) {
    Elf64_Phdr ph{};
    std::memcpy(&ph,source.bytes()+eh.e_phoff+
       size_t(p)*sizeof(ph),sizeof(ph));
    if(ph.p_type!=PT_LOAD ||
       (ph.p_flags&(PF_R|PF_X))!=(PF_R|PF_X) ||
       (ph.p_flags&PF_W) || ph.p_filesz<c7n::kSourceBytes ||
       ph.p_vaddr>UINT64_MAX-image->loadBias)
      continue;
    const uint64_t va=image->loadBias+ph.p_vaddr;
    if(targetRIP<va)continue;
    const uint64_t within=targetRIP-va;
    if(within>ph.p_filesz-c7n::kSourceBytes ||
       ph.p_offset>source.size() ||
       within>source.size()-ph.p_offset ||
       c7n::kSourceBytes>source.size()-ph.p_offset-within)
      continue;
    if(originalTarget)return 28;
    originalTarget=source.bytes()+ph.p_offset+within;
  }
  const auto* stageTarget=staged.GuestReadOnlyBytes(
     1,targetRIP,c7n::kSourceBytes);
  if(!originalTarget || !stageTarget ||
     std::memcmp(originalTarget,stageTarget,c7n::kSourceBytes)!=0)
    return 29;
  const uint8_t originalTargetByte=stageTarget[0];
  if(originalRSP<8)return 30;
  // Save the real startup stack slot that the original CALL writes.
  uint64_t originalStackSlot=0;
  std::memcpy(&originalStackSlot,
     reinterpret_cast<const void*>(uintptr_t(originalRSP-8)),8);
  g::ApplyWitness nativePages;
  if(!g::ApplyOwnedOriginalPTLoadPagePermissions(
       staged,original,nativePages) ||
     !nativePages.originalPinnedSourceValidated ||
     !nativePages.nativeNoWritableExecutablePage ||
     !nativePages.nativeNonPTLoadHolesDenied ||
     !nativePages.nativeStackGuardDenied ||
     nativePages.originalModulesProtected!=3)
    return 12;
  if(c7n::RightsAt(originalRIP)!="r-xp" ||
     c7n::RightsAt(originalRSP)!="rw-p")
    return 13;

  // Keep original MOV and original CALL source bytes fully unchanged.
  // HLT is inserted at the *real* signed-call target; the HLT itself
  // is a test trap, NOT an authentic loader target instruction.
  const uint64_t targetPage=targetRIP&~uint64_t(4095);
  auto* target=reinterpret_cast<unsigned char*>(uintptr_t(targetRIP));
  if(::mprotect(reinterpret_cast<void*>(
       uintptr_t(targetPage)),4096,PROT_READ|PROT_WRITE)!=0)
    return 14;
  target[0]=c7n::kInjectedHLT;
  if(::mprotect(reinterpret_cast<void*>(
       uintptr_t(targetPage)),4096,PROT_READ|PROT_EXEC)!=0)
    return 15;
  if(c7n::RightsAt(originalRIP)!="r-xp" ||
     c7n::RightsAt(targetRIP)!="r-xp" ||
     std::memcmp(reinterpret_cast<const void*>(uintptr_t(originalRIP)),
                 originalSourceBytes.data(),8)!=0 ||
     target[0]!=c7n::kInjectedHLT)
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
  c7n::DenyAllGuestSyscalls deny{originalRIP,targetRIP};
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
  std::fputs("KERNIX_C3D7N_BEGIN_REAL_ORIGINAL_LDSO_MOV_AND_CALL_TARGET_FEX_EXECUTETHREAD\n",stderr);
  std::fflush(stderr);
  ctx->ExecuteThread(thread);
  const uint64_t postRIP=cpu.rip;
  uint64_t pushedReturn=0;
  std::memcpy(&pushedReturn,
     reinterpret_cast<const void*>(uintptr_t(originalRSP-8)),8);
  if(cpu.gregs[FEXCore::X86State::REG_RDI]!=originalRSP ||
     cpu.gregs[FEXCore::X86State::REG_RSP]!=originalRSP-8 ||
     pushedReturn!=returnRIP ||
     (postRIP!=targetRIP && postRIP!=targetRIP+1)) {
    std::fprintf(stderr,
      "C3D7N_ORIGINAL_CALL_POSTSTATE_FAIL entry=%llx target=%llx rip=%llx rsp=%llx rdi=%llx ret=%llx expected_ret=%llx\n",
      (unsigned long long)originalRIP,
      (unsigned long long)targetRIP,
      (unsigned long long)postRIP,
      (unsigned long long)cpu.gregs[FEXCore::X86State::REG_RSP],
      (unsigned long long)cpu.gregs[FEXCore::X86State::REG_RDI],
      (unsigned long long)pushedReturn,
      (unsigned long long)returnRIP);
    return 21;
  }
  // Restore target opcode and startup stack only AFTER guest thread stops.
  if(::mprotect(reinterpret_cast<void*>(
       uintptr_t(targetPage)),4096,PROT_READ|PROT_WRITE)!=0)
    return 22;
  target[0]=originalTargetByte;
  if(::mprotect(reinterpret_cast<void*>(
       uintptr_t(targetPage)),4096,PROT_READ|PROT_EXEC)!=0)
    return 23;
  std::memcpy(reinterpret_cast<void*>(uintptr_t(originalRSP-8)),
              &originalStackSlot,8);
  if(c7n::RightsAt(originalRIP)!="r-xp" ||
     c7n::RightsAt(targetRIP)!="r-xp" ||
     std::memcmp(reinterpret_cast<const void*>(uintptr_t(originalRIP)),
                 originalSourceBytes.data(),originalSourceBytes.size())!=0 ||
     std::memcmp(target,originalTarget,c7n::kSourceBytes)!=0 ||
     !c7n::OriginalFileBackedBytesRestored(original,staged) ||
     staged.WindowsHeld()!=4)return 24;
  if(!staged.Release() || staged.WindowsHeld()!=0)return 25;
  std::puts(
    "KERNIX_G2EC3D7N_REAL_ORIGINAL_LDSO_FIRST_MOV_AND_SECOND_REL32_CALL_FEX_LINUX_ARM64_PASS"
    " sha256_original_three_elf=1"
    " genuine_original_entry_first_mov_executed=1"
    " genuine_original_second_rel32_call_executed=1"
    " exact_source_call_target_file_backed_rx=1"
    " original_x86_rsp_to_rdi_verified=1"
    " x86_call_pushed_original_next_rip_verified=1"
    " x86_call_stack_pointer_decremented_8=1"
    " target_first_guest_instruction_replaced_with_test_hlt=1"
    " original_call_target_opcode_executed=0"
    " original_entry_8_bytes_never_modified=1"
    " source_call_target_original_byte_restored=1"
    " original_guest_startup_stack_slot_restored=1"
    " original_three_file_backed_ptloads_bytes_preserved=1"
    " native_guest_pages_WX_separated=1"
    " all_original_guest_windows_released=1"
    " real_dynamic_loader_completed=0"
    " guest_syscalls_forwarded=0"
    " android_device=0 wine=0");
  return 0;
}
