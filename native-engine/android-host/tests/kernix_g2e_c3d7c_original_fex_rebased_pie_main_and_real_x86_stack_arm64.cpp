// SPDX-License-Identifier: MIT
// C3-D7C: source-pinned upstream FEXCore executes actual x86-64 instructions
// with data addresses that are also the Linux kernel-chosen *rebased guest*
// PIE main-ELF and original Linux x86-64 initial AUXV stack VAs.
// This is a Linux ARM64 standalone bounded fixture; original ld-linux RIP is
// NOT entered. FEX uses compatible identity guest/native host VA in this
// experiment. No Linux guest syscalls are forwarded, no Windows/Wine/Android.
#define main kernix_c3d7c_c2_source_reference_main
#include "kernix_g2e_c2_original_fex_actual_syscall_trap_arm64.cpp"
#undef main
#include "kernix_g2e_c3d7b_kernel_selected_pie_guest_vas.h"
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
#error C3-D7C actual source-pinned original FEX runs on Linux AArch64
#endif
namespace c7c {
// mov rax,[rbx] (real original rebased x86 ELF source bytes)
// mov rdx,[rsp] (real original x86 initial Linux startup argc = 1)
// add rax,rdx
// add rax,7
// mov [rcx],rax (independent owned writable guest result page)
// hlt (bounded FEX exit)
constexpr uint8_t kFixture[]={
    0x48,0x8b,0x03,
    0x48,0x8b,0x14,0x24,
    0x48,0x01,0xd0,
    0x48,0x83,0xc0,0x07,
    0x48,0x89,0x01,
    0xf4
};
static_assert(sizeof(kFixture)==18);
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
    std::fputs("KERNIX_C3D7C_UNEXPECTED_GUEST_SYSCALL_DENIED\n",stderr);
    _exit(94);
  }
  FEXCore::HLE::ExecutableRangeInfo QueryGuestExecutableRange(
      FEXCore::Core::InternalThreadState*,uint64_t guestVA) override {
    if(guestVA>=code_ && guestVA<code_+sizeof(kFixture))
      return {code_,sizeof(kFixture),false};
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
} // namespace c7c

int main(int argc,char** argv) {
  if(argc!=2 || !argv[1])return 2;
  if(::sysconf(_SC_PAGESIZE)!=4096)return 3;
  int fd=::open(argv[1],O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
  if(fd<0)return 4;
  std::array<uint8_t,16> entropy{};
  for(size_t i=0;i<entropy.size();++i)
      entropy[i]=static_cast<uint8_t>(i+1);
  kernix::g2e::c3d7b::NativeChosenPIEGuestLayout guest;
  kernix::g2e::c3d7b::Witness staging;
  if(!guest.Stage(fd,entropy,staging) ||
     staging.phase!=kernix::g2e::c3d7b::Phase::Complete ||
     staging.imagesVerified!=3 ||
     staging.windowsReserved!=4 ||
     !staging.pinnedOriginalELFSHA256Verified ||
     !staging.guestAddressEqualsOwnedHostPage ||
     !staging.linuxAuxvRebased ||
     !staging.originalBytesCopiedReadOnly ||
     staging.originalFEXGuestMemoryAttached ||
     staging.originalLdsoExecuted ||
     staging.nativeExecutablePageGranted)
    { ::close(fd);return 5; }
  ::close(fd);

  const auto* plan=guest.LaunchPlan();
  const auto* main=guest.Module(0);
  const auto* ldso=guest.Module(1);
  const auto* libc=guest.Module(2);
  if(!plan||!main||!ldso||!libc ||
     plan->guestInterpreterEntry!=staging.originalInterpreterRebasedRIP ||
     plan->guestMainEntry!=staging.mainRebasedEntry ||
     plan->stack.guestRSP!=staging.x86RebasedStackRSP ||
     plan->stack.guestBottom==0 ||
     plan->stack.guestBottom>=
         kernix::g2e::c1::kGuestUserLimit)return 6;
  const auto* guestMainELF=guest.GuestReadOnlyBytes(
      0,main->chosenImageStart,sizeof(uint64_t));
  if(!guestMainELF || guestMainELF[0]!=0x7f ||
     guestMainELF[1]!='E'||guestMainELF[2]!='L'||
     guestMainELF[3]!='F')return 7;
  uint64_t before=0;
  std::memcpy(&before,guestMainELF,sizeof(before));
  if(before>std::numeric_limits<uint64_t>::max()-8)
    return 8;
  uint64_t argcWord=0;
  std::memcpy(&argcWord,
      reinterpret_cast<const void*>(
          static_cast<uintptr_t>(plan->stack.guestRSP)),
      sizeof(argcWord));
  if(argcWord!=1)return 9;
  const uint64_t expected=before+argcWord+7;

  c7c::NativePage code,result;
  if(!code.Create(0x0000080000000000ULL,4096,PROT_READ|PROT_WRITE) ||
     !result.Create(0x0000100000000000ULL,4096,PROT_READ|PROT_WRITE))
    return 10;
  std::memcpy(code.get(),c7c::kFixture,sizeof(c7c::kFixture));
  if(std::memcmp(code.get(),c7c::kFixture,sizeof(c7c::kFixture))!=0 ||
     ::mprotect(code.get(),4096,PROT_READ|PROT_EXEC)!=0)
    return 11;
  const uint64_t sentinel=0x4b45524e49585a31ULL;
  std::memcpy(result.get(),&sentinel,sizeof(sentinel));

  FEXCore::Config::Initialize();
  FEXCore::Config::Load();
  FEXCore::Config::ReloadMetaLayer();
  FEXCore::Config::Set(FEXCore::Config::CONFIG_IS64BIT_MODE,"1");
  FEXCore::Config::Set(FEXCore::Config::CONFIG_MAXINST,"1");
  if(!FEXCore::Config::GetConv<bool>(
        FEXCore::Config::CONFIG_IS64BIT_MODE).value_or(false))
    return 12;
  FEXCore::HostFeatures host{};
  host.DCacheLineLog2=4;
  host.ProcessFeatures.HostType=FEXCore::HostFeatures::HostTypeEnum::Linux;
  host.ProcessFeatures.Is64BitMode=1;
  host.ProcessPID=static_cast<uint32_t>(getpid());
  host.CPUMIDRs.push_back(0);
  auto ctx=FEXCore::Context::Context::CreateNewContext(host);
  if(!ctx)return 13;
  FEXCore::SignalDelegator signals{};
  c7c::NoSyscall syscalls{code.base()};
  ctx->SetSignalDelegator(&signals);
  ctx->SetSyscallHandler(&syscalls);
  ctx->EnableExitOnHLT();
  if(!ctx->InitCore())return 14;
  auto* thread=ctx->CreateThread();
  if(!thread||!thread->CurrentFrame)return 15;

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

  const uint64_t guestStartStackRSP=plan->stack.guestRSP;
  cpu.rip=code.base();
  cpu.gregs[FEXCore::X86State::REG_RSP]=guestStartStackRSP;
  cpu.gregs[FEXCore::X86State::REG_RBX]=main->chosenImageStart;
  cpu.gregs[FEXCore::X86State::REG_RCX]=result.base();
  cpu.gregs[FEXCore::X86State::REG_RAX]=0;
  std::fputs(
      "KERNIX_C3D7C_PINNED_FEX_ACTUAL_X86_REBASED_ELF_AND_STACK_READ_START\n",
      stderr);
  std::fflush(stderr);
  ctx->ExecuteThread(thread);
  uint64_t guestStored=0;
  std::memcpy(&guestStored,result.get(),sizeof(guestStored));
  if(guestStored!=expected ||
     thread->CurrentFrame->State.gregs[FEXCore::X86State::REG_RAX]!=expected ||
     thread->CurrentFrame->State.gregs[FEXCore::X86State::REG_RSP]!=guestStartStackRSP ||
     guestStored==sentinel)
    return 16;
  if(std::memcmp(guestMainELF,&before,sizeof(before))!=0 ||
     guest.WindowsHeld()!=4 ||
     plan->stack.guestRSP!=guestStartStackRSP ||
     !guest.GuestReadOnlyBytes(
        1,plan->guestInterpreterEntry,1) ||
     !guest.GuestReadOnlyBytes(
        2,libc->chosenImageStart,4))
    return 17;
  if(!guest.Release() || guest.WindowsHeld()!=0)
    return 18;
  std::puts(
    "KERNIX_G2EC3D7C_SOURCE_PINNED_FEX_X86_LOAD_REBASED_REAL_PIE_ELF_AND_REAL_LINUX_STACK_STORE_LINUX_ARM64_PASS original_3_elf_sha256=1 real_x86_elf_load=1 real_x86_linux_stack_load=1 real_x86_store=1 cpu_rax_correct=1 source_pages_ro=1 guest_vas_kernel_selected_and_native_identity=1 guest_stack_auxv_rebased=1 original_elf_rip_executed=0 original_ldso_executed=0 android_device=0 wine=0");
  return 0;
}
