// SPDX-License-Identifier: MIT
// C3-D7D: source-pinned upstream FEXCore executes actual x86-64 instructions
// with data addresses that are also the Linux kernel-chosen *rebased guest*
// PIE main-ELF and original Linux x86-64 initial AUXV stack VAs.
// This is a Linux ARM64 standalone bounded fixture; original ld-linux RIP is
// NOT entered. FEX uses compatible identity guest/native host VA in this
// experiment. No Linux guest syscalls are forwarded, no Windows/Wine/Android.
#define main kernix_c3d7d_android_alu_reference_main
#include "kernix_fexcore_x86_64_alu_probe.cpp"
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
#include <sys/stat.h>
#include <string>
#if !defined(__ANDROID__) || !defined(__aarch64__)
#error C3-D7D requires Android/Bionic AArch64 execution
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
  // Only one exact app-private root selected by the signed Android app.
  // No arbitrary command, external storage, /sdcard or host filesystem.
  constexpr const char* kFlag="--kernix-c3d7d-rebased-fex-original-x86-memory-v1";
  if(argc!=3 || !argv[1] || !argv[2] ||
     std::strcmp(argv[1],kFlag)!=0 ||
     argv[2][0]!='/' || std::strlen(argv[2])>4096 ||
     std::string(argv[2]).find("..")!=std::string::npos ||
     !std::string(argv[2]).ends_with("/c3d7d-root")) {
    std::puts("KERNIX_G2EC3D7D_RESTRICTED_APP_PRIVATE_ROOT_REJECTED");
    return 126;
  }
  if(::sysconf(_SC_PAGESIZE)!=4096)return 3;
  int fd=::open(argv[2],O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
  if(fd<0)return 4;
  struct stat owner{};
  if(::fstat(fd,&owner)!=0 || !S_ISDIR(owner.st_mode) ||
     owner.st_uid!=::getuid() ||
     (owner.st_mode&(S_IWGRP|S_IWOTH))) {
    ::close(fd);
    return 21;
  }
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
  std::fputs("KERNIX_C3D7D_ANDROID_ACTUAL_FEX_REBASED_X86_START\n",stderr);
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
    "KERNIX_G2EC3D7D_ANDROID_FEX_REBASED_X86_ELF_STACK_LOAD_STORE_PASS\n"
    "NATIVE_KERNEL_PAGE_BYTES=4096\n"
    "ORIGINAL_THREE_X86_LINUX_ELF_SHA256_VERIFIED=1\n"
    "ORIGINAL_THREE_PIE_MODULES_REBASED=1\n"
    "REBASED_LINUX_X86_STACK_AUXV=1\n"
    "KERNEL_CHOSEN_CANONICAL_GUEST_VAS=1\n"
    "ACTUAL_FEX_X86_ELF_DATA_LOAD=1\n"
    "ACTUAL_FEX_X86_STACK_DATA_LOAD=1\n"
    "ACTUAL_FEX_X86_GUEST_STORE=1\n"
    "FEX_CPU_RAX_MATCHED=1\n"
    "NATIVE_GUEST_PAGES_READONLY=1\n"
    "MEMORY_WINDOWS_RELEASED=1\n"
    "ORIGINAL_LINUX_LDSO_EXECUTED=0\n"
    "ORIGINAL_ELF_GUEST_RIP_EXECUTED=0\n"
    "WINE_OR_WINDOWS_PE_EXECUTED=0");
  return 0;
}
