// SPDX-License-Identifier: MIT
// C3-D7L: bounded genuine FEXCore x86-64 *fixture* execution on Linux
// ARM64, using guest fs_cached, a kernel-chosen native identity-mapped
// guest memory page, glibc x86_64 TCB HEADER / DTV INITIAL SLOT
// ABI (reference upstream glibc 2.36), and authentic SHA-pinned source
// libc.so.6 PT_TLS 16-byte initializer in an actual guest TLS block.
// Runtime tests FS:0, FS:8, FS:16, FS:-136, DTV[1].val via x86
// instructions. Full struct pthread, dynamic glibc TCB/DTV runtime,
// guest arch_prctl, relocations, IFUNC, original ld-linux execution,
// Android device and Wine are NOT implemented or claimed here.
#define main kernix_c3d7l_c2_source_reference_main
#include "kernix_g2e_c2_original_fex_actual_syscall_trap_arm64.cpp"
#undef main
#include "kernix_g2e_c3d7k_source_pinned_fex_fs_gs_cpu_state_abi_gate.h"
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <optional>
#include <sys/mman.h>
#include <unistd.h>
#if !defined(__aarch64__) || !defined(KERNIX_G2EC2_ORIGINAL_FEX_LINUX_ARM64_CI)
#error C3D7L genuine FEX guest FS x86 opcode test only runs on Linux AArch64
#endif
namespace k=kernix::g2e::c3d7k;
namespace j=kernix::g2e::c3d7j;
namespace i=kernix::g2e::c3d7i;
namespace h=kernix::g2e::c3d7h;
namespace g=kernix::g2e::c3d7g;
namespace b=kernix::g2e::c3d7b;
namespace c7l {
// Verified guest x86 machine code. All accesses are guest memory.
//  1 mov rax, qword ptr fs:[0]         (TCB header 'tcb')
//  2 mov rcx, qword ptr fs:[8]         (DTV pointer)
//  3 mov rdx, qword ptr fs:[16]        (TCB header 'self')
//  4 mov rbx, qword ptr fs:[-136]      (original libc TLS first 8B)
//  5 mov rsi, qword ptr [rcx+16]       (DTV[1].pointer.val, 16B slot)
//  6 mov r9,  qword ptr [rsi]          (real original libc TLS initializer)
//  7-11 store all five independent witnesses to a guest RW result page
// 12 hlt (bounded and exact FEX exit; no guest syscall or ldso)
inline constexpr uint8_t kGuestFSFixture[]={
  0x64,0x48,0x8b,0x04,0x25,0x00,0x00,0x00,0x00,
  0x64,0x48,0x8b,0x0c,0x25,0x08,0x00,0x00,0x00,
  0x64,0x48,0x8b,0x14,0x25,0x10,0x00,0x00,0x00,
  0x64,0x48,0x8b,0x1c,0x25,0x78,0xff,0xff,0xff,
  0x48,0x8b,0x71,0x10,
  0x4c,0x8b,0x0e,
  0x48,0x89,0x07,
  0x48,0x89,0x4f,0x08,
  0x48,0x89,0x57,0x10,
  0x48,0x89,0x5f,0x18,
  0x4c,0x89,0x4f,0x20,
  0xf4
};
static_assert(sizeof(kGuestFSFixture)==63);
// Small owned native guest mapping; never MAP_FIXED and never shares
// the original ELF's page-protection or source lifetime.
class NativePage final {
  void* owned_=MAP_FAILED;
  size_t bytes_=0;
public:
  NativePage()=default;
  NativePage(const NativePage&)=delete;
  NativePage& operator=(const NativePage&)=delete;
  ~NativePage() { if(owned_!=MAP_FAILED)::munmap(owned_,bytes_); }
  bool Create(uintptr_t hint,size_t n,int prot) noexcept {
    if(owned_!=MAP_FAILED || !n)return false;
    void* p=::mmap(reinterpret_cast<void*>(hint),n,prot,
                   MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    if(p==MAP_FAILED)return false;
    if(!kernix::g2e::c1::GuestRange(
       reinterpret_cast<uintptr_t>(p),n)) {
      ::munmap(p,n);return false;
    }
    owned_=p;bytes_=n;return true;
  }
  void* get() const noexcept {
    return owned_==MAP_FAILED?nullptr:owned_;
  }
  uint64_t base() const noexcept {
    return static_cast<uint64_t>(reinterpret_cast<uintptr_t>(get()));
  }
};
struct alignas(8) DTVEntry {
  uint64_t value=0;
  uint64_t toFree=0;
};
static_assert(sizeof(DTVEntry)==16);
// Source glibc 2.36 sysdeps/x86_64/nptl/tls.h: first three
// pointers at 0,8,16. This is only the header prefix, NOT a
// pthread descriptor or complete glibc TCB.
struct TCBHeaderPrefix {
  uint64_t tcb=0;
  uint64_t dtv=0;
  uint64_t self=0;
};
static_assert(sizeof(TCBHeaderPrefix)==24);
static_assert(offsetof(TCBHeaderPrefix,dtv)==8);
static_assert(offsetof(TCBHeaderPrefix,self)==16);
class NoSyscall final : public FEXCore::HLE::SyscallHandler {
public:
  explicit NoSyscall(uintptr_t code):code_(code){}
  void HandleSyscall(FEXCore::Core::CpuStateFrame*) override {
    std::fputs("KERNIX_C3D7L_UNEXPECTED_GUEST_SYSCALL_DENIED\n",stderr);
    _exit(94);
  }
  FEXCore::HLE::ExecutableRangeInfo QueryGuestExecutableRange(
       FEXCore::Core::InternalThreadState*,uint64_t rip) override {
    if(rip>=code_ && rip<code_+sizeof(kGuestFSFixture))
      return {code_,sizeof(kGuestFSFixture),false};
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
} // namespace c7l

int main(int argc,char** argv) {
  if(argc!=2 || !argv[1])return 2;
  if(::sysconf(_SC_PAGESIZE)!=4096)return 3;
  int root=::open(argv[1],O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
  if(root<0)return 4;
  kernix::g2e::GuestPreflight original;
  std::string reason;
  if(!kernix::g2e::Validate(root,original,reason)) {
    std::fprintf(stderr,"C3D7L_SHA_PINNED_SOURCE_DENIED %s\n",reason.c_str());
    ::close(root);return 5;
  }
  std::array<uint8_t,16> entropy{};
  for(size_t n=0;n<16;++n)entropy[n]=uint8_t(n+1);
  b::NativeChosenPIEGuestLayout guest;
  b::Witness loaded;
  if(!guest.Stage(root,entropy,loaded) ||
     !loaded.pinnedOriginalELFSHA256Verified ||
     !loaded.linuxAuxvRebased ||
     loaded.originalELFCodeExecuted ||
     loaded.originalLdsoExecuted ||
     guest.WindowsHeld()!=4) {
    ::close(root);return 6;
  }
  ::close(root);
  g::PermissionPlan pages;
  g::Reject pageReject;
  if(!g::BuildVerifiedOriginalPermissionPlan(
     original,guest,pages,pageReject))return 7;
  h::Plan relro;
  h::Reject relroReject;
  if(!h::BuildVerifiedOriginalThreeELFRelroPlan(
     original,guest,pages,relro,relroReject))return 8;
  i::Plan dynamic;
  i::Reject dynamicReject;
  if(!i::InspectOriginalThreeModules(
     original,guest,pages,relro,dynamic,dynamicReject))return 9;
  j::TLSModel tls;
  j::DependencyGate dep;
  j::Reject tlsReject;
  if(!j::BuildOriginalStaticTLSModel(
     original,guest,dynamic,relro,tls,dep,tlsReject))return 10;
  k::Witness fsABI;
  k::Reject fsReject;
  if(!k::InspectSourcePinnedFEXGuestFSandGS(
     tls,dep,fsABI,fsReject) ||
     tls.originalInitializerBytes!=16 ||
     tls.totalTLSMemoryBytes!=136 ||
     tls.alignedStaticBlockBytes!=136 ||
     dep.sourceOriginalIRelativeResolvers!=47 ||
     !fsABI.originalGuestCPUStateNotAttached)return 11;
  uint64_t originalTLSFirstQword=0;
  std::memcpy(&originalTLSFirstQword,
       tls.bytes.data()+tls.negativeTLSBlockStart,8);
  const auto* originalGuestTLS=guest.GuestReadOnlyBytes(
     2,dynamic.modules[2].tlsOriginalGuestVA,16);
  if(!originalGuestTLS ||
     std::memcmp(originalGuestTLS,
       tls.bytes.data()+tls.negativeTLSBlockStart,16)!=0)
    return 12;

  // Linux-kernel CHOSEN native/guest identity memory. Both pages RW
  // and NONEXEC, with bounds checked before the FEX instruction stream.
  // TP is the 4096-aligned start of the second page: 136-byte TLS
  // block sits immediately before it (Variant II single module model).
  c7l::NativePage guestTCB,code,result;
  if(!guestTCB.Create(0x0000080000000000ULL,8192,PROT_READ|PROT_WRITE) ||
     !code.Create(0x0000100000000000ULL,4096,PROT_READ|PROT_WRITE) ||
     !result.Create(0x0000180000000000ULL,4096,PROT_READ|PROT_WRITE))
    return 13;
  const uint64_t guestFSBase=guestTCB.base()+4096;
  const uint64_t guestTLSStart=guestFSBase-tls.alignedStaticBlockBytes;
  const uint64_t dtvPreSlot=guestFSBase+512;
  const uint64_t dtvPointer=dtvPreSlot+sizeof(c7l::DTVEntry);
  if(guestFSBase%32 || guestTLSStart<guestTCB.base() ||
     dtvPreSlot+3*sizeof(c7l::DTVEntry)>
       guestTCB.base()+8192)return 14;
  std::memcpy(reinterpret_cast<void*>(
    static_cast<uintptr_t>(guestTLSStart)),
    tls.bytes.data()+tls.negativeTLSBlockStart,
    tls.alignedStaticBlockBytes);
  c7l::TCBHeaderPrefix tcb{guestFSBase,dtvPointer,guestFSBase};
  std::memcpy(reinterpret_cast<void*>(
    static_cast<uintptr_t>(guestFSBase)),&tcb,sizeof(tcb));
  // glibc 2.36: DTV[-1].counter=size, DTV[0].counter=generation,
  // DTV[1].pointer.val=TLS data and to_free=NULL (static).
  const c7l::DTVEntry slots[]={
    {1,0},{1,0},{guestTLSStart,0}
  };
  std::memcpy(reinterpret_cast<void*>(
    static_cast<uintptr_t>(dtvPreSlot)),slots,sizeof(slots));
  if(std::memcmp(reinterpret_cast<void*>(
       static_cast<uintptr_t>(guestTLSStart)),
       originalGuestTLS,16)!=0)return 15;
  std::memcpy(code.get(),c7l::kGuestFSFixture,
              sizeof(c7l::kGuestFSFixture));
  if(::mprotect(code.get(),4096,PROT_READ|PROT_EXEC)!=0)
    return 16;
  std::array<uint64_t,5> before{};
  before.fill(0x4b45524e49584c31ULL);
  std::memcpy(result.get(),before.data(),sizeof(before));

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
  auto context=FEXCore::Context::Context::CreateNewContext(host);
  if(!context)return 17;
  FEXCore::SignalDelegator signals{};
  c7l::NoSyscall deny{code.base()};
  context->SetSignalDelegator(&signals);
  context->SetSyscallHandler(&deny);
  context->EnableExitOnHLT();
  if(!context->InitCore())return 18;
  auto* thread=context->CreateThread();
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
  cpu.rip=code.base();
  cpu.gregs[FEXCore::X86State::REG_RSP]=
     guest.LaunchPlan()->stack.guestRSP;
  cpu.gregs[FEXCore::X86State::REG_RDI]=result.base();
  cpu.fs_idx=0;cpu.gs_idx=0;
  cpu.fs_cached=guestFSBase;cpu.gs_cached=0;
  if(cpu.fs_cached!=guestFSBase || cpu.gs_cached!=0 ||
     cpu.fs_idx!=0 || cpu.gs_idx!=0)return 20;
  std::fputs("KERNIX_C3D7L_EXECUTE_REAL_FEX_X86_FS_TCB_DTV_AND_ORIGINAL_TLS_FIXTURE_BEGIN\n",stderr);
  std::fflush(stderr);
  context->ExecuteThread(thread);
  std::array<uint64_t,5> actual{};
  std::memcpy(actual.data(),result.get(),sizeof(actual));
  if(actual[0]!=guestFSBase ||
     actual[1]!=dtvPointer ||
     actual[2]!=guestFSBase ||
     actual[3]!=originalTLSFirstQword ||
     actual[4]!=originalTLSFirstQword ||
     actual==before ||
     cpu.fs_cached!=guestFSBase ||
     cpu.gs_cached!=0) {
    std::fprintf(stderr,
      "C3D7L_FEX_FS_DTV_RUNTIME_MISMATCH actual_tcb=%llx dtv=%llx self=%llx tlsFS=%llx tlsDTV=%llx expected_tcb=%llx expected_dtv=%llx init=%llx\n",
      static_cast<unsigned long long>(actual[0]),
      static_cast<unsigned long long>(actual[1]),
      static_cast<unsigned long long>(actual[2]),
      static_cast<unsigned long long>(actual[3]),
      static_cast<unsigned long long>(actual[4]),
      static_cast<unsigned long long>(guestFSBase),
      static_cast<unsigned long long>(dtvPointer),
      static_cast<unsigned long long>(originalTLSFirstQword));
    return 21;
  }
  if(guest.WindowsHeld()!=4 ||
     std::memcmp(originalGuestTLS,
       tls.bytes.data()+tls.negativeTLSBlockStart,16)!=0)
    return 22;
  if(!guest.Release() || guest.WindowsHeld()!=0)return 23;
  std::puts(
    "KERNIX_G2EC3D7L_PINNED_FEX_ACTUAL_X86_FS_TCB_DTV_ORIGINAL_LIBC_TLS_LINUX_ARM64_PASS"
    " authentic_three_linux_x86_elf_sha256=1"
    " pinned_FEXCore_ExecuteThread_called=1"
    " real_x86_FS_0_tcb_pointer_read=1"
    " real_x86_FS_8_dtv_pointer_read=1"
    " real_x86_FS_16_self_pointer_read=1"
    " real_x86_FS_negative_136_original_libc_tls_qword_read=1"
    " real_x86_DTV_1_original_libc_tls_indirect_read=1"
    " original_16_tls_initializer_bytes_preserved=1"
    " all_guest_data_addresses_kernel_chosen=1"
    " guest_FS_base_cpu_state_real_thread=1"
    " guest_HLT_bounded_no_guest_syscall=1"
    " original_guest_ld_linux_entry_executed=0"
    " complete_glibc_tcb_dtv_runtime=0"
    " relocations_ifunc_executed=0"
    " android_device=0 wine=0");
  return 0;
}
