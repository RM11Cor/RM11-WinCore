// SPDX-License-Identifier: MIT
// Functional *same FEX session* original PT_INTERP callee RW-state integration after live guest syscalls: source SHA256-pinned
// original x86 ELF main, ld-linux, libc PT_LOAD and authentic initial AUXV
// stack are owned and W^X protected by the existing C3-D7B/C3-D7G runtime.
// The SAME original upstream FEXCore context executes GNU-as x86 code which
// reads the original main image and initial argc, then makes genuine Linux
// x86 mmap(9) -> guest store/load -> munmap(11), and branches DIRECTLY to
// original PT_INTERP RIP to execute BOTH 48 89 e7 = MOV RSP,RDI and
// the authentic source-backed rel32 CALL. Only the CALL destination's
// 79th offset byte is temporarily HLT in owned guest shadow; source callee first 79 bytes run.
// This remains an instrumented bounded transition, NOT full glibc/Wine startup.
#include "kernix_g2e_c3d8a_original_loader_handoff_barrier.h"
#include "kernix_g0_guest_owned_anonymous_vm_kernel.h"
#include "kernix_g0_source_verified_guest_elf_fd_kernel.h"
#include "kernix_g0_original_elf_ldso_handoff_blob.h"
#include "kernix_g2e_c2_original_fex_cpu_state_adapter.h"
#include "kernix_g2e_c3d7n_original_ldso_call_source_target_gate.h"
#include <FEXCore/Config/Config.h>
#include <FEXCore/Core/Context.h>
#include <FEXCore/Core/HostFeatures.h>
#include <FEXCore/Core/CoreState.h>
#include <FEXCore/Core/X86Enums.h>
#include <FEXCore/Core/SignalDelegator.h>
#include <FEXCore/Debug/InternalThreadState.h>
#include <FEXCore/HLE/SyscallHandler.h>
#include <FEXCore/fextl/memory.h>
#include <array>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include "kernix_g2e_c3d7j_original_x86_static_tls_variant2_order_gate.h"
#include "kernix_g0_source_relative_rela_guest_writer_gate.h"
#include "kernix_g0_source_owned_guest_fs_tls_runtime.h"
#include <fcntl.h>
#include <fstream>
#include <memory>
#include <optional>
#include <string>
#include <sys/mman.h>
#include <unistd.h>

#if !defined(__aarch64__) || \
    (!defined(__ANDROID__) && !defined(KERNIX_G0_ORIGINAL_ELF_INTEGRATED_FEX_ARM64_CI))
#error G0 original pinned ELF + real FEX integration requires ARM64
#endif

namespace {
namespace c1=kernix::g2e::c1;
namespace c2=kernix::g2e::c2;
namespace c7b=kernix::g2e::c3d7b;
namespace c7g=kernix::g2e::c3d7g;
namespace c8a=kernix::g2e::c3d8a;
namespace h=kernix::g2e::c3d7h;
namespace d=kernix::g2e::c3d7i;
namespace tls=kernix::g2e::c3d7j;
namespace rela=kernix::g0::relawriter;
namespace fs=kernix::g0::fsruntime;
using FileService=kernix::g0::SourceVerifiedGuestElfFDKernel;
constexpr uint64_t kGuestAnonBytes=4096;
// The byte stream is additionally pinned by the original triad SHA256 check.
constexpr size_t kStop=79;
constexpr size_t kFrame=192;
constexpr std::array<uint8_t,80> kCallee{{
0xf3,0x0f,0x1e,0xfa,0x55,
0x48,0x8d,0x0d,0x14,0xfe,0xfd,0xff,
0x48,0x8d,0x05,0xe5,0x90,0x01,0x00,
0x66,0x48,0x0f,0x6e,0xc9,0x66,0x48,0x0f,0x6e,0xd0,
0x66,0x0f,0x6c,0xca,0x48,0x89,0xe5,
0x41,0x57,0x41,0x56,0x41,0x55,0x41,0x54,0x53,
0x48,0x81,0xec,0x88,0x00,0x00,0x00,
0x48,0x89,0xbd,0x78,0xff,0xff,0xff,
0x0f,0x29,0x4d,0x80,0x0f,0x31,
0x80,0x25,0xde,0x8b,0x01,0x00,0xdf,
0x48,0x8d,0x35,0xc1,0x88,0x01,0x00,0x41
}};
static_assert(kCallee.size()==kStop+1);
std::string RightsAt(uint64_t address) {
 std::ifstream maps("/proc/self/maps");
 std::string line;
 while(std::getline(maps,line)){
  unsigned long long lo=0,hi=0; char rights[5]{};
  if(std::sscanf(line.c_str(),"%llx-%llx %4s",&lo,&hi,rights)!=3)continue;
  if(address>=lo && address<hi)return rights;
 }
 return "unmapped";
}

class SingleFEXOriginalCallRetGuard final {
  void* ptr_=MAP_FAILED;
  size_t total_=0;
public:
  SingleFEXOriginalCallRetGuard()=default;
  SingleFEXOriginalCallRetGuard(
      const SingleFEXOriginalCallRetGuard&)=delete;
  SingleFEXOriginalCallRetGuard& operator=(
      const SingleFEXOriginalCallRetGuard&)=delete;
  ~SingleFEXOriginalCallRetGuard(){(void)Release();}
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

class OwnedGuestFixtureCode final {
public:
    ~OwnedGuestFixtureCode() {if(address_)::munmap(address_,length_);}
    bool Install() noexcept {
        const long hostPage=::sysconf(_SC_PAGESIZE);
        if(hostPage!=4096)return false; // C3-D7B/C3-D7G are 4K only.
        length_=static_cast<size_t>(hostPage);
        void* p=::mmap(reinterpret_cast<void*>(0x0000440000000000ULL),
            length_,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
        if(p==MAP_FAILED)return false;
        address_=p;
        if(!c1::GuestRange(Address(),length_))return false;
        std::memcpy(p,KERNIX_G0_ELF_LDSO_HANDOFF_GUEST,
                    sizeof(KERNIX_G0_ELF_LDSO_HANDOFF_GUEST));
        if(::mprotect(p,length_,PROT_READ|PROT_EXEC)!=0)return false;
        return true;
    }
    uintptr_t Address() const noexcept {
        return reinterpret_cast<uintptr_t>(address_);
    }
private:
    void* address_=nullptr;
    size_t length_=0;
};

class OneProcessOriginalElfSyscalls final : public FEXCore::HLE::SyscallHandler {
public:
    OneProcessOriginalElfSyscalls(uint64_t entry,uint64_t originalLdsoTarget,
                                 const kernix::g2b::X86GuestProcessLaunchPlan& plan,
                                 const c7b::ImageMeta& mainImage,
                                 uint64_t mainSourceWord,
                                 const c7b::NativeChosenPIEGuestLayout& owner,
                                 const fs::OwnedGuestFS& guestFS,
                                 uint64_t sourceMainRelroPage,
                                 FileService& fileService)
       :Entry(entry),
        Stack{plan.stack.guestBottom,plan.stack.guestTop,true},
        MainStart(mainImage.chosenImageStart),
        InitialRSP(plan.stack.guestRSP),
        MainSourceWord(mainSourceWord),
        OriginalLdsoEntry(plan.guestInterpreterEntry),
        OriginalLdsoTarget(originalLdsoTarget),
        Owner(owner),
        GuestFS(guestFS),
        SourceMainRelroPage(sourceMainRelroPage),
         Files(fileService){}
    void HandleSyscall(FEXCore::Core::CpuStateFrame* frame) override {
        if(++Calls>11) {
            std::fputs("G0_COMBINED_TOO_MANY_SYSCALLS_REJECTED\n",stderr);
            _exit(51);
        }
        c2::ActualFexTrapWitness verified{};
        if(!c2::DecodePinnedFexCpuState(frame,Stack,verified) ||
           !verified.originalFexCpuStateFrameRead) {
            std::fputs("G0_COMBINED_FEX_CPUSTATE_REJECTED\n",stderr);
            _exit(52);
        }
        const auto& trap=verified.decoded;
        const size_t syscallOffset=Calls==1?
            G0_ELF_LDSO_HANDOFF_ARCH_SET_FS_OFFSET:Calls==2?
            G0_ELF_LDSO_HANDOFF_MMAP_OFFSET:Calls==3?
            G0_ELF_LDSO_HANDOFF_GETRANDOM_1_OFFSET:Calls==4?
            G0_ELF_LDSO_HANDOFF_GETRANDOM_2_OFFSET:Calls==5?
            G0_ELF_LDSO_HANDOFF_GUEST_OPENAT_OFFSET:Calls==6?
            G0_ELF_LDSO_HANDOFF_GUEST_PREAD64_OFFSET:Calls==7?
            G0_ELF_LDSO_HANDOFF_GUEST_READ_OFFSET:Calls==8?
            G0_ELF_LDSO_HANDOFF_GUEST_CLOSE_OFFSET:Calls==9?
            G0_ELF_LDSO_HANDOFF_FOREIGN_RELRO_MPROTECT_OFFSET:Calls==10?
            G0_ELF_LDSO_HANDOFF_MPROTECT_OFFSET:
            G0_ELF_LDSO_HANDOFF_MUNMAP_OFFSET;
        if(frame->State.rip!=Entry+syscallOffset ||
           trap.nextGuestRIP!=Entry+syscallOffset+2 ||
           Owner.WindowsHeld()!=4 ||
           !Owner.LaunchPlan() ||
           Owner.LaunchPlan()->stack.guestRSP!=InitialRSP ||
           Owner.Module(0)->chosenImageStart!=MainStart ||
           !Owner.GuestReadOnlyBytes(1,OriginalLdsoEntry,8)) {
            std::fputs("G0_COMBINED_ORIGINAL_ENTRY_OR_RIP_REJECTED\n",stderr);
            _exit(53);
        }
        if(Calls==1) {
            // ARCH_SET_FS guest-only FEX CPUState update; never host TLS.
            if(trap.guestNumber!=158 ||
               trap.args[0]!=0x1002 ||
               trap.args[1]!=GuestFS.FSBase() ||
               GuestFS.FSBase()<65536 ||
               frame->State.fs_cached!=0 ||
               frame->State.gs_cached!=0 ||
               frame->State.gregs[FEXCore::X86State::REG_R12]!=MainSourceWord ||
               frame->State.gregs[FEXCore::X86State::REG_R14]!=1 ||
               RightsAt(GuestFS.FSBase())!="rw-p") {
                std::fputs("KERNIX_G0_ARCH_SET_FS_GUEST_ONLY_AUTH_REJECT\n",stderr);
                _exit(61);
            }
            frame->State.fs_cached=GuestFS.FSBase();
            frame->State.gregs[FEXCore::X86State::REG_RAX]=0;
            frame->State.rip=trap.nextGuestRIP;
            GuestArchSetFSObserved=true;
            std::fputs("KERNIX_G0_SOURCE_AUTHENTICATED_X86_ARCH_SET_FS_CPUSTATE_APPLIED_NOT_HOST_TLS\n",stderr);
            return;
        }
        if(Calls==2) {
            if(!GuestArchSetFSObserved ||
               frame->State.fs_cached!=GuestFS.FSBase() ||
               !GuestFS.GuestReadbacksMatch()) {
                std::fputs("KERNIX_G0_X86_FS_TCB_DTV_SOURCE_LIBC_TLS_READBACK_REJECT\n",stderr);
                _exit(62);
            }
            std::fputs("KERNIX_G0_REAL_FEX_X86_FS_TCB_DTV_ORIGINAL_LIBC_TLS_READS_BEFORE_MMAP_PASS\n",stderr);
            if(trap.guestNumber!=c1::kMmap ||
               trap.args[0]!=0 || trap.args[1]!=kGuestAnonBytes ||
               trap.args[2]!=3 || trap.args[3]!=0x22 ||
               !c1::IsGuestMmapFdAnonymous(trap.args[4]) ||
               trap.args[5]!=0 ||
               frame->State.gregs[FEXCore::X86State::REG_R12]!=MainSourceWord ||
               frame->State.gregs[FEXCore::X86State::REG_R14]!=1) {
                std::fputs("G0_COMBINED_MAIN_ELF_OR_ARGC_NOT_READ_BY_X86_REJECTED\n",stderr);
                _exit(54);
            }
            const auto result=Heap.Dispatch(trap);
            if(!result.guestSyscallAuthenticated ||
               !result.nativeAnonymousMapCalled ||
               !result.guestWritableDataMapped ||
               result.hostAnyUntrustedSyscallForwarded ||
               result.guestReturn<65536 || Heap.Count()!=1) {
                std::fputs("G0_COMBINED_X86_MMAP_OWNER_REJECTED\n",stderr);
                _exit(55);
            }
            HeapAddress=static_cast<uint64_t>(result.guestReturn);
            const auto span=Heap.AuthenticatedRW(HeapAddress,kGuestAnonBytes);
            if(!span.attested || span.guestExecute ||
               !span.guestRead || !span.guestWrite ||
               span.start!=HeapAddress ||
               span.pastLast!=HeapAddress+kGuestAnonBytes) {
                std::fputs("G0_COMBINED_ANON_PAGE_RIGHTS_REJECTED\n",stderr);
                _exit(56);
            }
            // An authenticated guest must never be able to unmap
            // source-owned main, interpreter, libc or initial stack.
            auto counterfeit=trap;
            counterfeit.guestNumber=c1::kMunmap;
            counterfeit.args={OriginalLdsoEntry,kGuestAnonBytes,0,0,0,0};
            const auto denied=Heap.Dispatch(counterfeit);
            if(denied.guestReturn!=-EINVAL ||
               denied.nativeOwnedMapReleased ||
               Heap.Count()!=1 || Owner.WindowsHeld()!=4) {
                std::fputs("G0_COMBINED_FOREIGN_LDSO_MUNMAP_DENIAL_REJECTED\n",stderr);
                _exit(57);
            }
            DeniedForeignUnmap=true;
            frame->State.gregs[FEXCore::X86State::REG_RAX]=HeapAddress;
            frame->State.rip=trap.nextGuestRIP;
            std::fputs("KERNIX_G0_COMBINED_FEX_ORIGINAL_ELF_AND_STACK_CONSUMED\n",stderr);
            return;
        }
        if(Calls==3 || Calls==4) {
            // Both are actual translated x86 Linux getrandom(318) from
            // the genuine FEX CPU frame, not a host-only test call.
            // All guest buffers must be in the SAME native owner-held
            // heap VMA; the original source ELF/TLS/JIT is forbidden.
            const bool first=(Calls==3);
            const uint64_t guestAt=HeapAddress+(first?64:96);
            if(!GuestArchSetFSObserved ||
               frame->State.fs_cached!=GuestFS.FSBase() ||
               !GuestFS.GuestReadbacksMatch() ||
               (first?FirstEntropyWritten:!FirstEntropyWritten) ||
               trap.guestNumber!=c1::kGetrandom ||
               trap.args[0]!=guestAt ||
               trap.args[1]!=32 || trap.args[2]!=0 ||
               Heap.Count()!=1 || RightsAt(HeapAddress)!="rw-p" ||
               !Heap.AuthenticatedRW(guestAt,32).guestWrite ||
               frame->State.gregs[FEXCore::X86State::REG_R12]!=MainSourceWord ||
               frame->State.gregs[FEXCore::X86State::REG_R14]!=1){
                 std::fputs("KERNIX_G0_X86_REAL_GUEST_GETRANDOM_SOURCE_OR_OWNER_REJECT\n",stderr);
                 _exit(71);
            }
            const std::array<unsigned char,32> zeros{};
            std::array<unsigned char,32> before{};
            std::memcpy(before.data(),
                reinterpret_cast<const void*>(static_cast<uintptr_t>(guestAt)),32);
            if(before!=zeros) {
                std::fputs("KERNIX_G0_X86_GUEST_ENTROPY_STAGING_NOT_ZERO_REJECT\n",stderr);
                _exit(72);
            }
            const auto result=Heap.Dispatch(trap);
            if(result.guestReturn!=32 ||
               !result.guestSyscallAuthenticated ||
               !result.nativeTrustedEntropySourceRead ||
               !result.guestOwnedWritableEntropyFilled ||
               result.hostAnyUntrustedSyscallForwarded){
                std::fputs("KERNIX_G0_X86_REAL_GUEST_KERNEL_ENTROPY_BRIDGE_REJECT\n",stderr);
                _exit(73);
            }
            std::array<unsigned char,32> after{};
            std::memcpy(after.data(),
                reinterpret_cast<const void*>(static_cast<uintptr_t>(guestAt)),32);
            if(after==zeros || (!first && after==FirstEntropyBytes)){
                std::fputs("KERNIX_G0_X86_GUEST_RANDOM_OUTPUT_NOT_INDEPENDENT_REJECT\n",stderr);
                _exit(74);
            }
            if(first){
                FirstEntropyBytes=after;FirstEntropyWritten=true;
                std::fputs("KERNIX_G0_ACTUAL_FEX_X86_GETRANDOM_318_FIRST_AUTHENTIC_OWNED_RW_BUFFER_KERNEL_ENTROPY_FILLED\n",stderr);
            }else{
                SecondEntropyWritten=true;
                std::fputs("KERNIX_G0_ACTUAL_FEX_X86_GETRANDOM_318_SECOND_INDEPENDENT_OWNED_RW_BUFFER_KERNEL_ENTROPY_FILLED\n",stderr);
            }
            frame->State.gregs[FEXCore::X86State::REG_RAX]=32;
            frame->State.rip=trap.nextGuestRIP;
            return;
        }
        if(Calls>=5 && Calls<=8) {
            const bool opened=Calls==5,pre=Calls==6,read=Calls==7,closed=Calls==8;
            const uint64_t guestFd=FileService::kGuestBaseFD;
            if(!FirstEntropyWritten || !SecondEntropyWritten ||
               !Files.Bound() || Heap.Count()!=1 ||
               RightsAt(HeapAddress)!="rw-p" ||
               frame->State.fs_cached!=GuestFS.FSBase() ||
               !GuestFS.GuestReadbacksMatch() ||
               frame->State.gregs[FEXCore::X86State::REG_R12]!=MainSourceWord ||
               frame->State.gregs[FEXCore::X86State::REG_R14]!=1 ||
               (opened && (trap.guestNumber!=c1::kOpenat ||
                   trap.args[0]!=uint64_t(int64_t(-100)) ||
                   trap.args[1]!=HeapAddress+256 ||
                   trap.args[2]!=0x80000 || trap.args[3]!=0 ||
                   Files.OpenCount()!=0)) ||
               (pre && (trap.guestNumber!=c1::kPread64 ||
                   trap.args[0]!=guestFd || trap.args[1]!=HeapAddress+512 ||
                   trap.args[2]!=64 || trap.args[3]!=0 ||
                   Files.OpenCount()!=1)) ||
               (read && (trap.guestNumber!=c1::kRead ||
                   trap.args[0]!=guestFd || trap.args[1]!=HeapAddress+576 ||
                   trap.args[2]!=64 || Files.OpenCount()!=1)) ||
               (closed && (trap.guestNumber!=c1::kClose ||
                   trap.args[0]!=guestFd || Files.OpenCount()!=1))) {
                std::fputs("KERNIX_G0_GUEST_OPENAT_READ_PREAD_CLOSE_AUTH_REJECT\n",stderr);
                _exit(75);
            }
            const auto result=Files.Dispatch(trap,Heap);
            if(!result.guestSyscallAuthenticated ||
               result.hostPathOpened || result.hostGuestFdForwarded ||
               result.hostAnyUntrustedSyscallForwarded ||
               result.guestReturn!=(opened?int64_t(guestFd):pre||read?64:0)) {
                std::fputs("KERNIX_G0_GUEST_SOURCE_IMMUTABLE_FILE_SYSCALL_REJECT\n",stderr);
                _exit(76);
            }
            if(pre || read) {
                const auto* original=Owner.GuestReadOnlyBytes(
                    1,Owner.Module(1)->chosenImageStart,64);
                const auto* actual=reinterpret_cast<const uint8_t*>(
                    static_cast<uintptr_t>(HeapAddress+(pre?512:576)));
                if(!original ||
                   !result.copiedSnapshotToAuthenticatedGuestWritable ||
                   std::memcmp(original,actual,64)!=0) {
                    std::fputs("KERNIX_G0_GUEST_ORIGINAL_SOURCE_LDSO_ELF_BYTES_REJECT\n",stderr);
                    _exit(77);
                }
            }
            if(closed && (!result.guestFdClosed || Files.OpenCount()!=0)) {
                std::fputs("KERNIX_G0_GUEST_SYNTHETIC_FD_CLOSE_REJECT\n",stderr);
                _exit(78);
            }
            if(opened){GuestOpened=true;
                std::fputs("KERNIX_G0_REAL_FEX_X86_ORIGINAL_LDSO_SOURCE_SNAPSHOT_OPENAT_GUEST_FD100_PASS\n",stderr);}
            if(pre){GuestPread=true;
                std::fputs("KERNIX_G0_REAL_FEX_X86_ORIGINAL_LDSO_SOURCE_SNAPSHOT_PREAD64_ELF64_PASS\n",stderr);}
            if(read){GuestRead=true;
                std::fputs("KERNIX_G0_REAL_FEX_X86_ORIGINAL_LDSO_SOURCE_SNAPSHOT_READ_ELF64_PASS\n",stderr);}
            if(closed){GuestClosed=true;
                std::fputs("KERNIX_G0_REAL_FEX_X86_ORIGINAL_LDSO_SOURCE_SNAPSHOT_CLOSE_NO_HOST_FD_PASS\n",stderr);}
            frame->State.gregs[FEXCore::X86State::REG_RAX]=
                static_cast<uint64_t>(result.guestReturn);
            frame->State.rip=trap.nextGuestRIP;
            return;
        }
        if(Calls==9) {
            // Actual x86 guest syscall 10 targeting the AUTHENTIC,
            // SOURCE-PINNED main ELF PT_GNU_RELRO full writable page.
            // No original dynamic-linker relocation closure witness;
            // deny without modifying the guest source mapping.
            if(!GuestArchSetFSObserved ||
               frame->State.fs_cached!=GuestFS.FSBase() ||
               !GuestFS.GuestReadbacksMatch() ||
               trap.guestNumber!=c1::kMprotect ||
               trap.args[0]!=SourceMainRelroPage ||
               trap.args[1]!=4096 ||
               trap.args[2]!=PROT_READ ||
               SourceMainRelroPage<MainStart ||
               !Owner.GuestReadOnlyBytes(0,SourceMainRelroPage,8) ||
               RightsAt(SourceMainRelroPage)!="rw-p" ||
               Heap.Count()!=1 ||
               RightsAt(HeapAddress)!="rw-p" ||
               frame->State.gregs[FEXCore::X86State::REG_R12]!=MainSourceWord ||
               frame->State.gregs[FEXCore::X86State::REG_R14]!=1) {
               std::fputs("KERNIX_G0_GUEST_SOURCE_MAIN_RELRO_MPROTECT_TRAP_REJECT\n",stderr);
               _exit(66);
            }
            const auto beforeOriginal=RightsAt(SourceMainRelroPage);
            const auto denial=Heap.Dispatch(trap);
            if(denial.guestReturn!=-EINVAL ||
               denial.nativeOwnedMapProtectionChanged ||
               denial.hostAnyUntrustedSyscallForwarded ||
               RightsAt(SourceMainRelroPage)!=beforeOriginal ||
               Heap.Count()!=1 || Owner.WindowsHeld()!=4){
               std::fputs("KERNIX_G0_SOURCE_ELF_RELRO_PREMATURE_SEAL_DENIAL_REJECT\n",stderr);
               _exit(67);
            }
            GuestSourceRelroSealDenied=true;
            frame->State.gregs[FEXCore::X86State::REG_RAX]=
                static_cast<uint64_t>(static_cast<int64_t>(-EINVAL));
            frame->State.rip=trap.nextGuestRIP;
            std::fputs("KERNIX_G0_ACTUAL_FEX_GUEST_X86_ORIGINAL_MAIN_GNU_RELRO_MPROTECT_PREMATURE_DENIED_SOURCE_PAGE_UNCHANGED\n",stderr);
            return;
        }
        if(Calls==10) {
            if(!GuestOpened || !GuestPread || !GuestRead || !GuestClosed ||
               Files.OpenCount()!=0 ||
               !FirstEntropyWritten || !SecondEntropyWritten ||
               !GuestSourceRelroSealDenied ||
               RightsAt(SourceMainRelroPage)!="rw-p" ||
               !GuestArchSetFSObserved ||
               frame->State.fs_cached!=GuestFS.FSBase() ||
               !GuestFS.GuestReadbacksMatch() ||
               trap.guestNumber!=c1::kMprotect ||
               trap.args[0]!=HeapAddress ||
               trap.args[1]!=kGuestAnonBytes ||
               trap.args[2]!=PROT_READ ||
               Heap.Count()!=1 ||
               !DeniedForeignUnmap ||
               frame->State.gregs[FEXCore::X86State::REG_R12]!=MainSourceWord ||
               frame->State.gregs[FEXCore::X86State::REG_R14]!=1 ||
               RightsAt(HeapAddress)!="rw-p") {
                std::fputs("KERNIX_G0_ORIGINAL_FEX_REAL_X86_MPROTECT_TRAP_REJECT\n",stderr);
                _exit(63);
            }
            const auto beforeLD=RightsAt(OriginalLdsoEntry);
            auto counterfeit=trap;
            counterfeit.args={OriginalLdsoEntry,kGuestAnonBytes,PROT_READ,0,0,0};
            const auto denied=Heap.Dispatch(counterfeit);
            if(denied.guestReturn!=-EINVAL ||
               denied.nativeOwnedMapProtectionChanged ||
               RightsAt(OriginalLdsoEntry)!=beforeLD ||
               Heap.Count()!=1) {
                std::fputs("KERNIX_G0_ORIGINAL_ELF_MPROTECT_OWNER_DENIAL_REJECT\n",stderr);
                _exit(64);
            }
            const auto protect=Heap.Dispatch(trap);
            const auto span=Heap.AuthenticatedRW(HeapAddress,kGuestAnonBytes);
            if(protect.guestReturn!=0 ||
               !protect.guestSyscallAuthenticated ||
               !protect.nativeOwnedMapProtectionChanged ||
               protect.guestWritableDataMapped ||
               protect.hostAnyUntrustedSyscallForwarded ||
               !span.attested || !span.guestRead ||
               span.guestWrite || span.guestExecute ||
               RightsAt(HeapAddress)!="r--p") {
                std::fputs("KERNIX_G0_NATIVE_ONLY_OWNED_X86_MPROTECT_RO_REJECT\n",stderr);
                _exit(65);
            }
            ProtectedGuestAnonRO=true;
            frame->State.gregs[FEXCore::X86State::REG_RAX]=0;
            frame->State.rip=trap.nextGuestRIP;
            std::fputs("KERNIX_G0_REAL_FEX_X86_GUEST_MPROTECT_OWNED_HEAP_RW_TO_RO_NATIVE_PROTECTED_BEFORE_X86_READ\n",stderr);
            return;
        }
        if(!GuestOpened || !GuestPread || !GuestRead || !GuestClosed ||
           Files.OpenCount()!=0 ||
           !FirstEntropyWritten || !SecondEntropyWritten ||
           !GuestSourceRelroSealDenied ||
           RightsAt(SourceMainRelroPage)!="rw-p" ||
           !ProtectedGuestAnonRO ||
           !GuestArchSetFSObserved ||
           frame->State.fs_cached!=GuestFS.FSBase() ||
           !GuestFS.GuestReadbacksMatch() ||
           trap.guestNumber!=c1::kMunmap ||
           trap.args[0]!=HeapAddress ||
           trap.args[1]!=kGuestAnonBytes ||
           frame->State.gregs[FEXCore::X86State::REG_R12]!=MainSourceWord ||
           frame->State.gregs[FEXCore::X86State::REG_R14]!=1 ||
           frame->State.gregs[FEXCore::X86State::REG_R15]!=MainSourceWord ||
           Heap.Count()!=1 || !DeniedForeignUnmap ||
           !Heap.AuthenticatedRW(HeapAddress,sizeof(uint64_t)).attested ||
           Heap.AuthenticatedRW(HeapAddress,sizeof(uint64_t)).guestWrite ||
           !Heap.AuthenticatedRW(HeapAddress,sizeof(uint64_t)).guestRead ||
           RightsAt(HeapAddress)!="r--p") {
            std::fputs("G0_COMBINED_REAL_X86_HEAP_COPY_OR_MUNMAP_REJECTED\n",stderr);
            _exit(58);
        }
        uint64_t copied=0;
        std::memcpy(&copied,
             reinterpret_cast<const void*>(static_cast<uintptr_t>(HeapAddress)),
             sizeof(copied));
        if(copied!=MainSourceWord ||
           !Owner.GuestReadOnlyBytes(0,MainStart,sizeof(uint64_t))) {
            std::fputs("G0_COMBINED_SOURCE_ELF_GUEST_COPY_REJECTED\n",stderr);
            _exit(59);
        }
        const auto released=Heap.Dispatch(trap);
        if(released.guestReturn!=0 ||
           !released.nativeOwnedMapReleased ||
           released.hostAnyUntrustedSyscallForwarded ||
           Heap.Count()!=0 || Heap.AuthenticatedRW(HeapAddress,1).attested ||
           Owner.WindowsHeld()!=4) {
            std::fputs("G0_COMBINED_HEAP_CLEANUP_REJECTED\n",stderr);
            _exit(60);
        }
        WholeProcessIntegrationCompleted=true;
        frame->State.gregs[FEXCore::X86State::REG_RAX]=0;
        frame->State.rip=trap.nextGuestRIP;
        std::fputs("KERNIX_G0_COMBINED_X86_HEAP_COPY_AND_MUNMAP_WITH_ORIGINAL_PIE_ALIVE\n",stderr);
    }
    FEXCore::HLE::ExecutableRangeInfo QueryGuestExecutableRange(
        FEXCore::Core::InternalThreadState*,uint64_t address) override {
        if(address>=Entry &&
           address<Entry+sizeof(KERNIX_G0_ELF_LDSO_HANDOFF_GUEST))
            return {Entry,sizeof(KERNIX_G0_ELF_LDSO_HANDOFF_GUEST),false};
        // Original source-backed PT_INTERP bytes remain RX. FEX may
        // query the first instruction and the bounded next HLT only.
        if(address>=OriginalLdsoEntry && address<OriginalLdsoEntry+16)
            return {OriginalLdsoEntry,16,false};
        if(address>=OriginalLdsoTarget && address<OriginalLdsoTarget+128)
            return {OriginalLdsoTarget,128,false};
        return {0,0,false};
    }
    std::optional<FEXCore::ExecutableFileSectionInfo>
    LookupExecutableFileSection(
        FEXCore::Core::InternalThreadState*,uint64_t) override {
        return std::nullopt;
    }
    unsigned Calls=0;
    bool DeniedForeignUnmap=false;
    bool WholeProcessIntegrationCompleted=false;
    bool GuestArchSetFSObserved=false;
    bool ProtectedGuestAnonRO=false;
    bool GuestSourceRelroSealDenied=false;
    bool FirstEntropyWritten=false;
    bool SecondEntropyWritten=false;
    bool GuestOpened=false,GuestPread=false,GuestRead=false,GuestClosed=false;
    std::array<unsigned char,32> FirstEntropyBytes{};
    kernix::g0::BoundedGuestAnonymousVM Heap{};
    // The original x86 fixture preserves its mmap result in guest RBX
    // through the real munmap; that historic pointer is a register
    // witness only. It must never be dereferenced after unmapping.
    uint64_t HistoricalMmapAddress() const noexcept {return HeapAddress;}
private:
    uint64_t Entry=0;
    c1::X86GuestStackBoundary Stack{};
    uint64_t MainStart=0,InitialRSP=0,MainSourceWord=0;
    uint64_t OriginalLdsoEntry=0,OriginalLdsoTarget=0,HeapAddress=0;
    const c7b::NativeChosenPIEGuestLayout& Owner;
    const fs::OwnedGuestFS& GuestFS;
    uint64_t SourceMainRelroPage=0;
    FileService& Files;
};

int Run(int argc,char** argv) {
    // New test proves a real guest-x86 fixture RELA write from an
    // authentic original source record. Genuine ld-linux dynamic
    // relocation and TLS/FS remain unexecuted.
    // Preflight extends device-accepted G0 without executing a genuine
    // relocation writer / guest FS/GS or full dynamic linker.
    // Deterministic stage markers are stderr-only, bounded and do not
    // modify the guest or host address-space permissions. Detect
    // pre-ExecuteThread SIGSEGV separately from original FEX JIT.
    const auto stage=[](const char* name) noexcept {
        std::fprintf(stderr,"KERNIX_G0_MOV_CALL_DIAGNOSTIC_STAGE=%s\n",name);
        std::fflush(stderr);
    };
    stage("entered");
    if(argc!=2 || !argv[1] || ::sysconf(_SC_PAGESIZE)!=4096)
        return 2;
    const int fd=::open(argv[1],O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(fd<0)return 3;
    kernix::g2e::GuestPreflight original{};
    std::string why{};
    const bool verified=kernix::g2e::Validate(fd,original,why);
    if(!verified || !original.exactSha256Matched ||
       !original.exactInterpreterAndGlibcClosure ||
       !original.readOnlyAnonymousSnapshots) {
        ::close(fd);return 4;
    }
    stage("source_sha256_verified");
    std::array<uint8_t,16> entropy{};
    for(size_t i=0;i<entropy.size();++i)entropy[i]=uint8_t(i+1);
    c7b::NativeChosenPIEGuestLayout owned{};
    c7b::Witness source{};
    // Trusted original source root FD from exact GNU ELF preflight:
    // component-wise O_NOFOLLOW eliminates symlink parent traversal.
    FileService guestFiles{};
    const auto subdir=[](int parent,const char* child)->int {
       return ::openat(parent,child,
           O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    };
    const int bin=subdir(fd,"bin");
    const int lib64=subdir(fd,"lib64");
    const int lib=subdir(fd,"lib");
    const int libx=lib>=0?subdir(lib,"x86_64-linux-gnu"):-1;
    std::array<int,3> fds{{-1,-1,-1}};
    if(bin>=0)fds[0]=::openat(bin,"kernix-g2e-dynamic-guest",
                        O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);
    if(lib64>=0)fds[1]=::openat(lib64,"ld-linux-x86-64.so.2",
                        O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);
    if(libx>=0)fds[2]=::openat(libx,"libc.so.6",
                        O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);
    if(bin>=0)::close(bin);
    if(lib64>=0)::close(lib64);
    if(libx>=0)::close(libx);
    if(lib>=0)::close(lib);
    const bool snapshotBound=guestFiles.BindSourceOriginalTriad(fds);
    for(int sourceFd:fds)if(sourceFd>=0)::close(sourceFd);
    const bool staged=snapshotBound && owned.Stage(fd,entropy,source);
    ::close(fd);
    if(!snapshotBound || !guestFiles.Bound() ||
       guestFiles.OpenCount()!=0)return 80;
    if(!staged || !source.pinnedOriginalELFSHA256Verified ||
       source.windowsReserved!=4 || owned.WindowsHeld()!=4 ||
       !source.linuxAuxvRebased || !source.originalBytesCopiedReadOnly ||
       source.originalLdsoExecuted || source.originalELFCodeExecuted)
        return 5;
    stage("original_source_ptload_staged");
    const auto* plan=owned.LaunchPlan();
    const auto* main=owned.Module(0);
    const auto* interpreter=owned.Module(1);
    if(!plan || !main || !interpreter ||
       !c1::GuestRange(main->chosenImageStart,8) ||
       !c1::GuestRange(plan->guestInterpreterEntry,8) ||
       plan->guestInterpreterEntry<interpreter->chosenImageStart ||
       !owned.GuestReadOnlyBytes(1,plan->guestInterpreterEntry,8))
        return 7;
    const auto* sourceMain=owned.GuestReadOnlyBytes(
         0,main->chosenImageStart,sizeof(uint64_t));
    if(!sourceMain || sourceMain[0]!=0x7f || sourceMain[1]!='E' ||
       sourceMain[2]!='L' || sourceMain[3]!='F')
        return 8;
    uint64_t first8=0;
    std::memcpy(&first8,sourceMain,sizeof(first8));
    const uint64_t rsp=plan->stack.guestRSP;
    uint64_t argcWord=0;
    std::memcpy(&argcWord,
        reinterpret_cast<const void*>(static_cast<uintptr_t>(rsp)),
        sizeof(argcWord));
    if(argcWord!=1 || (rsp&15)!=0)
        return 9;
    // Link to the original source-verified PT_INTERP entry within the
    // SAME exact original PT_LOAD/guest AUXV VMAs, not a synthetic
    // separately allocated copy or a second FEX process.
    const uint64_t originalLdsoRIP=plan->guestInterpreterEntry;
    if((originalLdsoRIP&4095)>4096-16 ||
       originalLdsoRIP<interpreter->chosenImageStart ||
       !c1::GuestRange(originalLdsoRIP,16))return 20;
    stage("original_elf_and_auxv_stack_read_verified");
    // Reuse the existing source-only C3-D7N exact original ELF
    // entry CALL rel32 target contract (NO second competing loader).
    c7g::PermissionPlan planRights{};
    c7g::Reject rightsReject{};
    if(!c7g::BuildVerifiedOriginalPermissionPlan(
          original,owned,planRights,rightsReject))return 22;
    stage("original_permission_plan_verified");
    // This is NOT a relocated loader or TLS runtime: reuse independent
    // source-authenticated C3-D7H/I/J metadata and TLS-model contracts
    // before PT_LOAD W^X hardening. No guest relocations/FS/GS writes.
    h::Plan relro{};
    h::Reject relroReject{};
    if(!h::BuildVerifiedOriginalThreeELFRelroPlan(
         original,owned,planRights,relro,relroReject)){
      std::fprintf(stderr,"KERNIX_G0_ELF_RELRO_PREFLIGHT_REJECT reason=%u\n",
                   unsigned(relroReject));return 42;
    }
    d::Plan dynamic{};
    d::Reject dynamicReject{};
    if(!d::InspectOriginalThreeModules(
         original,owned,planRights,relro,dynamic,dynamicReject)){
      std::fprintf(stderr,"KERNIX_G0_ELF_DYNAMIC_PREFLIGHT_REJECT reason=%u\n",
                   unsigned(dynamicReject));return 43;
    }
    tls::TLSModel tlsModel{};
    tls::DependencyGate dependencies{};
    tls::Reject tlsReject{};
    if(!tls::BuildOriginalStaticTLSModel(
        original,owned,dynamic,relro,tlsModel,dependencies,tlsReject)){
      std::fprintf(stderr,"KERNIX_G0_ORIGINAL_TLS_MODEL_REJECT reason=%u\n",
                   unsigned(tlsReject));return 44;
    }
    const auto& libcDyn=dynamic.modules[2];
    if(!dynamic.originalThreeSHA256SourcesVerified ||
       !dynamic.allOriginalDynamicTablesBounded ||
       !dynamic.allOriginalTLSRangesBounded ||
       dynamic.originalELFRelocationsApplied ||
       dynamic.x86GuestFSGSInitialized ||
       !dependencies.authenticateThreeOriginalELFs ||
       !dependencies.requiresActualRelocationWrites ||
       !dependencies.requiresRealGuestTCBAndDTV ||
       !dependencies.requiresActualGuestFSBase ||
       !dependencies.requiresRealIFUNCResolverGuestExecution ||
       !dependencies.requiresPostRelocationRELRO ||
       dependencies.realRelocationWritePerformed ||
       dependencies.guestFSBaseAssigned ||
       dependencies.guestRelroApplied ||
       !tlsModel.sourceInitializerMatchesOriginalELF ||
       !tlsModel.zeroFillMatchesOriginalPTTLSMemsz ||
       tlsModel.realGuestFSBaseAssigned ||
       tlsModel.originalLdsoExecuted ||
       dependencies.sourceOriginalTLSModules!=1 ||
       !tlsModel.originalInitializerBytes ||
       !libcDyn.tlsTotalMemorySize ||
       dependencies.sourceOriginalRelrTargets==0 ||
       dependencies.sourceOriginalIRelativeResolvers==0 ||
       dynamic.relocationTargetsOutsideInitialRW!=0)return 45;
    // The initial source-verified TLS data is still byte-identical to
    // its original guest memory and remains a HOST-ONLY model.
    const auto* tlsBytes=owned.GuestReadOnlyBytes(
        2,libcDyn.tlsOriginalGuestVA,tlsModel.originalInitializerBytes);
    if(!tlsBytes ||
       std::memcmp(tlsBytes,
          tlsModel.bytes.data()+tlsModel.negativeTLSBlockStart,
          tlsModel.originalInitializerBytes)!=0)return 46;
    stage("original_three_elf_dynamic_relr_rela_and_libc_tls_source_preflight_only");
    fs::OwnedGuestFS guestFS{};
    const bool tlsOwnerInstalled=guestFS.Install(tlsModel);
    if(!tlsOwnerInstalled ||
       !guestFS.FSBase() ||
       RightsAt(guestFS.FSBase())!="rw-p") {
      std::fprintf(stderr,
       "KERNIX_G0_GUEST_FS_OWNER_INSTALL_REJECT installed=%d fs=%llx rights=%s source_init=%zu source_aligned=%zu source_negative_start=%zu native_errno=%d\n",
       int(tlsOwnerInstalled),
       static_cast<unsigned long long>(guestFS.FSBase()),
       RightsAt(guestFS.FSBase()).c_str(),
       tlsModel.originalInitializerBytes,
       tlsModel.alignedStaticBlockBytes,
       tlsModel.negativeTLSBlockStart,errno);
      return 63;
    }
    stage("source_original_libc_PT_TLS_installed_into_bounded_guest_TCB_DTV_not_full_glibc");
    // One exact main ELF R_X86_64_RELATIVE is authorized by SHA-pinned
    // DT_RELA + ELF PT_LOAD permission plan, before native W^X hardening.
    // The guest FIXTURE, not the original ld-linux, later performs it
    // between real x86 mmap and munmap. We intentionally do NOT claim
    // the real dynamic linker handled relocations.
    rela::Witness relative{};
    rela::Reject relativeReject{};
    if(!rela::FindSourceMainRelativeRela(
         original,owned,planRights,dynamic,relative,relativeReject) ||
       !relative.authenticatedOriginalRela ||
       !relative.independentGuestPTLoadWritePermitted ||
       relative.actuallyExecutedByOriginalLdso ||
       relative.sourceRelocationInfo!=uint64_t(R_X86_64_RELATIVE) ||
       relative.guestMainLoadBias!=main->chosenImageStart ||
       relative.previousValue==relative.expectedSourceValue){
      std::fprintf(stderr,"KERNIX_G0_REAL_X86_RELATIVE_SOURCE_SELECT_REJECT reason=%u\n",
                   unsigned(relativeReject));return 48;
    }
    stage("original_sha256_main_elf_relative_rela_source_and_rw_target_authorized");
    kernix::g2e::c3d7n::CallProof call{};
    kernix::g2e::c3d7n::Reject callReject{};
    if(!kernix::g2e::c3d7n::VerifyAuthenticLdsoSecondCallTarget(
          original,owned,planRights,call,callReject) ||
       call.originalEntry!=originalLdsoRIP ||
       call.originalReturnRIP!=originalLdsoRIP+8 ||
       call.originalGuestStartupRSP!=rsp ||
       call.originalTarget==originalLdsoRIP ||
       (call.originalTarget&4095)>4096-80 ||
       !c1::GuestRange(call.originalTarget,16))
        return 23;
    stage("original_source_call_target_verified");
    // Source and ELF permission policy MUST be fully verified before
    // C3-D7G mprotect(PROT_NONE) hides genuine non-PT_LOAD holes.
    // BuildVerifiedOriginalPermissionPlan reads source/guest metadata;
    // rebuilding the plan after hardening previously SIGSEGV'd.
    c7g::ApplyWitness rights{};
    if(!c7g::ApplyOwnedOriginalPTLoadPagePermissions(
        owned,original,rights) ||
       !rights.originalPinnedSourceValidated ||
       !rights.nativeNoWritableExecutablePage ||
       !rights.nativeNonPTLoadHolesDenied ||
       !rights.nativeStackGuardDenied ||
       !rights.nativeLinuxStackWritableNonExecutable ||
       rights.originalModulesProtected!=3 ||
       rights.originalLdsoExecuted || rights.fexEntered)
        return 6;
    stage("ptload_native_wx_permissions_applied");
    // The pending original PT_GNU_RELRO must stay RW until the REAL
    // GNU dynamic linker has completed all relocations. A single
    // KERNIX-owned RELATIVE fixture store is NOT that completion.
    uint64_t authenticMainRelroRWPage=0;
    for(size_t pg=0;pg<c7g::kModulePages;++pg) {
        if(!relro.modules[0].sealedAfterRealRelocation[pg] ||
           (planRights.modules[0].rights[pg]&(c7g::kRead|c7g::kWrite))!=
            (c7g::kRead|c7g::kWrite))continue;
        const uint64_t addr=main->chosenImageStart+uint64_t(pg)*4096;
        if(RightsAt(addr)!="rw-p" ||
           !owned.GuestReadOnlyBytes(0,addr,8))continue;
        authenticMainRelroRWPage=addr;
        break;
    }
    h::Reject earlySealReject{};
    if(!authenticMainRelroRWPage ||
       h::SealOriginalRelroBeforeVerifiedRealRelocations(
          relro,earlySealReject) ||
       earlySealReject!=h::Reject::NoRelocationProof ||
       (authenticMainRelroRWPage&4095)!=0 ||
       !c1::GuestRange(authenticMainRelroRWPage,4096))
       return 70;
    stage("source_main_GNU_RELRO_original_RW_fullpage_selected_but_no_real_ldso_relocation_completion_witness");
    if(RightsAt(relative.guestTarget)!="rw-p" ||
       !owned.GuestReadOnlyBytes(0,relative.sourceGuestRela,sizeof(Elf64_Rela)))
       return 49;
    uint64_t beforeSourceRelaInfo=0;
    std::memcpy(&beforeSourceRelaInfo,
      reinterpret_cast<const void*>(
        static_cast<uintptr_t>(relative.sourceGuestRela+8)),8);
    if(beforeSourceRelaInfo!=uint64_t(R_X86_64_RELATIVE))return 50;
    const uint64_t originalTarget=call.originalTarget;
    auto* originalEntry=owned.GuestReadOnlyBytes(1,originalLdsoRIP,16);
    auto* originalTargetBytes=owned.GuestReadOnlyBytes(1,originalTarget,16);
    if(!originalEntry || !originalTargetBytes ||
       std::memcmp(originalEntry,call.originalEntryBytes.data(),16)!=0 ||
       std::memcmp(originalTargetBytes,call.originalTargetBytes.data(),16)!=0 ||
       call.originalTargetBytes[0]==0xf4)return 24;
    stage("original_entry_target_rx_source_bytes_verified");
    // Execute authentic source-backed callee after real guest mmap/munmap:
    // prove the original loader updates its own RW data and stack state.
    // Only the *next* opcode is replaced by HLT in owned guest staging.
    const auto* actual80=owned.GuestReadOnlyBytes(1,originalTarget,kCallee.size());
    if(!actual80 || std::memcmp(actual80,kCallee.data(),kCallee.size())!=0)
      return 36;
    const uint64_t base=interpreter->loadBias;
    int32_t dispAND=0,dispRSI=0;
    std::memcpy(&dispAND,kCallee.data()+67,4);
    std::memcpy(&dispRSI,kCallee.data()+75,4);
    const uint64_t dataAt=originalTarget+72+
        static_cast<uint64_t>(static_cast<int64_t>(dispAND));
    const uint64_t pointerRSI=originalTarget+79+
        static_cast<uint64_t>(static_cast<int64_t>(dispRSI));
    if(dataAt!=base+0x38e06 || pointerRSI!=base+0x38af0 ||
       RightsAt(dataAt)!="rw-p" || RightsAt(rsp-kFrame)!="rw-p" ||
       (rsp&15)!=0)return 37;
    auto* dataByte=reinterpret_cast<uint8_t*>(static_cast<uintptr_t>(dataAt));
    const uint8_t originalData=*dataByte;
    const uint8_t seededData=static_cast<uint8_t>(originalData|0x20u);
    const uint8_t expectedData=static_cast<uint8_t>(seededData&0xdfu);
    if(expectedData==seededData)return 38;
    std::array<uint8_t,kFrame> originalStack{};
    std::memcpy(originalStack.data(),reinterpret_cast<const void*>(
        static_cast<uintptr_t>(rsp-kFrame)),originalStack.size());
    *dataByte=seededData;
    stage("source_original_callee_writable_data_and_guest_stack_verified");
    const auto targetPage=originalTarget&~uint64_t(4095);
    auto* targetByte=reinterpret_cast<uint8_t*>(
        static_cast<uintptr_t>(originalTarget));
    if(::mprotect(reinterpret_cast<void*>(
          static_cast<uintptr_t>(targetPage)),4096,PROT_READ|PROT_WRITE)!=0)
        return 25;
    targetByte[kStop]=0xf4;
    if(::mprotect(reinterpret_cast<void*>(
          static_cast<uintptr_t>(targetPage)),4096,PROT_READ|PROT_EXEC)!=0)
        return 26;
    if(targetByte[kStop]!=0xf4 ||
       std::memcmp(targetByte,kCallee.data(),kStop)!=0 ||
       std::memcmp(originalEntry,call.originalEntryBytes.data(),8)!=0)
        return 27;
    stage("original_callee_next_source_opcode_bounded_hlt_rx_installed");
    OwnedGuestFixtureCode code;
    if(!code.Install() || !c1::GuestRange(
        code.Address(),sizeof(KERNIX_G0_ELF_LDSO_HANDOFF_GUEST)))
        return 10;

    stage("integration_guest_fixture_rx_installed");
    FEXCore::Config::Initialize();
    FEXCore::Config::Load();
    FEXCore::Config::ReloadMetaLayer();
    FEXCore::Config::Set(FEXCore::Config::CONFIG_IS64BIT_MODE,"1");
    FEXCore::Config::Set(FEXCore::Config::CONFIG_MAXINST,"1");
    if(!FEXCore::Config::GetConv<bool>(
         FEXCore::Config::CONFIG_IS64BIT_MODE).value_or(false))
        return 11;
    FEXCore::HostFeatures host{};
    host.DCacheLineLog2=4;
    host.ProcessFeatures.HostType=FEXCore::HostFeatures::HostTypeEnum::Linux;
    host.ProcessFeatures.Is64BitMode=1;
    host.ProcessPID=static_cast<uint32_t>(::getpid());
    host.CPUMIDRs.push_back(0);
    stage("original_fex_host_features_initialized");
    SingleFEXOriginalCallRetGuard callret{};
    if(!callret.Reserve())return 29;
    stage("fex_callret_host_guard_initialized");
    auto ctx=FEXCore::Context::Context::CreateNewContext(host);
    if(!ctx)return 12;
    FEXCore::SignalDelegator signals{};
    OneProcessOriginalElfSyscalls handler{
        code.Address(),originalTarget,*plan,*main,first8,
        owned,guestFS,authenticMainRelroRWPage,guestFiles};
    ctx->SetSignalDelegator(&signals);
    ctx->SetSyscallHandler(&handler);
    ctx->EnableExitOnHLT();
    stage("original_fex_context_configured");
    if(!ctx->InitCore())return 13;
    stage("original_fex_core_initialized");
    auto* thread=ctx->CreateThread();
    if(!thread || !thread->CurrentFrame)return 14;
    stage("original_fex_thread_created");
    FEXCore::Core::CPUState::gdt_segment gdt[32]{};
    auto& cpu=thread->CurrentFrame->State;
    thread->CallRetStackBase=callret.Base();
    cpu.callret_sp=callret.InitialSP();
    if(!thread->CallRetStackBase ||
       !callret.Contains(cpu.callret_sp-16,16))return 30;
    cpu.segment_arrays[FEXCore::Core::CPUState::SEGMENT_ARRAY_INDEX_GDT]=gdt;
    cpu.segment_arrays[FEXCore::Core::CPUState::SEGMENT_ARRAY_INDEX_LDT]=gdt;
    cpu.cs_idx=FEXCore::Core::CPUState::DEFAULT_USER_CS<<3;
    auto* descriptor=FEXCore::Core::CPUState::GetSegmentFromIndex(cpu,cpu.cs_idx);
    FEXCore::Core::CPUState::SetGDTBase(descriptor,0);
    FEXCore::Core::CPUState::SetGDTLimit(descriptor,0xFFFFF);
    descriptor->L=1;descriptor->D=0;cpu.cs_cached=0;
    cpu.rip=code.Address();
    cpu.gregs[FEXCore::X86State::REG_RSP]=rsp;
    cpu.gregs[FEXCore::X86State::REG_RAX]=authenticMainRelroRWPage;
    cpu.gregs[FEXCore::X86State::REG_R13]=main->chosenImageStart;
    cpu.gregs[FEXCore::X86State::REG_R8]=guestFS.FSBase();
    cpu.gregs[FEXCore::X86State::REG_R9]=relative.sourceGuestRela;
    cpu.fs_cached=0;
    cpu.gs_cached=0;
    cpu.gregs[FEXCore::X86State::REG_RBP]=originalLdsoRIP;
    cpu.gregs[FEXCore::X86State::REG_RDI]=0x4b45524e49585431ULL;
    cpu.gregs[FEXCore::X86State::REG_R12]=0;
    cpu.gregs[FEXCore::X86State::REG_R14]=0;
    cpu.gregs[FEXCore::X86State::REG_R15]=0;
    stage("original_x86_guest_cpu_state_ready_before_execute");
    std::fputs("KERNIX_G0_ORIGINAL_LDSO_MOV_CALL_AFTER_FEX_HEAP_START\n",stderr);
    std::fflush(stderr);
    ctx->ExecuteThread(thread);
    stage("original_fex_execute_thread_returned");
    if(handler.Calls!=11 || !handler.GuestArchSetFSObserved ||
       !handler.GuestOpened || !handler.GuestPread ||
       !handler.GuestRead || !handler.GuestClosed ||
       guestFiles.OpenCount()!=0 ||
       !handler.FirstEntropyWritten || !handler.SecondEntropyWritten ||
       !handler.GuestSourceRelroSealDenied ||
       RightsAt(authenticMainRelroRWPage)!="rw-p" ||
       !handler.ProtectedGuestAnonRO ||
       cpu.fs_cached!=guestFS.FSBase() ||
       cpu.gs_cached!=0 ||
       !guestFS.GuestReadbacksMatch() ||
       !handler.WholeProcessIntegrationCompleted ||
       !handler.DeniedForeignUnmap || handler.Heap.Count()!=0 ||
       cpu.gregs[FEXCore::X86State::REG_R12]!=first8 ||
       cpu.gregs[FEXCore::X86State::REG_R14]!=1 ||
       cpu.gregs[FEXCore::X86State::REG_R15]!=first8 ||
       cpu.gregs[FEXCore::X86State::REG_RSP]!=rsp-kFrame ||
       cpu.gregs[FEXCore::X86State::REG_RDI]!=rsp ||
       cpu.gregs[FEXCore::X86State::REG_RBP]!=rsp-16 ||
       cpu.gregs[FEXCore::X86State::REG_RSI]!=pointerRSI ||
       cpu.gregs[FEXCore::X86State::REG_RCX]!=base ||
       cpu.xmm.sse.data[1][0]!=base ||
       cpu.xmm.sse.data[1][1]!=base+0x392d8 ||
       *dataByte!=expectedData ||
       (cpu.rip!=originalTarget+kStop &&
        cpu.rip!=originalTarget+kStop+1) ||
       owned.WindowsHeld()!=4){
      std::fprintf(stderr,
       "KERNIX_G0_FUNCTIONAL_LOADER_RW_REJECT stage=post_fex rip=%llx rsp=%llx rsi=%llx expected_rsi=%llx byte=%02x expected_byte=%02x\n",
       static_cast<unsigned long long>(cpu.rip),
       static_cast<unsigned long long>(cpu.gregs[FEXCore::X86State::REG_RSP]),
       static_cast<unsigned long long>(cpu.gregs[FEXCore::X86State::REG_RSI]),
       static_cast<unsigned long long>(pointerRSI),unsigned(*dataByte),unsigned(expectedData));
      return 15;
    }
    std::array<uint64_t,7> stackSlots{};
    for(size_t i=0;i<stackSlots.size();++i)
      std::memcpy(&stackSlots[i],reinterpret_cast<const void*>(
        static_cast<uintptr_t>(rsp-8*(i+1))),sizeof(uint64_t));
    const uint64_t historicalHeap=handler.HistoricalMmapAddress();
    if(historicalHeap<65536 ||
       (historicalHeap&uint64_t{4095})!=0 ||
       handler.Heap.Count()!=0)return 30;
    // The seventh saved slot is authentic RBX: it holds the unmapped
    // guest heap's previous address, not zero.
    const std::array<uint64_t,7> wantedSlots{
      call.originalReturnRIP,originalLdsoRIP,first8,1,
      main->chosenImageStart,first8,historicalHeap};
    if(stackSlots!=wantedSlots){
      for(size_t i=0;i<stackSlots.size();++i)
        std::fprintf(stderr,
          "KERNIX_G0_STACK_STATE_MISMATCH slot=%zu actual=%llx expected=%llx\n",
          i,static_cast<unsigned long long>(stackSlots[i]),
          static_cast<unsigned long long>(wantedSlots[i]));
      return 31;
    }
    uint64_t localRDI=0;
    std::array<uint64_t,2> localXMM{};
    std::memcpy(&localRDI,reinterpret_cast<const void*>(
        static_cast<uintptr_t>(rsp-16-0x88)),8);
    std::memcpy(localXMM.data(),reinterpret_cast<const void*>(
        static_cast<uintptr_t>(rsp-16-0x80)),16);
    if(localRDI!=rsp || localXMM[0]!=base ||
       localXMM[1]!=base+0x392d8){
      std::fprintf(stderr,
         "KERNIX_G0_LOCAL_STATE_MISMATCH rdi=%llx expected_rdi=%llx xmm1lo=%llx expected_lo=%llx xmm1hi=%llx expected_hi=%llx\n",
         static_cast<unsigned long long>(localRDI),
         static_cast<unsigned long long>(rsp),
         static_cast<unsigned long long>(localXMM[0]),
         static_cast<unsigned long long>(base),
         static_cast<unsigned long long>(localXMM[1]),
         static_cast<unsigned long long>(base+0x392d8));
      return 39;
    }
    // This witness is a genuine original-source-derived guest x86
    // store, not a fabricated host-side relocation success marker.
    uint64_t actualGuestRelative=0;
    std::memcpy(&actualGuestRelative,reinterpret_cast<const void*>(
        static_cast<uintptr_t>(relative.guestTarget)),8);
    uint64_t afterSourceRelaInfo=0;
    std::memcpy(&afterSourceRelaInfo,reinterpret_cast<const void*>(
        static_cast<uintptr_t>(relative.sourceGuestRela+8)),8);
    if(actualGuestRelative!=relative.expectedSourceValue ||
       actualGuestRelative==relative.previousValue ||
       afterSourceRelaInfo!=beforeSourceRelaInfo ||
       RightsAt(relative.guestTarget)!="rw-p"){
      std::fprintf(stderr,
       "KERNIX_G0_SOURCE_RELATIVE_GUEST_WRITE_REJECT target=%llx actual=%llx expected=%llx previous=%llx info=%llx\n",
       static_cast<unsigned long long>(relative.guestTarget),
       static_cast<unsigned long long>(actualGuestRelative),
       static_cast<unsigned long long>(relative.expectedSourceValue),
       static_cast<unsigned long long>(relative.previousValue),
       static_cast<unsigned long long>(afterSourceRelaInfo));
      return 51;
    }
    std::fputs("KERNIX_G0_REAL_FEX_X86_ARCH_PRCTL_SET_FS_GUEST_TCB_DTV_LIBC_TLS_READ_PASS_SAME_HEAP_LDSO_PROCESS\n",stderr);
    std::fputs("KERNIX_G0_REAL_GUEST_SOURCE_RELA_FS_MMAP_MPROTECT_RO_MUNMAP_EARLY_ORIGINAL_LDSO_COMPOSED_NOT_FULL_GLIBC_RELRO\n",stderr);
    std::fputs("KERNIX_G0_SOURCE_ORIGINAL_MAIN_GNU_RELRO_NATIVE_MPROTECT_FROM_X86_DENIED_PENDING_REAL_LDSO_RELOCATION\n",stderr);
    std::fputs("KERNIX_G0_SAME_ORIGINAL_FEX_X86_GUEST_GETRANDOM_318_TWICE_FS_RELA_GNURELRO_DENY_ANON_RO_EARLY_LDSO_PASS_NOT_FULL_GLIBC\n",stderr);
    std::fputs("KERNIX_G0_REAL_FEX_X86_ORIGINAL_LDSO_OPENAT_PREAD64_READ_CLOSE_SNAPSHOT_OWNER_ONLY_SAME_SESSION_NO_FULL_GLIBC\n",stderr);
    std::fputs("KERNIX_G0_REAL_FEX_GUEST_X86_SOURCE_RELATIVE_RELA_STORE_AFTER_MMAP_VERIFIED_NOT_ORIGINAL_LDSO_RELOCATION\n",stderr);
    if(!dependencies.requiresActualRelocationWrites ||
       !dependencies.requiresRealGuestTCBAndDTV ||
       !dependencies.requiresRealIFUNCResolverGuestExecution ||
       dependencies.realRelocationWritePerformed ||
       dependencies.guestFSBaseAssigned || dependencies.guestRelroApplied ||
       !dynamic.originalThreeSHA256SourcesVerified ||
       !tlsModel.sourceInitializerMatchesOriginalELF)
      return 47;
    std::fputs("KERNIX_G0_REAL_FEX_HEAP_LDSO_RW_AND_SOURCE_DYNAMIC_TLS_PREFLIGHT_COEXIST\n",stderr);
    std::fputs("KERNIX_G0_SAME_FEX_ORIGINAL_LDSO_CALLEE_GUEST_RW_AND_STACK_STATE_VERIFIED\n",stderr);
    // Destroy native JIT context before modifying source-owned RX
    // guest PT_LOAD and before releasing the host-only callret stack.
    ctx.reset();
    if(!callret.Release())return 32;
    if(!guestFS.Release())return 64;
    if(::mprotect(reinterpret_cast<void*>(
          static_cast<uintptr_t>(targetPage)),4096,PROT_READ|PROT_WRITE)!=0)
      return 33;
    targetByte[kStop]=kCallee[kStop];
    if(::mprotect(reinterpret_cast<void*>(
          static_cast<uintptr_t>(targetPage)),4096,PROT_READ|PROT_EXEC)!=0)
      return 34;
    if(std::memcmp(kCallee.data(),targetByte,kCallee.size())!=0 ||
       std::memcmp(call.originalEntryBytes.data(),originalEntry,16)!=0)
      return 35;
    *dataByte=originalData;
    if(*dataByte!=originalData)return 40;
    // A guest x86 reloc fixture modified original main ELF's staged
    // PT_LOAD RW word; restore this exact source prior to file-backed
    // unchanged/release gates. Never mutate on-disk ELF or user games.
    std::memcpy(reinterpret_cast<void*>(
       static_cast<uintptr_t>(relative.guestTarget)),
       &relative.previousValue,sizeof(relative.previousValue));
    uint64_t restoredRelative=0;
    std::memcpy(&restoredRelative,reinterpret_cast<const void*>(
       static_cast<uintptr_t>(relative.guestTarget)),8);
    if(restoredRelative!=relative.previousValue)return 52;
    std::fputs("KERNIX_G0_GUEST_SOURCE_RELA_RELATIVE_RW_QWORD_RESTORED_NO_LDSO_RELOCATION_CLAIM\n",stderr);
    std::memcpy(reinterpret_cast<void*>(static_cast<uintptr_t>(rsp-kFrame)),
                originalStack.data(),originalStack.size());
    if(std::memcmp(reinterpret_cast<const void*>(static_cast<uintptr_t>(rsp-kFrame)),
                   originalStack.data(),originalStack.size())!=0)return 41;
    std::fputs("KERNIX_G0_SOURCE_CALLEE_GUEST_RW_STACK_AND_EXECUTABLE_RESTORED_WX_SAFE\n",stderr);
    std::fputs("KERNIX_G0_ORIGINAL_LDSO_DYNAMIC_GLIBC_TLS_FULL_RUNTIME_NOT_EXECUTED\n",stderr);
    uint32_t unchanged=0;
    if(!c8a::FileBackedSegmentsUnchanged(original,owned,unchanged) ||
       unchanged<3)return 16;
    guestFiles.Reset();
    if(guestFiles.Bound() || guestFiles.OpenCount()!=0)return 81;
    if(!handler.Heap.Reset() ||
       !owned.Release() || owned.WindowsHeld()!=0)return 17;
#if defined(__ANDROID__)
    std::puts("KERNIX_G0_X86_LDSO_SNAPSHOT_FILES_GETRANDOM_RELRO_ANDROID_CANDIDATE_NOT_FULL_GLIBC");
#else
    std::puts("KERNIX_G0_X86_LDSO_SNAPSHOT_FILES_GETRANDOM_RELRO_LINUX_PASS_NOT_FULL_GLIBC");
#endif
    return 0;
}
} // namespace

int main(int argc,char** argv) {return Run(argc,argv);}
