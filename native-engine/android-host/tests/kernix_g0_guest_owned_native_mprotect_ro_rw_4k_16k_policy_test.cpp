// SPDX-License-Identifier: MIT
// Native Linux test of real owner-held guest anonymous mprotect rights.
// NOT original GNU ld-linux PT_GNU_RELRO; that requires authentic
// dynamic relocation completion and original source ELF page ownership.
#include "kernix_g0_guest_owned_anonymous_vm_kernel.h"
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <sys/mman.h>
#include <unistd.h>

namespace abi=kernix::g2e::c1;
namespace vm=kernix::g0;
static abi::TrapClassification Trap(
 uint64_t no,uint64_t a=0,uint64_t b=0,uint64_t c=0,
 uint64_t d=0,uint64_t e=0,uint64_t f=0) {
  abi::X86LinuxSyscallTrap cpu{};
  cpu.rax=no;cpu.rdi=a;cpu.rsi=b;cpu.rdx=c;
  cpu.r10=d;cpu.r8=e;cpu.r9=f;
  cpu.rip=0x0000440000001000ULL;cpu.rcxNext=cpu.rip+2;
  cpu.rsp=0x0000600000003ff0ULL;
  const abi::X86GuestStackBoundary stack{
    0x0000600000000000ULL,0x0000600000004000ULL,true};
  abi::TrapClassification result{};
  assert(abi::ClassifyVerifiedTrap(cpu,stack,result));
  return result;
}
static std::string Rights(uint64_t address) {
  std::ifstream maps("/proc/self/maps");
  std::string line;
  while(std::getline(maps,line)){
    uint64_t low=0,high=0;
    std::string rights;
    const auto dash=line.find('-');
    const auto space=line.find(' ');
    if(dash==std::string::npos||space==std::string::npos)continue;
    try {
      low=std::stoull(line.substr(0,dash),nullptr,16);
      high=std::stoull(line.substr(dash+1,space-dash-1),nullptr,16);
    }catch(...){continue;}
    if(address<low||address>=high)continue;
    std::istringstream rightStream(line.substr(space+1));
    rightStream>>rights;
    return rights;
  }
  return {};
}
int main(){
  static_assert(vm::NativePageGuestLengthSafe(4096,4096));
  static_assert(vm::NativePageGuestLengthSafe(16384,16384));
  static_assert(!vm::NativePageGuestLengthSafe(4096,16384));
  static_assert(!vm::NativePageGuestLengthSafe(8192,16384));
  vm::BoundedGuestAnonymousVM vma;
  auto denied=vma.Dispatch(Trap(abi::kMprotect));
  assert(denied.guestReturn==-38 && !denied.nativeOwnedMapProtectionChanged);
  const long page=::sysconf(_SC_PAGESIZE);
  assert(page==4096||page==16384);
  const uint64_t n=static_cast<uint64_t>(page);
  auto first=vma.Dispatch(Trap(abi::kMmap,0,n,PROT_READ|PROT_WRITE,0x22,UINT64_MAX,0));
  assert(first.guestReturn>65536 && first.guestWritableDataMapped);
  const uint64_t address=static_cast<uint64_t>(first.guestReturn);
  auto initial=vma.AuthenticatedRW(address,n);
  assert(initial.attested && initial.guestRead &&
         initial.guestWrite && !initial.guestExecute &&
         Rights(address)=="rw-p");
  *reinterpret_cast<volatile uint64_t*>(static_cast<uintptr_t>(address))=
     0x4b45524e49585031ULL;
  auto reject=vma.Dispatch(Trap(abi::kMprotect,address,n,PROT_READ|PROT_EXEC));
  assert(reject.guestReturn==-22 && !reject.nativeOwnedMapProtectionChanged);
  reject=vma.Dispatch(Trap(abi::kMprotect,address,n,PROT_READ|PROT_WRITE|PROT_EXEC));
  assert(reject.guestReturn==-22);
  reject=vma.Dispatch(Trap(abi::kMprotect,address,n,PROT_NONE));
  assert(reject.guestReturn==-22);
  reject=vma.Dispatch(Trap(abi::kMprotect,address,n/2,PROT_READ));
  assert(reject.guestReturn==-22);
  reject=vma.Dispatch(Trap(abi::kMprotect,address+page,n,PROT_READ));
  assert(reject.guestReturn==-22);
  reject=vma.Dispatch(Trap(abi::kMprotect,address+8,n,PROT_READ));
  assert(reject.guestReturn==-22);
  reject=vma.Dispatch(Trap(abi::kMprotect,address-uint64_t(page),n,PROT_READ));
  assert(reject.guestReturn==-22);
  auto forged=Trap(abi::kMprotect,address,n,PROT_READ);
  forged.trapBoundaryAuthenticated=false;
  reject=vma.Dispatch(forged);
  assert(reject.guestReturn==-38 && !reject.nativeOwnedMapProtectionChanged);
  forged=Trap(abi::kMprotect,address,n,PROT_READ);
  forged.hostSyscallDispatched=true;
  reject=vma.Dispatch(forged);
  assert(reject.guestReturn==-38 && !reject.nativeOwnedMapProtectionChanged);
  // Real kernel mprotect on exactly one owner-held guest VMA.
  auto readonly=vma.Dispatch(Trap(abi::kMprotect,address,n,PROT_READ));
  assert(readonly.guestSyscallAuthenticated &&
         readonly.guestReturn==0 &&
         readonly.nativeOwnedMapProtectionChanged &&
         !readonly.guestWritableDataMapped);
  auto ro=vma.AuthenticatedRW(address,n);
  assert(ro.attested && ro.guestRead && !ro.guestWrite &&
         !ro.guestExecute && Rights(address)=="r--p");
  assert(*reinterpret_cast<const volatile uint64_t*>(
       static_cast<uintptr_t>(address))==0x4b45524e49585031ULL);
  // Denial of third-party source ELF mappings never changes page rights.
  const auto rejectHost=vma.Dispatch(Trap(abi::kMprotect,
      0x0000110000000000ULL,n,PROT_READ));
  assert(rejectHost.guestReturn==-22 && !rejectHost.nativeOwnedMapProtectionChanged);
  assert(Rights(address)=="r--p");
  const auto writable=vma.Dispatch(
      Trap(abi::kMprotect,address,n,PROT_READ|PROT_WRITE));
  assert(writable.guestReturn==0 &&
         writable.nativeOwnedMapProtectionChanged &&
         writable.guestWritableDataMapped &&
         vma.AuthenticatedRW(address,n).guestWrite &&
         Rights(address)=="rw-p");
  *reinterpret_cast<volatile uint64_t*>(static_cast<uintptr_t>(address))=
      0x4b45524e49585032ULL;
  const auto released=vma.Dispatch(Trap(abi::kMunmap,address,n));
  assert(released.guestReturn==0 && released.nativeOwnedMapReleased &&
         vma.Count()==0 && !vma.AuthenticatedRW(address,1).attested);
  assert(vma.Reset());
  std::puts("KERNIX_G0_ACTUAL_OWNER_HELD_GUEST_ANON_X86_MPROTECT_RW_RO_RW_AND_UNMAP_LINUX_NATIVE_PASS_NOT_ORIGINAL_ELF_RELRO");
}
