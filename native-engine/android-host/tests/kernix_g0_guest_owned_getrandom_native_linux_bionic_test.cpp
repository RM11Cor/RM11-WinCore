// SPDX-License-Identifier: MIT
// Real native Linux bounded x86 guest Linux getrandom(318) syscall bridge.
// THIS IS NOT original glibc's guest getrandom, not full Linux guest
// runtime and not executed under FEX until an independent guest test.
#include "kernix_g0_guest_owned_anonymous_vm_kernel.h"
#include <array>
#include <algorithm>
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <sys/mman.h>
#include <unistd.h>
namespace a=kernix::g2e::c1;
namespace v=kernix::g0;
static a::TrapClassification Trap(
 uint64_t n,uint64_t x=0,uint64_t y=0,uint64_t z=0,
 uint64_t r10=0,uint64_t r8=0,uint64_t r9=0){
  a::X86LinuxSyscallTrap regs{};
  regs.rax=n;regs.rdi=x;regs.rsi=y;regs.rdx=z;
  regs.r10=r10;regs.r8=r8;regs.r9=r9;
  regs.rip=0x0000440000001000ULL;regs.rcxNext=regs.rip+2;
  regs.rsp=0x0000600000003ff0ULL;
  a::TrapClassification result{};
  const a::X86GuestStackBoundary stack{
    0x0000600000000000ULL,0x0000600000004000ULL,true};
  assert(a::ClassifyVerifiedTrap(regs,stack,result));
  return result;
}
static void Rejected(v::BoundedGuestAnonymousVM& vm,
  a::TrapClassification t,int64_t expected){
  auto res=vm.Dispatch(t);
  assert(res.guestReturn==expected &&
         !res.nativeTrustedEntropySourceRead &&
         !res.guestOwnedWritableEntropyFilled &&
         !res.hostAnyUntrustedSyscallForwarded);
}
int main(){
  v::BoundedGuestAnonymousVM vm{};
  Rejected(vm,Trap(a::kGetrandom,0x1100000000ULL,32,0),-14);
  Rejected(vm,Trap(a::kGetrandom,0x1100000000ULL,0,0),-22);
  Rejected(vm,Trap(a::kGetrandom,0x1100000000ULL,257,0),-22);
  Rejected(vm,Trap(a::kGetrandom,0x1100000000ULL,32,1),-22);
  const long host=::sysconf(_SC_PAGESIZE);
  assert(host==4096 || host==16384);
  const uint64_t n=static_cast<uint64_t>(host);
  const auto mapped=vm.Dispatch(Trap(a::kMmap,0,n,3,0x22,UINT64_MAX,0));
  assert(mapped.guestReturn>65536 &&
         mapped.nativeAnonymousMapCalled &&
         mapped.guestWritableDataMapped);
  const uint64_t addr=static_cast<uint64_t>(mapped.guestReturn);
  assert(vm.AuthenticatedRW(addr,n).guestWrite);
  std::memset(reinterpret_cast<void*>(static_cast<uintptr_t>(addr)),0,n);
  Rejected(vm,Trap(a::kGetrandom,addr+n-16,32,0),-14);
  Rejected(vm,Trap(a::kGetrandom,addr-8,32,0),-14);
  Rejected(vm,Trap(a::kGetrandom,0x22000000000ULL,32,0),-14);
  Rejected(vm,Trap(a::kGetrandom,addr,32,2),-22);
  Rejected(vm,Trap(a::kGetrandom,addr,0,0),-22);
  auto fake=Trap(a::kGetrandom,addr,32,0);
  fake.trapBoundaryAuthenticated=false;
  Rejected(vm,fake,-38);
  fake=Trap(a::kGetrandom,addr,32,0);
  fake.sourceRegisterMappingChecked=false;
  Rejected(vm,fake,-38);
  fake=Trap(a::kGetrandom,addr,32,0);
  fake.hostSyscallDispatched=true;
  Rejected(vm,fake,-38);
  fake=Trap(a::kGetrandom,addr,32,0);
  fake.guestMemoryDereferenced=true;
  Rejected(vm,fake,-38);
  std::array<uint8_t,32> before{};
  std::memcpy(before.data(),reinterpret_cast<const void*>(
       static_cast<uintptr_t>(addr)),before.size());
  auto first=vm.Dispatch(Trap(a::kGetrandom,addr,32,0));
  assert(first.guestReturn==32 &&
         first.guestSyscallAuthenticated &&
         first.nativeTrustedEntropySourceRead &&
         first.guestOwnedWritableEntropyFilled &&
         !first.hostAnyUntrustedSyscallForwarded);
  std::array<uint8_t,32> entropy1{};
  std::memcpy(entropy1.data(),reinterpret_cast<const void*>(
        static_cast<uintptr_t>(addr)),entropy1.size());
  assert(entropy1!=before);
  auto second=vm.Dispatch(Trap(a::kGetrandom,addr+32,32,0));
  assert(second.guestReturn==32 && second.nativeTrustedEntropySourceRead);
  std::array<uint8_t,32> entropy2{};
  std::memcpy(entropy2.data(),reinterpret_cast<const void*>(
        static_cast<uintptr_t>(addr+32)),entropy2.size());
  assert(entropy1!=entropy2);
  // Protecting owner-held page read-only also prevents entropy output.
  auto protect=vm.Dispatch(Trap(a::kMprotect,addr,n,PROT_READ));
  assert(protect.guestReturn==0 &&
         protect.nativeOwnedMapProtectionChanged &&
         !vm.AuthenticatedRW(addr,64).guestWrite);
  Rejected(vm,Trap(a::kGetrandom,addr,32,0),-14);
  std::array<uint8_t,32> readOnly{};
  std::memcpy(readOnly.data(),reinterpret_cast<const void*>(
       static_cast<uintptr_t>(addr)),readOnly.size());
  assert(readOnly==entropy1);
  auto restore=vm.Dispatch(Trap(a::kMprotect,addr,n,PROT_READ|PROT_WRITE));
  assert(restore.guestReturn==0 &&
         vm.AuthenticatedRW(addr,64).guestWrite);
  const auto release=vm.Dispatch(Trap(a::kMunmap,addr,n));
  assert(release.guestReturn==0 && release.nativeOwnedMapReleased &&
         vm.Count()==0);
  Rejected(vm,Trap(a::kGetrandom,addr,32,0),-14);
  assert(vm.Reset());
  std::puts("KERNIX_G0_NATIVE_OWNER_ONLY_X86_GUEST_GETRANDOM_318_WRITABLE_GUEST_VMA_BOUNDED_TRUE_KERNEL_ENTROPY_PASS_NOT_FEX_OR_PHONE");
}
