// SPDX-License-Identifier: MIT
// Actual native VMA allocation and release for an authenticated x86 guest
// syscall trap; host-only decoded trap test, NOT FEX/device execution.
#include "kernix_g0_guest_owned_anonymous_vm_kernel.h"
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>
#include <sys/mman.h>
#include <unistd.h>
namespace abi=kernix::g2e::c1;
namespace vm=kernix::g0;
static abi::TrapClassification Trap(
    uint64_t n,uint64_t x=0,uint64_t y=0,uint64_t z=0,
    uint64_t r10=0,uint64_t r8=0,uint64_t r9=0) {
  abi::X86LinuxSyscallTrap regs{};
  regs.rax=n;regs.rdi=x;regs.rsi=y;regs.rdx=z;
  regs.r10=r10;regs.r8=r8;regs.r9=r9;
  regs.rip=0x0000440000001000ULL;regs.rcxNext=regs.rip+2;
  regs.rsp=0x0000600000003ff0ULL;
  abi::X86GuestStackBoundary stack{
    0x0000600000000000ULL,0x0000600000004000ULL,true};
  abi::TrapClassification t{};
  assert(abi::ClassifyVerifiedTrap(regs,stack,t));
  return t;
}
static abi::TrapClassification Map(uint64_t n=4096) {
  return Trap(abi::kMmap,0,n,3,0x22,UINT64_MAX,0);
}
static abi::TrapClassification Unmap(uint64_t addr,uint64_t n=4096) {
  return Trap(abi::kMunmap,addr,n);
}
int main() {
  static_assert(vm::NativePageGuestLengthSafe(4096,4096));
  static_assert(vm::NativePageGuestLengthSafe(16384,4096));
  static_assert(vm::NativePageGuestLengthSafe(16384,16384));
  static_assert(!vm::NativePageGuestLengthSafe(4096,16384));
  static_assert(!vm::NativePageGuestLengthSafe(8192,16384));
  static_assert(vm::NativePageGuestLengthSafe(8192,4096));
  static_assert(!vm::NativePageGuestLengthSafe(0,4096));
  static_assert(!vm::NativePageGuestLengthSafe(4096,8192));
  vm::BoundedGuestAnonymousVM guest;
  assert(guest.Count()==0);
  auto fake=Map();
  fake.trapBoundaryAuthenticated=false;
  auto denied=guest.Dispatch(fake);
  assert(denied.guestReturn==-38 && !denied.nativeAnonymousMapCalled);
  assert(guest.Count()==0);
  fake=Map();fake.sourceRegisterMappingChecked=false;
  assert(guest.Dispatch(fake).guestReturn==-38);
  fake=Map();fake.hostSyscallDispatched=true;
  assert(guest.Dispatch(fake).guestReturn==-38);
  fake=Map();fake.guestMemoryDereferenced=true;
  assert(guest.Dispatch(fake).guestReturn==-38);
  assert(guest.Dispatch(Trap(abi::kOpenat)).guestReturn==-38);
  assert(guest.Dispatch(Trap(abi::kMprotect)).guestReturn==-38);
  assert(guest.Dispatch(Trap(abi::kMmap,0,4096,7,0x22,UINT64_MAX,0)).guestReturn==-22);
  assert(guest.Dispatch(Trap(abi::kMmap,4096,4096,3,0x22,UINT64_MAX,0)).guestReturn==-22);
  assert(guest.Dispatch(Trap(abi::kMmap,0,4096,3,0x32,UINT64_MAX,0)).guestReturn==-22);
  assert(guest.Dispatch(Trap(abi::kMmap,0,4096,3,0x22,0,0)).guestReturn==-22);
  assert(guest.Dispatch(Trap(abi::kMmap,0,4096,3,0x22,UINT64_MAX,4096)).guestReturn==-22);
  assert(guest.Dispatch(Map(8192*1024)).guestReturn==-22);
  assert(guest.Count()==0);

  auto opened=guest.Dispatch(Map());
  assert(opened.guestSyscallAuthenticated && opened.nativeAnonymousMapCalled);
  assert(opened.guestWritableDataMapped);
  assert(opened.guestReturn>65536 && !opened.hostAnyUntrustedSyscallForwarded);
  const uint64_t p=static_cast<uint64_t>(opened.guestReturn);
  assert(abi::CanonicalGuestPointer(p));
  assert(guest.Count()==1 && guest.AllocatedRequestedBytes()==4096);
  auto owner=guest.AuthenticatedRW(p,4096);
  assert(owner.attested && owner.guestRead && owner.guestWrite &&
         !owner.guestExecute && owner.start==p && owner.pastLast==p+4096);
  assert(!guest.AuthenticatedRW(p+4095,2).attested);
  assert(!guest.AuthenticatedRW(p-1,1).attested);
  // Real host mapping is writable, but the only exposed guest span is
  // the specifically registered owner-held x86 VMA.
  std::memset(reinterpret_cast<void*>(static_cast<uintptr_t>(p)),0x5a,4096);
  assert(*reinterpret_cast<const volatile uint8_t*>(static_cast<uintptr_t>(p))==0x5a);
  auto wrong=guest.Dispatch(Unmap(p+4096));
  assert(wrong.guestReturn==-22 && !wrong.nativeOwnedMapReleased);
  wrong=guest.Dispatch(Unmap(p,8192));
  assert(wrong.guestReturn==-22 && guest.Count()==1);
  // One-on-one guest VA -> host VMA exact unmap, no other guest memory.
  auto done=guest.Dispatch(Unmap(p));
  assert(done.guestReturn==0 && done.nativeOwnedMapReleased);
  assert(guest.Count()==0 && !guest.AuthenticatedRW(p,1).attested);
  assert(guest.Dispatch(Unmap(p)).guestReturn==-22);
  assert(guest.Reset());

  // All slots are independent; quota and source register provenance checked.
  for(size_t i=0;i<vm::BoundedGuestAnonymousVM::kSlots;++i){
    auto m=guest.Dispatch(Map());
    assert(m.guestReturn>0 && guest.Count()==i+1);
  }
  assert(guest.Dispatch(Map()).guestReturn==-12);
  assert(guest.Count()==vm::BoundedGuestAnonymousVM::kSlots);
  assert(guest.Reset() && guest.Count()==0);
  assert(guest.AllocatedRequestedBytes()==0);
  std::puts("KERNIX_G0_REAL_NATIVE_LINUX_X86_GUEST_ANON_MMAP_MUNMAP_OWNER_HELD_RW_AND_DENIALS_HOST_PASS_NOT_FEX_ANDROID");
  return 0;
}
