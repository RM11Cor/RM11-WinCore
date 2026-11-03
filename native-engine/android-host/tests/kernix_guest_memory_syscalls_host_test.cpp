// KERNIX bounded Linux mmap/munmap, write and getpid regression test.
// SPDX-License-Identifier: MIT; no x86 guest JIT executed in this host test.
#include "kernix_guest_memory_syscalls.h"
#include <cassert>
#include <cstdio>
#include <cstring>
int main(){
  constexpr uintptr_t code=0x400000;
  for(size_t i=0;i<kernix::kManagedSyscalls.size();++i){
    const auto e=kernix::kManagedSyscalls[i];
    assert(kernix::validateTrap(i,e.number,code,code+e.ripOffset,code+e.nextOffset));
    assert(!kernix::validateTrap(i,e.number+1,code,code+e.ripOffset,code+e.nextOffset));
    assert(!kernix::validateTrap(i,e.number,code,code+e.ripOffset+1,code+e.nextOffset));
    assert(!kernix::validateTrap(i,e.number,code,code+e.ripOffset,code+e.nextOffset+1));
  }
  assert(!kernix::validateTrap(4,11,code,code+100,code+102));
  kernix::ManagedGuestHeap heap;
  assert(!heap.allocate(1,kernix::kHeapSize,3,0x22,UINT64_MAX,0));
  assert(!heap.allocate(0,4096,3,0x22,UINT64_MAX,0));
  assert(!heap.allocate(0,kernix::kHeapSize,5,0x22,UINT64_MAX,0));
  assert(!heap.allocate(0,kernix::kHeapSize,3,0x22,1,0));
  assert(kernix::ManagedGuestHeap::isAnonymousFd(UINT64_MAX));
  assert(kernix::ManagedGuestHeap::isAnonymousFd(UINT32_MAX));
  assert(!kernix::ManagedGuestHeap::isAnonymousFd(0));
  assert(!kernix::ManagedGuestHeap::isAnonymousFd(1));
  assert(!kernix::ManagedGuestHeap::isAnonymousFd(0x12340000ffffffffULL));
  assert(heap.allocateChecked(0,kernix::kHeapSize,3,0x22,2,0) ==
         kernix::ManagedGuestHeap::AllocationResult::BadArguments);
  int hostError=-1;
  assert(heap.allocateChecked(0,kernix::kHeapSize,5,0x22,UINT64_MAX,0,
                              &hostError) ==
         kernix::ManagedGuestHeap::AllocationResult::BadArguments);
  assert(hostError==0);
  assert(heap.allocateChecked(0,kernix::kHeapSize,3,0x22,UINT32_MAX,0,
                              &hostError) ==
         kernix::ManagedGuestHeap::AllocationResult::Success);
  assert(hostError==0);
  assert(!heap.isUnmapped());
  assert(heap.address()!=0 && heap.address()%4096==0);
  assert(!heap.allocate(0,kernix::kHeapSize,3,0x22,UINT64_MAX,0));
  constexpr char msg[]="KERNIX_ELF_RW_MEMORY_PASS\n";
  static_assert(sizeof(msg)-1==26);
  assert(heap.containsExactMessage(heap.address(),26));
  assert(!heap.containsExactMessage(heap.address()+1,26));
  assert(!heap.containsExactMessage(heap.address(),27));
  assert(!heap.matches(msg,26));
  ::memcpy(reinterpret_cast<void*>(heap.address()),msg,26);
  assert(heap.matches(msg,26));
  assert(!heap.freeByGuest(heap.address(),4096));
  assert(!heap.freeByGuest(heap.address()+1,kernix::kHeapSize));
  assert(heap.freeByGuest(heap.address(),kernix::kHeapSize));
  assert(heap.isUnmapped());
  std::puts("KERNIX_GUEST_MANAGED_HEAP_AND_FOUR_SYSCALL_BOUNDARY_PASS");
}
