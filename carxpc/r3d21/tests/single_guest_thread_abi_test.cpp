#include "carxpc/r3d21/native/single_guest_thread_abi.hpp"
#include <cassert>
#include <cstdio>
#include <cerrno>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/syscall.h>
int main(){
  using namespace carx_r3d21;
  carx_r3d19::GuestMappings maps{};
  const int64_t mapped=maps.map(-1,false,0,8192,
    PROT_READ|PROT_WRITE,
    carx_r3d19::kLinuxMapPrivate|carx_r3d19::kLinuxMapAnonymous,
    ~uint64_t(0),0);
  assert(mapped>0);
  const auto owned=[&](uint64_t p,uint64_t len){
    return maps.owned_range(p,len);
  };
  ThreadABI thread{};
  const int64_t actualNativeTid=::syscall(SYS_gettid);
  assert(actualNativeTid>0);
  const uint64_t child=static_cast<uint64_t>(mapped)+0x3d0;
  // Source-known sample 0x...63d0 points into mapped 0x...5000 + 0x13d0.
  const int64_t realTid=thread.register_guest_clear_child_tid(child,owned);
  assert(realTid==actualNativeTid && thread.registeredChildTid);
  assert(thread.clearChildTid==child && thread.guest_gettid()==realTid);
  assert(thread.guest_getpid()==::getpid() && thread.pid>0);
  // Return value is current TID, not an invented constant, and does NOT
  // dereference/write the clear-child-tid address at registration time.
  assert(*reinterpret_cast<const uint32_t*>(uintptr_t(child))==0);
  assert(thread.register_guest_clear_child_tid(child+1,owned)==-EFAULT);
  assert(thread.register_guest_clear_child_tid(
    uint64_t(mapped)+8192,owned)==-EFAULT);
  assert(thread.register_guest_clear_child_tid(0,owned)==actualNativeTid);
  assert(thread.clearChildTid==0);
  const uint64_t robust=static_cast<uint64_t>(mapped)+0x100;
  assert(thread.register_guest_robust_list(
    robust,kRobustListHead64Size,owned)==0);
  assert(thread.registeredRobustList && thread.robustListHead==robust);
  assert(thread.register_guest_robust_list(robust,16,owned)==-EINVAL);
  assert(thread.register_guest_robust_list(robust+1,24,owned)==-EFAULT);
  assert(thread.register_guest_robust_list(0x1234,24,owned)==-EFAULT);
  assert(thread.unsupported_guest_rseq(robust,kRseqGuestStructSize,0,0)
         ==-ENOSYS);
  assert(thread.rseqUnavailableProbed);
  // No host kernel set_tid_address is performed; host current thread ID
  // remains stable and ownership checks prevent arbitrary guest pointers.
  assert(::syscall(SYS_gettid)==actualNativeTid);
  assert(maps.unmap(uint64_t(mapped),8192)==0);
  std::puts("R3D21_REAL_SINGLE_WORKER_TID_GUEST_CHILD_TID_ROBUST_HEAD_RSEQ_ENOSYS_TEST_PASS");
}
