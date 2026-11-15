// SPDX-License-Identifier: MIT
// R3D16: capture the string of the original x86 ld.so 4th openat from the
// already-reserved 64KiB guest stack. Read-only, no syscall forwarding.
#pragma once
#include <cstddef>
#include <cstdint>
#include <cerrno>
#include <sys/uio.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <fcntl.h>
namespace carx_r3d16 {
constexpr uint64_t kStackTop=0x0000007000000000ULL;
constexpr uint64_t kStackSize=65536ULL;
constexpr size_t kMaxPathBytes=255;
inline bool capture_guest_stack_ascii_path(uint64_t ptr,char (&out)[256]) noexcept {
  for(char &c:out)c='\0';
  if(ptr<kStackTop-kStackSize || ptr>=kStackTop || ptr>kStackTop-2)return false;
  const size_t length=static_cast<size_t>(
    ((kStackTop-ptr)<kMaxPathBytes+1)?(kStackTop-ptr):(kMaxPathBytes+1));
  long n=-1;
#if defined(SYS_process_vm_readv)
  struct iovec local{out,length};
  struct iovec remote{reinterpret_cast<void*>(static_cast<uintptr_t>(ptr)),length};
  n=::syscall(SYS_process_vm_readv,::getpid(),&local,1UL,&remote,1UL,0UL);
  if(n<0 && errno!=ENOSYS && errno!=EPERM && errno!=EACCES)return false;
#endif
  if(n<0){
    const int fd=::open("/proc/self/mem",O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
    if(fd>=0){n=::pread(fd,out,length,static_cast<off_t>(ptr));::close(fd);}
  }
  if(n<=0 || n>static_cast<long>(length))return false;
  for(long i=0;i<n;++i){
    const auto c=static_cast<unsigned char>(out[i]);
    if(c==0)return i>0;
    if(c<0x20 || c>0x7e)return false;
  }
  for(char &c:out)c='\0';
  return false;
}
}