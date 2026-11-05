// SPDX-License-Identifier: MIT
// Real POSIX owned-file pread64->guest writable VM behavior and negative
// boundary tests. Synthetic authenticated test trap: NOT FEX device execution.
#include "kernix_g0_guest_syscall_dispatch.h"
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <limits>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
namespace abi=kernix::g2e::c1;
namespace g0=kernix::g0;

static abi::TrapClassification GuestPread(
    uint64_t fd,uint64_t va,uint64_t bytes,uint64_t offset) {
  abi::X86LinuxSyscallTrap cpu{};
  cpu.rax=abi::kPread64;
  cpu.rdi=fd;cpu.rsi=va;cpu.rdx=bytes;cpu.r10=offset;
  cpu.rip=0x440000001000ULL;
  cpu.rcxNext=cpu.rip+2;
  cpu.rsp=0x600000003ff0ULL;
  abi::X86GuestStackBoundary stack{
     0x600000000000ULL,0x600000004000ULL,true};
  abi::TrapClassification trap{};
  assert(abi::ClassifyVerifiedTrap(cpu,stack,trap));
  assert(trap.args[3]==offset);
  return trap;
}
int main() {
  const long pagesz=::sysconf(_SC_PAGESIZE);
  assert(pagesz>=4096 && pagesz<=65536);
  void* vm=::mmap(nullptr,static_cast<size_t>(pagesz),
     PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
  assert(vm!=MAP_FAILED);
  const uint64_t ptr=static_cast<uint64_t>(reinterpret_cast<uintptr_t>(vm));
  assert(abi::GuestRange(ptr,static_cast<uint64_t>(pagesz)));
  const abi::GuestVmInterval guestWritable{
     ptr,ptr+static_cast<uint64_t>(pagesz),true,true,false,true};
  constexpr char fileBytes[]="KERNIX_PINNED_GUEST_ELF_RO_CONTENT_0123456789";
  constexpr size_t length=sizeof(fileBytes)-1;

  char name[]="/tmp/kernix-g0-verified-ro-XXXXXX";
  const int writer=::mkstemp(name);
  assert(writer>=0);
  assert(::write(writer,fileBytes,length)==static_cast<ssize_t>(length));
  assert(::fchmod(writer,0400)==0);
  const int fd=::open(name,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
  assert(fd>=0);
  assert(::unlink(name)==0);
  assert(::lseek(fd,3,SEEK_SET)==3);
  const g0::PinnedReadOnlyGuestFile source{3,fd,length,true,true};
  const auto pass=g0::DispatchVerifiedGuestTrap(
       GuestPread(3,ptr,9,7),guestWritable,-1,source);
  assert(pass.event==g0::Event::ReadPinnedGuestFile);
  assert(pass.guestReturn==9 && pass.guestBytesValidated);
  assert(pass.hostPreadCalled && !pass.hostWriteCalled &&
         !pass.hostProcessExited);
  assert(std::memcmp(vm,fileBytes+7,9)==0);
  assert(::lseek(fd,0,SEEK_CUR)==3); // pread preserves original host FD cursor

  // Actual last few source bytes: no cross-file reading, clean EOF.
  const auto shortRead=g0::DispatchVerifiedGuestTrap(
       GuestPread(3,ptr,9,length-2),guestWritable,-1,source);
  assert(shortRead.event==g0::Event::ReadPinnedGuestFile);
  assert(shortRead.guestReturn==2);
  assert(std::memcmp(vm,fileBytes+length-2,2)==0);
  assert(g0::DispatchVerifiedGuestTrap(
       GuestPread(3,ptr,9,length),guestWritable,-1,source).guestReturn==0);

  // Every guest-supplied path/FD remains denied; only host-pinned fd 3.
  assert(g0::DispatchVerifiedGuestTrap(
       GuestPread(5,ptr,1,0),guestWritable,-1,source).guestReturn==-9);
  auto forged=source;
  forged.sourceSha256Verified=false;
  assert(g0::DispatchVerifiedGuestTrap(
       GuestPread(3,ptr,1,0),guestWritable,-1,forged).guestReturn==-9);
  forged=source;forged.ownerHeldNoFollowFd=false;
  assert(g0::DispatchVerifiedGuestTrap(
       GuestPread(3,ptr,1,0),guestWritable,-1,forged).guestReturn==-9);
  forged=source;forged.exactVerifiedSize=length+1;
  assert(g0::DispatchVerifiedGuestTrap(
       GuestPread(3,ptr,1,0),guestWritable,-1,forged).guestReturn==-9);
  forged=source;forged.hostFd=writer; // Writable FD must NEVER be read from guest.
  assert(g0::DispatchVerifiedGuestTrap(
       GuestPread(3,ptr,1,0),guestWritable,-1,forged).guestReturn==-9);

  // No guest memory change from denial, oversized count, invalid pointer,
  // stale attestation or a read-only destination.
  const auto invalidPtr=g0::DispatchVerifiedGuestTrap(
       GuestPread(3,ptr+static_cast<uint64_t>(pagesz)-1,2,0),
       guestWritable,-1,source);
  assert(invalidPtr.guestReturn==-14 && !invalidPtr.hostPreadCalled);
  const auto oversized=g0::DispatchVerifiedGuestTrap(
       GuestPread(3,ptr,g0::kMaxSinglePinnedPread+1,0),
       guestWritable,-1,source);
  assert(oversized.guestReturn==-22 && !oversized.hostPreadCalled);
  auto readOnly=guestWritable;readOnly.guestWrite=false;
  assert(g0::DispatchVerifiedGuestTrap(
       GuestPread(3,ptr,1,0),readOnly,-1,source).guestReturn==-14);
  auto stale=guestWritable;stale.attested=false;
  assert(g0::DispatchVerifiedGuestTrap(
       GuestPread(3,ptr,1,0),stale,-1,source).guestReturn==-14);
  auto badTrap=GuestPread(3,ptr,1,0);
  badTrap.trapBoundaryAuthenticated=false;
  assert(g0::DispatchVerifiedGuestTrap(
       badTrap,guestWritable,-1,source).event==g0::Event::Denied);
  assert(g0::DispatchVerifiedGuestTrap(
       GuestPread(3,ptr,1,std::numeric_limits<uint64_t>::max()),
       guestWritable,-1,source).guestReturn==-22);

  abi::TrapClassification ordinary{};
  ordinary.guestNumber=abi::kOpenat;
  ordinary.trapBoundaryAuthenticated=true;
  ordinary.sourceRegisterMappingChecked=true;
  assert(g0::DispatchVerifiedGuestTrap(
       ordinary,guestWritable,-1,source).guestReturn==-38);
  assert(::close(fd)==0 && ::close(writer)==0);
  assert(::munmap(vm,static_cast<size_t>(pagesz))==0);
  std::puts("KERNIX_G0_PINNED_GUEST_PREAD64_REAL_RO_FILE_TO_WRITABLE_VM_PASS_HOST_NO_FEX_ANDROID");
}
