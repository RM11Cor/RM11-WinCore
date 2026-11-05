// SPDX-License-Identifier: MIT
// POSIX native VM/pipe test. Test trap is constructed; not real FEX execution.
#include "kernix_g0_guest_syscall_dispatch.h"
#include <cassert>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <unistd.h>
#include <sys/mman.h>
namespace a=kernix::g2e::c1;
namespace g=kernix::g0;
static a::TrapClassification Verified(uint64_t n,uint64_t p0=0,uint64_t p1=0,uint64_t p2=0) {
 a::X86LinuxSyscallTrap in{};
 in.rax=n;in.rdi=p0;in.rsi=p1;in.rdx=p2;
 in.rip=0x440000001000;in.rcxNext=in.rip+2;in.rsp=0x600000003ff0;
 const a::X86GuestStackBoundary stack{0x600000000000,0x600000004000,true};
 a::TrapClassification out{};
 assert(a::ClassifyVerifiedTrap(in,stack,out));return out;
}
int main() {
 long ps=::sysconf(_SC_PAGESIZE);assert(ps>=4096&&ps<=65536);
 void* mem=::mmap(nullptr,(size_t)ps,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
 assert(mem!=MAP_FAILED);
 uint64_t va=(uint64_t)(uintptr_t)mem;
 assert(a::GuestRange(va,(size_t)ps));
 constexpr char payload[]="KERNIX_G0_REAL_GUEST_WRITE_BYTES\n";
 std::memcpy(mem,payload,sizeof(payload)-1);
 assert(::mprotect(mem,(size_t)ps,PROT_READ)==0);
 a::GuestVmInterval bytes{va,va+(uint64_t)ps,true,false,false,true};
 int p[2]={-1,-1};assert(::pipe(p)==0);
 auto result=g::DispatchVerifiedGuestTrap(Verified(a::kWrite,1,va,sizeof(payload)-1),bytes,p[1]);
 assert(result.event==g::Event::WroteGuestData&&result.guestBytesValidated&&
        result.hostWriteCalled&&result.guestReturn==(int64_t)sizeof(payload)-1);
 char buf[sizeof(payload)]{};
 assert(::read(p[0],buf,sizeof(buf)-1)==(ssize_t)sizeof(payload)-1);
 assert(std::memcmp(buf,payload,sizeof(payload)-1)==0);
 assert(g::DispatchVerifiedGuestTrap(Verified(a::kWrite,2,va,1),bytes,p[1]).guestReturn==-9);
 assert(g::DispatchVerifiedGuestTrap(Verified(a::kWrite,1,va+(uint64_t)ps-1,2),bytes,p[1]).guestReturn==-14);
 assert(g::DispatchVerifiedGuestTrap(Verified(a::kWrite,1,va,g::kMaxSingleWrite+1),bytes,p[1]).guestReturn==-22);
 assert(g::DispatchVerifiedGuestTrap(Verified(a::kWrite,1,va,1),bytes,-1).guestReturn==-9);
 auto forged=bytes;forged.attested=false;
 assert(g::DispatchVerifiedGuestTrap(Verified(a::kWrite,1,va,1),forged,p[1]).guestReturn==-14);
 auto spoof=Verified(a::kWrite,1,va,1);spoof.trapBoundaryAuthenticated=false;
 assert(g::DispatchVerifiedGuestTrap(spoof,bytes,p[1]).event==g::Event::Denied);
 assert(g::DispatchVerifiedGuestTrap(Verified(a::kArchPrctl,0x1002,va),bytes,p[1]).guestReturn==-38);
 assert(g::DispatchVerifiedGuestTrap(Verified(a::kMmap,0,4096),bytes,p[1]).guestReturn==-38);
 const auto id=g::DispatchVerifiedGuestTrap(Verified(a::kGetpid),bytes,-1);
 assert(id.event==g::Event::ReturnedRealPid&&id.guestReturn==getpid()&&!id.hostProcessExited);
 const auto end=g::DispatchVerifiedGuestTrap(Verified(a::kExitGroup,11),bytes,-1);
 assert(end.event==g::Event::ExitRequested&&end.guestExitRequested&&
        end.guestExitCode==11&&!end.hostProcessExited);
 assert(::close(p[0])==0&&::close(p[1])==0&&::munmap(mem,(size_t)ps)==0);
 std::puts("KERNIX_G0_GUEST_WRITE_PID_EXIT_BRIDGE_HOST_TEST_PASS_NO_FEX_ANDROID_DEVICE");
}
