// SPDX-License-Identifier: MIT
// Original SHA256-locked x86 main + ld-linux + glibc guest bytes proof.
// Actual private-root POSIX file + immutable-memory read, NOT FEX execution.
#include "kernix_g0_original_guest_snapshot_table.h"
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <sys/mman.h>
#include <unistd.h>
namespace abi=kernix::g2e::c1;
namespace g0=kernix::g0;
static abi::TrapClassification GuestTrap(
 uint64_t no,uint64_t fd,uint64_t ptr=0,uint64_t n=0,uint64_t off=0) {
 abi::X86LinuxSyscallTrap regs{};
 regs.rax=no;regs.rdi=fd;regs.rsi=ptr;regs.rdx=n;regs.r10=off;
 regs.rip=0x440000001000;regs.rcxNext=regs.rip+2;
 regs.rsp=0x600000003ff0;
 abi::TrapClassification trap{};
 const abi::X86GuestStackBoundary stack{
     0x600000000000,0x600000004000,true};
 assert(abi::ClassifyVerifiedTrap(regs,stack,trap));
 return trap;
}
int main(int argc,char** argv) {
 if(argc!=2)return 2;
 const int rootfd=::open(argv[1],O_RDONLY|O_CLOEXEC|O_DIRECTORY|O_NOFOLLOW);
 if(rootfd<0)return 3;
 g0::OriginalGuestSnapshotTable table;
 std::string why;
 if(!table.MountVerifiedAppPrivateOriginalRoot(rootfd,why)) {
   std::fprintf(stderr,"G0_PINNED_GUEST_SOURCE_MOUNT_REJECTED=%s\n",why.c_str());
   ::close(rootfd);return 4;
 }
 assert(table.Mounted());
 // Authentication and snapshots MUST no longer require the root directory.
 assert(::close(rootfd)==0);
 const long size=::sysconf(_SC_PAGESIZE);
 assert(size>=4096 && size<=65536);
 void* buffer=::mmap(reinterpret_cast<void*>(0x0000400000000000ULL),
  static_cast<size_t>(size),PROT_READ|PROT_WRITE,
  MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
 assert(buffer!=MAP_FAILED);
 const auto va=static_cast<uint64_t>(reinterpret_cast<uintptr_t>(buffer));
 assert(abi::GuestRange(va,static_cast<uint64_t>(size)));
 const abi::GuestVmInterval guest{va,va+static_cast<uint64_t>(size),
                                true,true,false,true};
 // Three independent, authentically sourced guest file descriptions.
 for(uint64_t fd=3;fd<=5;++fd) {
   std::memset(buffer,0,64);
   const auto result=table.Dispatch(GuestTrap(abi::kRead,fd,va,32),guest);
   assert(result.authenticated && result.guestWritableSpanValidated);
   assert(result.readFromImmutableSnapshot && result.linuxReturn==32);
   assert(!result.anyHostSyscallForwarded);
   const auto* p=static_cast<const unsigned char*>(buffer);
   assert(p[0]==0x7f && p[1]=='E' && p[2]=='L' && p[3]=='F');
   assert(p[4]==2 && p[5]==1 && p[18]==62 && p[19]==0);
   // Seekless pread using x86-64 guest R10, never the host file position.
   const auto pread=table.Dispatch(GuestTrap(abi::kPread64,fd,va,32,0),guest);
   assert(pread.linuxReturn==32 && pread.readFromImmutableSnapshot);
   const auto afterPread=table.Dispatch(GuestTrap(abi::kRead,fd,va,32),guest);
   assert(afterPread.linuxReturn==32);
   // The second sequential read begins at offset 32, unlike pread.
   assert(static_cast<const unsigned char*>(buffer)[0]!=0x7f);
 }
 auto closed=table.Dispatch(GuestTrap(abi::kClose,4),guest);
 assert(closed.guestFdClosed && closed.linuxReturn==0);
 assert(table.Dispatch(GuestTrap(abi::kRead,4,va,32),guest).linuxReturn==-9);
 auto fake=guest;fake.attested=false;
 assert(table.Dispatch(GuestTrap(abi::kRead,3,va,32),fake).linuxReturn==-14);
 auto noWrite=guest;noWrite.guestWrite=false;
 assert(table.Dispatch(GuestTrap(abi::kRead,3,va,32),noWrite).linuxReturn==-14);
 assert(table.Dispatch(GuestTrap(abi::kRead,6,va,32),guest).linuxReturn==-9);
 assert(table.Dispatch(GuestTrap(abi::kOpenat,3,va,32),guest).linuxReturn==-38);
 assert(::munmap(buffer,static_cast<size_t>(size))==0);
 table.Reset();assert(!table.Mounted());
 std::puts("KERNIX_G0_REAL_ORIGINAL_SHA256_X86_MAIN_LDSO_GLIBC_SNAPSHOT_GUEST_READ_PREAD_CLOSE_SOURCE_PASS_NO_FEX_ANDROID");
}
