// SPDX-License-Identifier: MIT
// Test-only synthetic immutable-file mounting. Production must use
// MountVerifiedAppPrivateOriginalRoot() on SHA-pinned real x86 guest triad.
#define KERNIX_G0_SNAPSHOT_TABLE_UNIT_TEST_ONLY
#include "kernix_g0_original_guest_snapshot_table.h"
#include <array>
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <sys/mman.h>
#include <unistd.h>
namespace a=kernix::g2e::c1;
namespace g=kernix::g0;
static a::TrapClassification Trap(
 uint64_t n,uint64_t fd,uint64_t ptr=0,
 uint64_t len=0,uint64_t off=0) {
 a::X86LinuxSyscallTrap raw{};
 raw.rax=n;raw.rdi=fd;raw.rsi=ptr;raw.rdx=len;raw.r10=off;
 raw.rip=0x440000001000;raw.rcxNext=raw.rip+2;
 raw.rsp=0x600000003ff0;
 a::X86GuestStackBoundary stack{0x600000000000,0x600000004000,true};
 a::TrapClassification result{};
 assert(a::ClassifyVerifiedTrap(raw,stack,result));return result;
}
int main() {
 const long page=::sysconf(_SC_PAGESIZE);
 assert(page>=4096 && page<=65536);
 char main[]="GNU-x86-real-main-1234567890";
 char ldso[]="original-ld-linux-abcdefghijk";
 char libc[]="source-pinned-original-libc-xxxx";
 const std::array<std::pair<const uint8_t*,size_t>,3> data{{
  {reinterpret_cast<const uint8_t*>(main),sizeof(main)-1},
  {reinterpret_cast<const uint8_t*>(ldso),sizeof(ldso)-1},
  {reinterpret_cast<const uint8_t*>(libc),sizeof(libc)-1}
 }};
 g::OriginalGuestSnapshotTable table;
 std::string failure;
 assert(table.MountSyntheticBytesForHostUnitTest(data,failure));
 assert(table.Mounted() && failure=="none");
 // This must remain independent from mutable original source storage.
 std::memset(main,'Z',sizeof(main)-1);
 std::memset(ldso,'Y',sizeof(ldso)-1);
 std::memset(libc,'X',sizeof(libc)-1);
 void* p=::mmap(nullptr,static_cast<size_t>(page),PROT_READ|PROT_WRITE,
   MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
 assert(p!=MAP_FAILED);
 const auto addr=reinterpret_cast<uintptr_t>(p);
 assert(a::GuestRange(addr,static_cast<uint64_t>(page)));
 const a::GuestVmInterval writable{
   addr,addr+static_cast<uintptr_t>(page),true,true,false,true};
 auto mainRead=table.Dispatch(Trap(a::kRead,3,addr,8),writable);
 assert(mainRead.authenticated && mainRead.readFromImmutableSnapshot &&
        mainRead.guestWritableSpanValidated && !mainRead.anyHostSyscallForwarded &&
        mainRead.linuxReturn==8 && std::memcmp(p,"GNU-x86-",8)==0);
 auto mainNext=table.Dispatch(Trap(a::kRead,3,addr,5),writable);
 assert(mainNext.linuxReturn==5 && std::memcmp(p,"real-",5)==0);
 // pread of original immutable interpreter does NOT advance fd offset.
 auto pread=table.Dispatch(Trap(a::kPread64,4,addr,8,9),writable);
 assert(pread.linuxReturn==8 &&
        std::memcmp(p,"-ld-linu",8)==0);
 auto ldsoFromStart=table.Dispatch(Trap(a::kRead,4,addr,8),writable);
 assert(ldsoFromStart.linuxReturn==8 &&
        std::memcmp(p,"original",8)==0);
 auto libcFirst=table.Dispatch(Trap(a::kRead,5,addr,13),writable);
 assert(libcFirst.linuxReturn==13 &&
        std::memcmp(p,"source-pinned",13)==0);
 auto tail=table.Dispatch(Trap(a::kPread64,3,addr,200,26),writable);
 assert(tail.linuxReturn==2 && std::memcmp(p,"90",2)==0);
 assert(table.Dispatch(Trap(a::kPread64,3,addr,7,28),writable).linuxReturn==0);
 // Unsupported guest paths / FDs cannot be opened by this table.
 assert(table.Dispatch(Trap(a::kRead,2,addr,1),writable).linuxReturn==-9);
 assert(table.Dispatch(Trap(a::kRead,6,addr,1),writable).linuxReturn==-9);
 assert(table.Dispatch(Trap(a::kPread64,3,addr,4097,0),writable).linuxReturn==-22);
 assert(table.Dispatch(Trap(a::kPread64,3,addr,2,UINT64_MAX),writable).linuxReturn==-22);
 assert(table.Dispatch(Trap(a::kPread64,3,
   addr+static_cast<uintptr_t>(page)-1,2,0),writable).linuxReturn==-14);
 a::GuestVmInterval ro=writable;ro.guestWrite=false;
 assert(table.Dispatch(Trap(a::kRead,3,addr,1),ro).linuxReturn==-14);
 a::GuestVmInterval fake=writable;fake.attested=false;
 assert(table.Dispatch(Trap(a::kRead,3,addr,1),fake).linuxReturn==-14);
 auto stale=Trap(a::kRead,3,addr,1);stale.trapBoundaryAuthenticated=false;
 assert(table.Dispatch(stale,writable).linuxReturn==-38);
 assert(table.Dispatch(Trap(a::kClose,4),writable).guestFdClosed);
 assert(table.Dispatch(Trap(a::kPread64,4,addr,1),writable).linuxReturn==-9);
 // Other original 2 source FDs remain owner-held until full process cleanup.
 assert(table.Dispatch(Trap(a::kPread64,5,addr,4,0),writable).linuxReturn==4);
 auto pathOpen=Trap(a::kOpenat,3,addr,8);
 assert(table.Dispatch(pathOpen,writable).linuxReturn==-38);
 table.Reset();assert(!table.Mounted());
 assert(table.Dispatch(Trap(a::kRead,3,addr,1),writable).linuxReturn==-38);
 assert(::munmap(p,static_cast<size_t>(page))==0);
 std::puts("KERNIX_G0_ORIGINAL_THREE_IMMUTABLE_SNAPSHOT_VIRTUAL_FDS_READ_PREAD64_CLOSE_HOST_PASS_NO_FEX_ANDROID");
}
