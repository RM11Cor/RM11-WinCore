#include "carxpc/r3d25/native/verified_multi_elf_syscall.hpp"
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cerrno>
#include <vector>
#include <array>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
int main(){
 using namespace carx_r3d25;
 // Exact source x86 0F05, never synthetic return without source proof.
 std::array<uint8_t,8192> wine{};
 wine[0x80]=0x0F;wine[0x81]=0x05;
 const carx_r3d3::Load wl{0x4000000000ULL,0,0,wine.size(),true};
 carx_r3d3::Record wr{};
 assert(carx_r3d3::make_record(wine.data(),wine.size(),&wl,1,
         wl.bias+0x80,39,7,&wr));
 assert(wr.source_file_offset==0x80 && wr.guest_syscall_number==39);
 wine[0x80]=0x00;
 assert(!carx_r3d3::make_record(wine.data(),wine.size(),&wl,1,
         wl.bias+0x80,39,7,&wr));
 // A verified rootfs libc-style readonly fd with original syscall at file
 // offset 0x1000+0x80, copied to owned guest RX pages at mapped base.
 char path[]="/tmp/carx-r3d25-source-XXXXXX";
 int fd=mkstemp(path);assert(fd>=0);
 unlink(path);
 std::array<unsigned char,8192> source{};
 source[0x1080]=0x0F;source[0x1081]=0x05;
 assert(write(fd,source.data(),source.size())==ssize_t(source.size()));
 void* p=mmap(nullptr,4096,PROT_READ|PROT_WRITE,
              MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
 assert(p!=MAP_FAILED);
 std::memcpy(reinterpret_cast<unsigned char*>(p),source.data()+4096,4096);
 assert(mprotect(p,4096,PROT_READ|PROT_EXEC)==0);
 carx_r3d23::BoundedExecVMAs exec{};
 const auto base=uint64_t(reinterpret_cast<uintptr_t>(p));
 assert(exec.replace_permissions(base,4096,true));
 RootfsLibcSource libs{};
 assert(libs.observe_mmap(base,4096,true,true,4096));
 const auto owned=[&](uint64_t addr){return exec.find(addr);};
 carx_r3d3::Record rr{};
 assert(libs.make_record(fd,base+0x80,334,999,owned,&rr));
 assert(rr.source_file_offset==0x1080);
 assert(rr.opcode_guest_rip==base+0x80);
 assert(rr.guest_syscall_number==334);
 assert(libs.make_record(fd,base+0x82,334,999,owned,&rr));
 assert(rr.interpretation==carx_r3d3::kObservedBeforeRip);
 assert(!libs.make_record(fd,base+0x200,334,999,owned,&rr));
 // W^X and stale RX provenanced removed on mprotect; previously observed
 // source bytes MUST NOT be used after permission change.
 assert(mprotect(p,4096,PROT_READ|PROT_WRITE)==0);
 assert(exec.replace_permissions(base,4096,false));
 libs.invalidate(base,4096);
 assert(!libs.make_record(fd,base+0x80,334,999,owned,&rr));
 // Unknown/ambiguous syscall sources never accepted.
 Source selection=Source::None;
 carx_r3d3::Record res{};
 const auto okgnu=[&](carx_r3d3::Record* r){*r=wr;return true;};
 const auto okw=[&](carx_r3d3::Record* r){*r=wr;return true;};
 const auto no=[&](carx_r3d3::Record*){return false;};
 assert(select_exactly_one(okgnu,no,no,selection,res));
 assert(selection==Source::GNU_LDSO);
 assert(!select_exactly_one(okgnu,okw,no,selection,res));
 assert(selection==Source::None);
 assert(!select_exactly_one(no,no,no,selection,res));
 assert(munmap(p,4096)==0);
 close(fd);
 std::puts("R3D25_GNU_WINE_LIBC_MULTI_ELF_SOURCE_LOCK_AND_LIVE_RX_OPCODE_TEST_PASS");
}
