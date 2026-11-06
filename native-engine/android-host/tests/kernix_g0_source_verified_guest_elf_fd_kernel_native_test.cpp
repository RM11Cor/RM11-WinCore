// SPDX-License-Identifier: MIT
// G0: actual three SHA256-locked original GNU/Linux x86 ELF files,
// independent immutable snapshots, Linux guest synthetic FDs and
// authenticated owner-only read/pread64, never host guest pathname.
#include "kernix_g0_source_verified_guest_elf_fd_kernel.h"
#include <array>
#include <cassert>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <sys/mman.h>
#include <unistd.h>
namespace a=kernix::g2e::c1;
namespace g=kernix::g0;
static a::TrapClassification Trap(
 uint64_t no,uint64_t x=0,uint64_t y=0,uint64_t z=0,
 uint64_t d=0,uint64_t e=0,uint64_t f=0){
  a::X86LinuxSyscallTrap cpu{};
  cpu.rax=no;cpu.rdi=x;cpu.rsi=y;cpu.rdx=z;
  cpu.r10=d;cpu.r8=e;cpu.r9=f;
  cpu.rip=0x0000440000001000ULL;cpu.rcxNext=cpu.rip+2;
  cpu.rsp=0x0000600000003ff0ULL;
  const a::X86GuestStackBoundary stack{
      0x0000600000000000ULL,0x0000600000004000ULL,true};
  a::TrapClassification result{};
  assert(a::ClassifyVerifiedTrap(cpu,stack,result));
  return result;
}
static void Put(uint64_t addr,const char* path){
  std::memcpy(reinterpret_cast<void*>(static_cast<uintptr_t>(addr)),
              path,std::strlen(path)+1);
}
static uint64_t FdOpen(g::SourceVerifiedGuestElfFDKernel& fd,
 g::BoundedGuestAnonymousVM& vm,uint64_t path,
 uint64_t flags=0x80000, uint64_t dirfd=static_cast<uint64_t>(int64_t(-100))){
  const auto res=fd.Dispatch(Trap(a::kOpenat,dirfd,path,flags,0),vm);
  assert(res.guestReturn>=100 && res.guestReturn<108 &&
         res.openedPinnedReadonlySnapshot &&
         !res.hostPathOpened && !res.hostGuestFdForwarded &&
         !res.hostAnyUntrustedSyscallForwarded);
  return static_cast<uint64_t>(res.guestReturn);
}
static void Bad(g::SourceVerifiedGuestElfFDKernel& fd,
 g::BoundedGuestAnonymousVM& vm,a::TrapClassification t,int64_t err){
  const auto r=fd.Dispatch(t,vm);
  assert(r.guestReturn==err && !r.openedPinnedReadonlySnapshot &&
         !r.copiedSnapshotToAuthenticatedGuestWritable &&
         !r.hostPathOpened && !r.hostGuestFdForwarded &&
         !r.hostAnyUntrustedSyscallForwarded);
}
int main(int argc,char** argv){
  if(argc!=2 || !argv[1] || argv[1][0]!='/')return 2;
  const std::string base(argv[1]);
  const std::array<std::string,3> paths{{
     base+"/bin/kernix-g2e-dynamic-guest",
     base+"/lib64/ld-linux-x86-64.so.2",
     base+"/lib/x86_64-linux-gnu/libc.so.6"
  }};
  std::array<int,3> input{{-1,-1,-1}};
  for(size_t i=0;i<paths.size();++i){
    input[i]=::open(paths[i].c_str(),O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
    assert(input[i]>=0);
  }
  g::SourceVerifiedGuestElfFDKernel files;
  assert(files.BindSourceOriginalTriad(input));
  assert(files.Bound() && files.OpenCount()==0);
  for(const int f:input)assert(::close(f)==0);
  g::BoundedGuestAnonymousVM vm;
  const auto mapped=vm.Dispatch(Trap(a::kMmap,0,4096,3,0x22,UINT64_MAX,0));
  assert(mapped.guestReturn>65536);
  const uint64_t page=static_cast<uint64_t>(mapped.guestReturn);
  const uint64_t path=page+64;
  const uint64_t output=page+512;
  Bad(files,vm,Trap(a::kOpenat,uint64_t(int64_t(-100)),0x50000000000ULL,0x80000,0),-14);
  Bad(files,vm,Trap(a::kOpenat,uint64_t(int64_t(-100)),path,0x80000,0),-2);
  Put(path,"/etc/passwd");
  Bad(files,vm,Trap(a::kOpenat,uint64_t(int64_t(-100)),path,0x80000,0),-2);
  Put(path,"/lib64/../lib/x86_64-linux-gnu/libc.so.6");
  Bad(files,vm,Trap(a::kOpenat,uint64_t(int64_t(-100)),path,0x80000,0),-2);
  Put(path,"/lib64/ld-linux-x86-64.so.2");
  Bad(files,vm,Trap(a::kOpenat,uint64_t(int64_t(-100)),path,0,0),-22);
  Bad(files,vm,Trap(a::kOpenat,uint64_t(int64_t(-100)),path,0x80000|2,0),-22);
  Bad(files,vm,Trap(a::kOpenat,uint64_t(int64_t(-100)),path,0x80000,0644),-22);
  Bad(files,vm,Trap(a::kOpenat,3,path,0x80000,0),-22);
  auto fake=Trap(a::kOpenat,uint64_t(int64_t(-100)),path,0x80000,0);
  fake.trapBoundaryAuthenticated=false;Bad(files,vm,fake,-38);
  const uint64_t ld=FdOpen(files,vm,path);
  assert(files.OpenCount()==1);
  auto pre=files.Dispatch(Trap(a::kPread64,ld,output,64,0),vm);
  assert(pre.guestReturn==64 && pre.copiedSnapshotToAuthenticatedGuestWritable);
  const unsigned char* bytes=reinterpret_cast<const unsigned char*>(
     static_cast<uintptr_t>(output));
  const unsigned char elfMagic[4]={0x7f,'E','L','F'};
  assert(std::memcmp(bytes,elfMagic,4)==0);
  std::array<unsigned char,64> original{};
  std::memcpy(original.data(),bytes,64);
  pre=files.Dispatch(Trap(a::kRead,ld,output+128,64),vm);
  assert(pre.guestReturn==64);
  assert(std::memcmp(reinterpret_cast<const void*>(
     static_cast<uintptr_t>(output+128)),original.data(),64)==0);
  pre=files.Dispatch(Trap(a::kRead,ld,output+192,64),vm);
  assert(pre.guestReturn==64);
  assert(std::memcmp(reinterpret_cast<const void*>(
     static_cast<uintptr_t>(output+192)),original.data(),64)!=0);
  pre=files.Dispatch(Trap(a::kPread64,ld,output+256,64,0),vm);
  assert(pre.guestReturn==64);
  assert(std::memcmp(reinterpret_cast<const void*>(
     static_cast<uintptr_t>(output+256)),original.data(),64)==0);
  Bad(files,vm,Trap(a::kPread64,ld,output,4097,0),-22);
  Bad(files,vm,Trap(a::kPread64,ld,page+4096-4,16,0),-14);
  Bad(files,vm,Trap(a::kPread64,3,output,32,0),-9);
  Bad(files,vm,Trap(a::kPread64,ld,0x11000000000ULL,32,0),-14);
  // Native file mutation after exact original snapshot must not alter
  // data supplied to x86; source files are disposable CI copies.
  int alter=::open(paths[1].c_str(),O_RDWR|O_CLOEXEC|O_NOFOLLOW);
  assert(alter>=0);
  unsigned char actual=0,changed=0;
  assert(::pread(alter,&actual,1,0)==1);
  changed=static_cast<unsigned char>(actual^0x5a);
  assert(::pwrite(alter,&changed,1,0)==1);
  auto immutable=files.Dispatch(Trap(a::kPread64,ld,output,64,0),vm);
  assert(immutable.guestReturn==64);
  assert(std::memcmp(reinterpret_cast<const void*>(
     static_cast<uintptr_t>(output)),original.data(),64)==0);
  // Reattestation MUST reject a mutated source.
  g::SourceVerifiedGuestElfFDKernel invalid;
  std::array<int,3> alteredFds{};
  for(size_t i=0;i<paths.size();++i){
    alteredFds[i]=::open(paths[i].c_str(),O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
    assert(alteredFds[i]>=0);
  }
  assert(!invalid.BindSourceOriginalTriad(alteredFds) &&
         !invalid.Bound());
  for(const int f:alteredFds)assert(::close(f)==0);
  assert(::pwrite(alter,&actual,1,0)==1);
  assert(::close(alter)==0);
  // Guest libc/loader sources are distinct read-only virtual files.
  Put(path,"/lib/x86_64-linux-gnu/libc.so.6");
  const uint64_t libc=FdOpen(files,vm,path);
  pre=files.Dispatch(Trap(a::kPread64,libc,output,64,0),vm);
  assert(pre.guestReturn==64 &&
         std::memcmp(reinterpret_cast<const void*>(
         static_cast<uintptr_t>(output)),elfMagic,4)==0);
  Put(path,"/bin/kernix-g2e-dynamic-guest");
  const uint64_t main=FdOpen(files,vm,path);
  assert(files.OpenCount()==3);
  pre=files.Dispatch(Trap(a::kPread64,main,output,64,0),vm);
  assert(pre.guestReturn==64 &&
         std::memcmp(reinterpret_cast<const void*>(
         static_cast<uintptr_t>(output)),elfMagic,4)==0);
  pre=files.Dispatch(Trap(a::kPread64,main,output,64,15976),vm);
  assert(pre.guestReturn==0); // source real exact EOF
  pre=files.Dispatch(Trap(a::kPread64,main,output,64,INT64_MAX+1ULL),vm);
  assert(pre.guestReturn==-22);
  // mprotect RO forbids guest writes; immutable snapshot stays private.
  const auto ro=vm.Dispatch(Trap(a::kMprotect,page,4096,PROT_READ));
  assert(ro.guestReturn==0 && !vm.AuthenticatedRW(page,32).guestWrite);
  Bad(files,vm,Trap(a::kPread64,ld,output,32,0),-14);
  const auto closeLD=files.Dispatch(Trap(a::kClose,ld),vm);
  assert(closeLD.guestReturn==0 && closeLD.guestFdClosed);
  Bad(files,vm,Trap(a::kPread64,ld,output,32,0),-9);
  for(uint64_t fd:{libc,main}){
    assert(files.Dispatch(Trap(a::kClose,fd),vm).guestReturn==0);
  }
  assert(files.OpenCount()==0);
  const auto release=vm.Dispatch(Trap(a::kMunmap,page,4096));
  assert(release.guestReturn==0 && vm.Count()==0);
  files.Reset();
  assert(!files.Bound());
  assert(vm.Reset());
  std::puts("KERNIX_G0_EXACT_SOURCE_ELF_GUEST_OPENAT_READ_PREAD64_CLOSE_IMMUTABLE_SNAPSHOT_OWNER_ONLY_NATIVE_LINUX_PASS_NOT_FEX_OR_PHONE");
  return 0;
}
