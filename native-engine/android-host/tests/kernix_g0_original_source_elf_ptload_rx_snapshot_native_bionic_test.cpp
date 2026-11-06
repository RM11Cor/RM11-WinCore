// SPDX-License-Identifier: MIT
// G0: actual three SHA256-locked original GNU/Linux x86 ELF files,
// independent immutable snapshots, Linux guest synthetic FDs and
// authenticated owner-only read/pread64 and TRUE NATIVE mprotect RO
// on copied SHA256 original ELF source; only genuine PF_R|PF_X
// PT_LOAD whole native-page snapshots can receive RX; never RWX.
#include "kernix_g0_source_verified_guest_elf_fd_kernel.h"
#include <array>
#include <cassert>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <elf.h>
#include <limits>
#include <fcntl.h>
#include <fstream>
#include <sstream>
#include <string>
#include <sys/mman.h>
#include <unistd.h>
namespace a=kernix::g2e::c1;
namespace g=kernix::g0;
static std::string NativeRights(uint64_t address){
  std::ifstream maps("/proc/self/maps");
  std::string line;
  while(std::getline(maps,line)){
    const auto dash=line.find('-'),sp=line.find(' ');
    if(dash==std::string::npos || sp==std::string::npos)continue;
    uint64_t a=0,b=0;
    try{
      a=std::stoull(line.substr(0,dash),nullptr,16);
      b=std::stoull(line.substr(dash+1,sp-dash-1),nullptr,16);
    }catch(...){continue;}
    if(address<a || address>=b)continue;
    std::string rights;
    std::istringstream iss(line.substr(sp+1));
    iss>>rights;return rights;
  }
  return {};
}

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
         !r.readonlySourceELFSnapshotMapped &&
         !r.guestReadonlySourceELFNativeProtectionApplied &&
         !r.executableSourceELFSnapshotMapped &&
         !r.guestExecutableSourceELFNativeProtectionApplied &&
         !r.hostPathOpened && !r.hostGuestFdForwarded &&
         !r.hostAnyUntrustedSyscallForwarded);
}
int main(int argc,char** argv){
  if(argc!=2 || !argv[1] || argv[1][0]!='/')return 2;
  static_assert(!g::NativePageGuestLengthSafe(4096,16384));
  static_assert(g::NativePageGuestLengthSafe(16384,16384));
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
  // Guest x86 mmap(fd=100) is dispatched ONLY through immutable
  // source-verified snapshot file service, never host fd mmap.
  const auto fileMmap=[&](uint64_t prot,uint64_t flags,uint64_t fd,
                           uint64_t off,uint64_t len=4096){
    return files.Dispatch(Trap(a::kMmap,0,len,prot,flags,fd,off),vm);
  };
  for(const auto& bad:std::array<std::array<uint64_t,5>,7>{{
    {{PROT_READ|PROT_WRITE,MAP_PRIVATE,ld,0,4096}},
    {{PROT_READ|PROT_EXEC,MAP_PRIVATE,ld,0,4096}},
    {{PROT_READ|PROT_WRITE|PROT_EXEC,MAP_PRIVATE,ld,0,4096}},
    {{PROT_READ,MAP_SHARED,ld,0,4096}},
    {{PROT_READ,MAP_PRIVATE|MAP_FIXED,ld,0,4096}},
    {{PROT_READ,MAP_PRIVATE|MAP_ANONYMOUS,ld,0,4096}},
    {{PROT_READ,MAP_PRIVATE,ld,17,4096}}
  }}){
    auto denied=fileMmap(bad[0],bad[1],bad[2],bad[3],bad[4]);
    assert(denied.guestReturn==-22 &&
           !denied.readonlySourceELFSnapshotMapped &&
           !denied.guestReadonlySourceELFNativeProtectionApplied);
  }
  Bad(files,vm,Trap(a::kMmap,0,4096,PROT_READ,MAP_PRIVATE,5,0),-9);
  Bad(files,vm,Trap(a::kMmap,0,4096,PROT_READ,MAP_PRIVATE,105,0),-9);
  Bad(files,vm,Trap(a::kMmap,0,4096,PROT_READ,MAP_PRIVATE,ld,235408),-22);
  const uint64_t hostpage=static_cast<uint64_t>(::sysconf(_SC_PAGESIZE));
  assert(hostpage==4096 || hostpage==16384);
  const auto mappedFile=fileMmap(PROT_READ,MAP_PRIVATE,ld,0,hostpage);
  assert(mappedFile.guestReturn>65536 &&
         mappedFile.readonlySourceELFSnapshotMapped &&
         mappedFile.guestReadonlySourceELFNativeProtectionApplied &&
         mappedFile.guestSyscallAuthenticated &&
         !mappedFile.hostPathOpened && !mappedFile.hostGuestFdForwarded &&
         !mappedFile.hostAnyUntrustedSyscallForwarded);
  const uint64_t readonlyMap=static_cast<uint64_t>(mappedFile.guestReturn);
  const auto roSpan=vm.AuthenticatedRW(readonlyMap,hostpage);
  assert(roSpan.attested && roSpan.guestRead &&
         !roSpan.guestWrite && !roSpan.guestExecute &&
         NativeRights(readonlyMap)=="r--p");
  assert(std::memcmp(reinterpret_cast<const void*>(
      static_cast<uintptr_t>(readonlyMap)),original.data(),64)==0);
  // Separate RX source page: derive the real ELF PT_LOAD PF_R|PF_X
  // native-page-aligned *file* offset from genuine SHA256 original ELF64
  // program headers. No hardcoded test-only made-up executable byte
  // positions can authorize a positive executable mapping.
  int sourceFd=::open(paths[1].c_str(),O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
  assert(sourceFd>=0);
  Elf64_Ehdr eh{};
  assert(::pread(sourceFd,&eh,sizeof(eh),0)==static_cast<ssize_t>(sizeof(eh)));
  assert(std::memcmp(eh.e_ident,ELFMAG,SELFMAG)==0);
  assert(eh.e_machine==EM_X86_64 &&
         eh.e_phentsize==sizeof(Elf64_Phdr) &&
         eh.e_phnum>0 && eh.e_phnum<=64);
  uint64_t verifiedRXOffset=UINT64_MAX;
  for(unsigned i=0;i<eh.e_phnum;++i){
    Elf64_Phdr ph{};
    const uint64_t entry=eh.e_phoff+
                    static_cast<uint64_t>(i)*sizeof(Elf64_Phdr);
    assert(::pread(sourceFd,&ph,sizeof(ph),static_cast<off_t>(entry))==
          static_cast<ssize_t>(sizeof(ph)));
    if(ph.p_type!=PT_LOAD ||
       (ph.p_flags&(PF_R|PF_W|PF_X))!=(PF_R|PF_X) ||
       ph.p_filesz<hostpage ||
       ph.p_offset>UINT64_MAX-hostpage)continue;
    const uint64_t aligned=(ph.p_offset+hostpage-1)&~(hostpage-1);
    if(aligned>=ph.p_offset &&
       aligned-ph.p_offset<=ph.p_filesz-hostpage){
       verifiedRXOffset=aligned;break;
    }
  }
  assert(verifiedRXOffset!=UINT64_MAX);
  std::array<uint8_t,4096> originalRX{};
  assert(hostpage==4096 && ::pread(sourceFd,originalRX.data(),
      originalRX.size(),static_cast<off_t>(verifiedRXOffset))==
      static_cast<ssize_t>(originalRX.size()));
  assert(::close(sourceFd)==0);
  Bad(files,vm,Trap(a::kMmap,0,hostpage,PROT_READ|PROT_EXEC,
                    MAP_PRIVATE,ld,0),-22); // ELF header not RX PT_LOAD
  Bad(files,vm,Trap(a::kMmap,0,hostpage,PROT_READ|PROT_EXEC,
                    MAP_SHARED,ld,verifiedRXOffset),-22);
  Bad(files,vm,Trap(a::kMmap,0,hostpage,PROT_READ|PROT_WRITE|PROT_EXEC,
                    MAP_PRIVATE,ld,verifiedRXOffset),-22);
  Bad(files,vm,Trap(a::kMmap,0,hostpage,PROT_EXEC,
                    MAP_PRIVATE,ld,verifiedRXOffset),-22);
  Bad(files,vm,Trap(a::kMmap,0,hostpage,PROT_READ|PROT_EXEC,
                    MAP_PRIVATE|MAP_FIXED,ld,verifiedRXOffset),-22);
  Bad(files,vm,Trap(a::kMmap,0,hostpage,PROT_READ|PROT_EXEC,
                    MAP_PRIVATE,ld,verifiedRXOffset+1),-22);
  Bad(files,vm,Trap(a::kMmap,0,hostpage,PROT_READ|PROT_EXEC,
                    MAP_PRIVATE,ld,235408),-22);
  const auto sourceRX=files.Dispatch(Trap(a::kMmap,0,hostpage,
                    PROT_READ|PROT_EXEC,MAP_PRIVATE,ld,verifiedRXOffset),vm);
  assert(sourceRX.guestReturn>65536 &&
         sourceRX.guestSyscallAuthenticated &&
         sourceRX.executableSourceELFSnapshotMapped &&
         sourceRX.guestExecutableSourceELFNativeProtectionApplied &&
         !sourceRX.readonlySourceELFSnapshotMapped &&
         !sourceRX.guestReadonlySourceELFNativeProtectionApplied &&
         !sourceRX.hostPathOpened && !sourceRX.hostGuestFdForwarded &&
         !sourceRX.hostAnyUntrustedSyscallForwarded);
  const uint64_t nativeRX=static_cast<uint64_t>(sourceRX.guestReturn);
  const auto rxSpan=vm.AuthenticatedRW(nativeRX,hostpage);
  assert(rxSpan.attested && rxSpan.guestRead &&
         !rxSpan.guestWrite && rxSpan.guestExecute &&
         NativeRights(nativeRX)=="r-xp" &&
         std::memcmp(reinterpret_cast<const void*>(
           static_cast<uintptr_t>(nativeRX)),
           originalRX.data(),originalRX.size())==0);
  // Host confirms no page was transiently both W and X when exposed.
  // Any guest mprotect upgrade for the authenticated source RX is
  // prohibited, including flipping RX->RW or RX->RWX.
  for(const uint64_t rights:{
         uint64_t(PROT_READ|PROT_WRITE),
         uint64_t(PROT_READ|PROT_WRITE|PROT_EXEC),
         uint64_t(PROT_READ)}) {
    const auto upgrade=vm.Dispatch(Trap(a::kMprotect,nativeRX,
                                       hostpage,rights));
    assert(upgrade.guestReturn==-22 &&
           !upgrade.nativeOwnedMapProtectionChanged &&
           NativeRights(nativeRX)=="r-xp");
  }
  Bad(files,vm,Trap(a::kPread64,ld,nativeRX,32,verifiedRXOffset),-14);
  const auto rejectedRandom=vm.Dispatch(Trap(a::kGetrandom,nativeRX,32,0));
  assert(rejectedRandom.guestReturn==-14 &&
         !rejectedRandom.guestOwnedWritableEntropyFilled);
  // Data-only source page remains RO, never becomes RX implicitly.
  assert(NativeRights(readonlyMap)=="r--p" &&
         !vm.AuthenticatedRW(readonlyMap,64).guestExecute &&
         vm.Count()==3);
  // File-backed snapshots are never upgradable to writable guest
  // memory or modifiable through read(0), getrandom or guest mprotect.
  auto upgrade=vm.Dispatch(Trap(a::kMprotect,readonlyMap,hostpage,
                                 PROT_READ|PROT_WRITE));
  assert(upgrade.guestReturn==-22 &&
         !upgrade.nativeOwnedMapProtectionChanged &&
         NativeRights(readonlyMap)=="r--p");
  upgrade=vm.Dispatch(Trap(a::kMprotect,readonlyMap,hostpage,
                            PROT_READ|PROT_EXEC));
  assert(upgrade.guestReturn==-22);
  Bad(files,vm,Trap(a::kPread64,ld,readonlyMap,32,0),-14);
  const auto entropyDenied=vm.Dispatch(
      Trap(a::kGetrandom,readonlyMap,32,0));
  assert(entropyDenied.guestReturn==-14 &&
         !entropyDenied.guestOwnedWritableEntropyFilled);
  assert(vm.Count()==3);
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
  assert(std::memcmp(reinterpret_cast<const void*>(
      static_cast<uintptr_t>(readonlyMap)),original.data(),64)==0 &&
      NativeRights(readonlyMap)=="r--p" &&
      NativeRights(nativeRX)=="r-xp" &&
      std::memcmp(reinterpret_cast<const void*>(
        static_cast<uintptr_t>(nativeRX)),
        originalRX.data(),originalRX.size())==0);
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
  // Both guest-owned file mappings outlive synthetic guest FD close.
  assert(vm.AuthenticatedRW(nativeRX,64).guestExecute &&
         NativeRights(nativeRX)=="r-xp");
  assert(vm.AuthenticatedRW(readonlyMap,64).attested &&
         !vm.AuthenticatedRW(readonlyMap,64).guestWrite &&
         NativeRights(readonlyMap)=="r--p" &&
         std::memcmp(reinterpret_cast<const void*>(
           static_cast<uintptr_t>(readonlyMap)),
           original.data(),64)==0);
  Bad(files,vm,Trap(a::kPread64,ld,output,32,0),-9);
  for(uint64_t fd:{libc,main}){
    assert(files.Dispatch(Trap(a::kClose,fd),vm).guestReturn==0);
  }
  assert(files.OpenCount()==0);
  const auto releaseRX=vm.Dispatch(Trap(a::kMunmap,nativeRX,hostpage));
  assert(releaseRX.guestReturn==0 && releaseRX.nativeOwnedMapReleased &&
         !vm.AuthenticatedRW(nativeRX,1).attested &&
         vm.Count()==2);
  const auto releaseFile=vm.Dispatch(
      Trap(a::kMunmap,readonlyMap,hostpage));
  assert(releaseFile.guestReturn==0 && releaseFile.nativeOwnedMapReleased &&
         vm.Count()==1 &&
         !vm.AuthenticatedRW(readonlyMap,1).attested);
  const auto release=vm.Dispatch(Trap(a::kMunmap,page,4096));
  assert(release.guestReturn==0 && vm.Count()==0);
  files.Reset();
  assert(!files.Bound());
  assert(vm.Reset());
  std::puts("KERNIX_G0_SOURCE_SHA256_ELF64_PT_LOAD_PF_RX_REAL_NATIVE_GUEST_MMAP_SEALED_RX_NOT_RWX_LINUX_PASS_NOT_X86_FEX_OR_PHONE");
  return 0;
}
