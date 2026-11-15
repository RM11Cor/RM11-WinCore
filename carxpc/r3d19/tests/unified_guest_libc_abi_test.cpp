#include "carxpc/r3d19/native/unified_guest_libc_abi.hpp"
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/mman.h>
#include <fcntl.h>
#include <elf.h>
#include <array>
int main(){
 using namespace carx_r3d19;
 char path[]="/tmp/r3d19-unified-libc-XXXXXX";
 int fd=::mkstemp(path);
 assert(fd>=0 && ::unlink(path)==0);
 std::array<unsigned char,12288> src{};
 for(size_t i=0;i<src.size();i++)src[i]=static_cast<unsigned char>(i%251);
 Elf64_Ehdr e{};
 std::memcpy(e.e_ident,ELFMAG,SELFMAG);
 e.e_ident[EI_CLASS]=ELFCLASS64;
 e.e_ident[EI_DATA]=ELFDATA2LSB;
 e.e_ident[EI_VERSION]=EV_CURRENT;
 e.e_type=ET_DYN;
 e.e_machine=EM_X86_64;
 e.e_ehsize=sizeof(Elf64_Ehdr);
 e.e_phentsize=sizeof(Elf64_Phdr);
 e.e_phoff=sizeof(Elf64_Ehdr);
 e.e_phnum=1;
 std::memcpy(src.data(),&e,sizeof(e));
 assert(::write(fd,src.data(),src.size())==ssize_t(src.size()));
 assert(carx_r3d17::verified_readonly_libc_fd(fd));
 void *stack=::mmap(reinterpret_cast<void*>(
     carx_r3d16::kStackTop-carx_r3d16::kStackSize),
     carx_r3d16::kStackSize,PROT_READ|PROT_WRITE,
     MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0);
 assert(stack==reinterpret_cast<void*>(
     carx_r3d16::kStackTop-carx_r3d16::kStackSize));
 uint64_t dst=carx_r3d16::kStackTop-0x1600;
 auto a=pread64_verified_libc_stack(fd,100,dst,784,64);
 assert(a.ok && a.n==784);
 assert(std::memcmp(reinterpret_cast<void*>(uintptr_t(dst)),src.data()+64,784)==0);
 auto rejected=pread64_verified_libc_stack(fd,100,dst,784,UINT64_MAX);
 assert(!rejected.ok);
 assert(fstat_verified_libc_to_guest_stack(fd,100,dst));
 auto statval=*reinterpret_cast<LinuxX64Stat*>(uintptr_t(dst));
 assert(statval.size==ssize_t(src.size()));
 assert((statval.mode & S_IFMT)==S_IFREG);
 assert(!fstat_verified_libc_to_guest_stack(fd,101,dst));
 GuestMappings vm{};
 assert(vm.map(fd,true,0,8192,PROT_READ,MAP_PRIVATE,100,0)>0);
 auto reservation=vm.map(fd,true,0,16384,PROT_NONE,
                          MAP_PRIVATE|MAP_ANONYMOUS,uint64_t(-1),0);
 assert(reservation>0);
 assert(vm.owned_range(uint64_t(reservation),16384));
 const uint64_t fixedAt=uint64_t(reservation)+4096;
 auto fixed=vm.map(fd,true,fixedAt,4096,PROT_READ,
                   MAP_PRIVATE|MAP_FIXED|kLinuxMapDenyWrite,100,4096);
 assert(fixed==int64_t(fixedAt));
 assert(std::memcmp(reinterpret_cast<void*>(uintptr_t(fixedAt)),
                   src.data()+4096,4096)==0);
 assert(vm.protect(uint64_t(reservation),4096,PROT_READ|PROT_WRITE)==0);
 assert(vm.protect(0x200000,4096,PROT_READ)==-EACCES);
 assert(vm.map(fd,true,0x200000,4096,PROT_READ,
               MAP_PRIVATE|MAP_FIXED,100,0)==-EACCES);
 assert(vm.map(fd,true,0,4096,PROT_READ|PROT_EXEC|PROT_WRITE,
               MAP_PRIVATE,100,0)==-EACCES);
 assert(vm.unmap(uint64_t(reservation)+4096,4096)==-EACCES);
 assert(vm.unmap(uint64_t(reservation),16384)==0);
 void* heap=::mmap(nullptr,8*1024*1024,PROT_NONE,
                    MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
 assert(heap!=MAP_FAILED);
 uint64_t current=0, base=reinterpret_cast<uintptr_t>(heap);
 assert(grow_guest_brk(base,base+12345,current));
 assert(current==base+12345);
 assert(!grow_guest_brk(base,base+4096,current));
 assert(::munmap(heap,8*1024*1024)==0);
 assert(::munmap(stack,carx_r3d16::kStackSize)==0);
 assert(::close(fd)==0);
 std::puts("R3D19_UNIFIED_PREAD64_FSTAT_MMAP_MPROTECT_MUNMAP_BRK_HOST_TEST_PASS");
 return 0;
}
