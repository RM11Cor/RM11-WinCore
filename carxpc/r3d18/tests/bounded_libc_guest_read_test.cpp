#include "carxpc/r3d18/native/bounded_libc_guest_read.hpp"
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <elf.h>
#include <cassert>
#include <cstdlib>
#include <cstring>
#include <array>
#include <cstdio>
int main(){
  using namespace carx_r3d18;
  char path[]="/tmp/r3d18-libc-read-XXXXXX";
  int fd=mkstemp(path);
  assert(fd>=0 && ::unlink(path)==0);
  std::array<unsigned char,8192> source{};
  for(size_t i=0;i<source.size();++i)source[i]=static_cast<unsigned char>(i%251);
  Elf64_Ehdr h{};
  std::memcpy(h.e_ident,ELFMAG,SELFMAG);
  h.e_ident[EI_CLASS]=ELFCLASS64;
  h.e_ident[EI_DATA]=ELFDATA2LSB;
  h.e_ident[EI_VERSION]=EV_CURRENT;
  h.e_type=ET_DYN;
  h.e_machine=EM_X86_64;
  h.e_ehsize=sizeof(Elf64_Ehdr);
  h.e_phoff=sizeof(Elf64_Ehdr);
  h.e_phentsize=sizeof(Elf64_Phdr);
  h.e_phnum=1;
  std::memcpy(source.data(),&h,sizeof(h));
  assert(::write(fd,source.data(),source.size())==ssize_t(source.size()));
  assert(carx_r3d17::verified_readonly_libc_fd(fd));
  void* mapped=::mmap(reinterpret_cast<void*>(carx_r3d16::kStackTop-carx_r3d16::kStackSize),
    carx_r3d16::kStackSize,PROT_READ|PROT_WRITE,
    MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0);
  assert(mapped==reinterpret_cast<void*>(carx_r3d16::kStackTop-carx_r3d16::kStackSize));
  uint64_t at=carx_r3d16::kStackTop-0xf68;
  uint64_t cursor=0;
  auto a=read_libc_to_owned_guest_stack(fd,100,at,832,cursor);
  assert(a.ok && a.n==832 && cursor==832);
  assert(std::memcmp(reinterpret_cast<const void*>(uintptr_t(at)),
                     source.data(),832)==0);
  auto b=read_libc_to_owned_guest_stack(fd,100,at,832,cursor);
  assert(b.ok && b.n==832 && cursor==1664);
  assert(std::memcmp(reinterpret_cast<const void*>(uintptr_t(at)),
                     source.data()+832,832)==0);
  auto badfd=read_libc_to_owned_guest_stack(fd,101,at,832,cursor);
  auto low=read_libc_to_owned_guest_stack(fd,100,carx_r3d16::kStackTop-carx_r3d16::kStackSize-1,832,cursor);
  auto edge=read_libc_to_owned_guest_stack(fd,100,carx_r3d16::kStackTop-3,832,cursor);
  auto big=read_libc_to_owned_guest_stack(fd,100,at,4097,cursor);
  auto zero=read_libc_to_owned_guest_stack(fd,100,at,0,cursor);
  auto nullfd=read_libc_to_owned_guest_stack(-1,100,at,832,cursor);
  assert(!badfd.ok && !low.ok && !edge.ok && !big.ok && !zero.ok && !nullfd.ok);
  assert(cursor==1664);
  assert(::munmap(mapped,carx_r3d16::kStackSize)==0);
  assert(::close(fd)==0);
  std::puts("R3D18_REAL_LIBC_READ_832_BOUNDED_STACK_HOST_TEST_PASS");
}
