// R3D17: validate source ELF identity; reject host objects and forged fd.
#include "carxpc/r3d17/native/verified_libc_fd.hpp"
#include <sys/mman.h>
#include <cassert>
#include <cstdio>
#include <fcntl.h>
#include <cstring>
int main() {
 using namespace carx_r3d17;
 assert(!verified_readonly_libc_fd(-1));
 assert(!verified_readonly_libc_fd(0));
 char path[]="/tmp/r3d17-libc-fixture-XXXXXX";
 int fd=mkstemp(path);
 assert(fd>=0);
 assert(::unlink(path)==0);
 assert(::ftruncate(fd,8192)==0);
 assert(!verified_readonly_libc_fd(fd));
 Elf64_Ehdr h{};
 std::memcpy(h.e_ident,ELFMAG,SELFMAG);
 h.e_ident[EI_CLASS]=ELFCLASS64;
 h.e_ident[EI_DATA]=ELFDATA2LSB;
 h.e_ident[EI_VERSION]=EV_CURRENT;
 h.e_type=ET_DYN;
 h.e_machine=EM_X86_64;
 h.e_ehsize=sizeof(Elf64_Ehdr);
 h.e_phoff=sizeof(Elf64_Ehdr);
 h.e_phnum=2;
 h.e_phentsize=sizeof(Elf64_Phdr);
 assert(::pwrite(fd,&h,sizeof(h),0)==ssize_t(sizeof(h)));
 assert(verified_readonly_libc_fd(fd));
 h.e_machine=EM_AARCH64;
 assert(::pwrite(fd,&h,sizeof(h),0)==ssize_t(sizeof(h)));
 assert(!verified_readonly_libc_fd(fd));
 h.e_machine=EM_X86_64;
 h.e_phoff=8191;
 assert(::pwrite(fd,&h,sizeof(h),0)==ssize_t(sizeof(h)));
 assert(!verified_readonly_libc_fd(fd));
 assert(::close(fd)==0);
 std::puts("R3D17_PREOPENED_LIBC_ELF64_X86_64_FD_HOST_TEST_PASS");
 return 0;
}
