#include "carxpc/r3d40/native/verified_rootfs_mmap_source.hpp"
#include "carxpc/r3d19/native/unified_guest_libc_abi.hpp"
#include <cassert>
#include <cstring>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <cstdio>
#include <cstdlib>
#include <array>
struct Vma {uint64_t base{0},length{0};};
int main(){
 char path[]="/tmp/carx-r3d40-elfXXXXXX";
 int fd=::mkstemp(path);assert(fd>=0);
 assert(::unlink(path)==0);
 std::array<unsigned char,8192> data{};
 Elf64_Ehdr eh{};
 std::memcpy(eh.e_ident,ELFMAG,SELFMAG);
 eh.e_ident[EI_CLASS]=ELFCLASS64;
 eh.e_ident[EI_DATA]=ELFDATA2LSB;
 eh.e_ident[EI_VERSION]=EV_CURRENT;
 eh.e_type=ET_DYN;
 eh.e_machine=EM_X86_64;
 eh.e_version=EV_CURRENT;
 eh.e_ehsize=sizeof(eh);
 eh.e_phentsize=sizeof(Elf64_Phdr);
 eh.e_phnum=1;
 eh.e_phoff=sizeof(eh);
 std::memcpy(data.data(),&eh,sizeof(eh));
 Elf64_Phdr ph{};
 ph.p_type=PT_LOAD;
 ph.p_flags=PF_R|PF_X;
 ph.p_offset=0;
 ph.p_filesz=8192;
 ph.p_memsz=8192;
 std::memcpy(data.data()+sizeof(eh),&ph,sizeof(ph));
 data[0x220]=0x0f;data[0x221]=0x05;
 assert(::write(fd,data.data(),data.size())==(ssize_t)data.size());
 assert(carx_r3d40::is_x86_64_elf_dso(fd));
 carx_r3d19::GuestMappings maps{};
 // Existing libc FD100 path is unchanged. Only verified FD101..116 may map.
 assert(maps.map(fd,true,0,8192,PROT_READ,0x802,101,0)==-EBADF);
 assert(maps.map(fd,true,0,8192,PROT_READ,0x802,100,0,true)==-EBADF);
 assert(maps.map(fd,true,0,8192,PROT_READ|PROT_WRITE|PROT_EXEC,
                 0x802,101,0,true)==-EACCES);
 const int64_t ro=maps.map(fd,true,0,8192,PROT_READ,0x802,101,0,true);
 assert(ro>0);
 assert(std::memcmp(reinterpret_cast<const void*>((uintptr_t)ro),
                    data.data(),8192)==0);
 carx_r3d40::GuestRootfsRxSource src{};
 assert(src.observe_mmap(fd,(uint64_t)ro,8192,false,0));
 carx_r3d3::Record record{};
 const auto find=[&](uint64_t /*ip*/)->Vma{return {uint64_t(ro),8192};};
 assert(!src.make_record(uint64_t(ro)+0x220,9,123,find,&record));
 assert(maps.unmap((uint64_t)ro,8192)==0);
 const int64_t rx=maps.map(fd,true,0,8192,PROT_READ|PROT_EXEC,
                           0x802,102,0,true);
 assert(rx>0);
 assert(src.observe_mmap(fd,(uint64_t)rx,8192,true,0));
 const auto allowed=[&](uint64_t ip)->Vma{
    if(ip>=uint64_t(rx) && ip-uint64_t(rx)<8192)
      return {uint64_t(rx),8192};
    return {};
 };
 assert(src.make_record(uint64_t(rx)+0x220,9,456,allowed,&record));
 assert(record.source_file_offset==0x220);
 assert(record.callback_guest_rip==uint64_t(rx)+0x220);
 assert(record.session_nonce==456);
 const int keep=::fcntl(fd,F_DUPFD_CLOEXEC,3);
 assert(keep>=0);
 assert(::close(fd)==0);
 assert(src.make_record(uint64_t(rx)+0x220,9,456,allowed,&record));
 src.invalidate(uint64_t(rx),8192);
 assert(!src.make_record(uint64_t(rx)+0x220,9,456,allowed,&record));
 assert(maps.unmap((uint64_t)rx,8192)==0);
 assert(::close(keep)==0);
 std::puts("R3D40_TRUSTED_APP_ROOTFS_FD101_MMAP_ELF_RX_OPCODE_SOURCE_PASS");
}
