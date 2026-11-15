// SPDX-License-Identifier: MIT
// R3D17: validate the Java-preopened app-owned GNU libc guest file descriptor.
// No arbitrary guest path, no direct host syscall forwarding, no mutable rootfs.
#pragma once
#include <elf.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cstdint>
#include <cstring>
#include <limits>
namespace carx_r3d17 {
constexpr int kGuestLibcFd = 100;
constexpr uint64_t kMinLibcLength = 4096;
constexpr uint64_t kMaxLibcLength = 32ULL*1024ULL*1024ULL;
constexpr char kGuestLibcPath[] = "/lib/x86_64-linux-gnu/libc.so.6";
inline bool verified_readonly_libc_fd(int fd) noexcept {
  if(fd<0) return false;
  struct stat st{};
  if(::fstat(fd,&st)!=0 || !S_ISREG(st.st_mode) ||
     st.st_size<static_cast<off_t>(kMinLibcLength) ||
     st.st_size>static_cast<off_t>(kMaxLibcLength))return false;
  Elf64_Ehdr eh{};
  if(::pread(fd,&eh,sizeof(eh),0)!=static_cast<ssize_t>(sizeof(eh)))return false;
  if(std::memcmp(eh.e_ident,ELFMAG,SELFMAG)!=0 ||
     eh.e_ident[EI_CLASS]!=ELFCLASS64 ||
     eh.e_ident[EI_DATA]!=ELFDATA2LSB ||
     eh.e_ident[EI_VERSION]!=EV_CURRENT ||
     eh.e_machine!=EM_X86_64 ||
     eh.e_type!=ET_DYN ||
     eh.e_ehsize!=sizeof(Elf64_Ehdr) ||
     eh.e_phentsize!=sizeof(Elf64_Phdr) ||
     eh.e_phnum==0 || eh.e_phnum>96)return false;
  const uint64_t phsize=uint64_t(eh.e_phnum)*sizeof(Elf64_Phdr);
  return eh.e_phoff<=uint64_t(st.st_size) &&
         phsize<=uint64_t(st.st_size)-eh.e_phoff;
}
} // namespace carx_r3d17
