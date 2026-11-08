// SPDX-License-Identifier: MIT
// Source-pinned Linux x86-64 ELF PT_GNU_RELRO page: OWNED NATIVE HOST SURROGATE.
// Run on Linux x86-64 or ARM64 with real 4KiB native host pages only.
// Does NOT execute original x86 GNU ld-linux, FEX, guest syscall10,
// Android, Wine, or PC game. Not a general ELF loader.
#include <algorithm>
#include <array>
#include <cassert>
#include <cerrno>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <elf.h>
#include <fstream>
#include <iterator>
#include <limits>
#include <sstream>
#include <string>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

namespace {
constexpr std::uint64_t kGuestPageStart=0x3000;
constexpr std::uint64_t kPageSize=4096;
constexpr std::uint64_t kGuestPageEnd=kGuestPageStart+kPageSize;
struct Slot {
  std::uint64_t guestOffset;
  std::uint64_t originalFileValue;
  std::uint64_t resolvedGuestValue;
};
constexpr std::array<Slot,8> kSlots{{
  {0x3db8,0x1160,0x800001160ULL}, // authentic GNU relative0 + source addend
  {0x3dc0,0x1120,0x800001120ULL}, // authentic GNU relative1 + source addend
  {0x3fd0,0x1030,0x804087bc0ULL}, // puts JUMP_SLOT
  {0x3fd8,0,0x80402a200ULL},     // __libc_start_main
  {0x3fe0,0,0},                 // _ITM_deregisterTMCloneTable
  {0x3fe8,0,0},                 // __gmon_start__
  {0x3ff0,0,0},                 // _ITM_registerTMCloneTable
  {0x3ff8,0,0x8040472a0ULL},     // __cxa_finalize
}};
bool contained(size_t start,size_t bytes,size_t total) {
  return start<=total && bytes<=total-start;
}
std::uint64_t qword(const std::uint8_t* at) {
  std::uint64_t v;
  std::memcpy(&v,at,sizeof(v));
  return v;
}
void setqword(std::uint8_t* at,std::uint64_t v) {
  std::memcpy(at,&v,sizeof(v));
}
std::string rights(std::uintptr_t address) {
  std::ifstream f("/proc/self/maps");
  std::string line;
  while(std::getline(f,line)){
    unsigned long long lo=0,hi=0;
    char perms[5]={0,0,0,0,0};
    if(std::sscanf(line.c_str(),"%llx-%llx %4s",&lo,&hi,perms)==3
       && lo<=address && address<hi)return perms;
  }
  return "";
}
bool sourceELFPage(const std::vector<std::uint8_t>& original,std::uint8_t* page) {
  if(original.size()<sizeof(Elf64_Ehdr))return false;
  Elf64_Ehdr h{};
  std::memcpy(&h,original.data(),sizeof(h));
  if(std::memcmp(h.e_ident,ELFMAG,SELFMAG)!=0 ||
     h.e_ident[EI_CLASS]!=ELFCLASS64 || h.e_ident[EI_DATA]!=ELFDATA2LSB ||
     h.e_type!=ET_DYN || h.e_machine!=EM_X86_64 ||
     h.e_phentsize!=sizeof(Elf64_Phdr) || h.e_phnum==0 || h.e_phnum>128 ||
     !contained(h.e_phoff,size_t(h.e_phnum)*sizeof(Elf64_Phdr),original.size()))
    return false;
  std::vector<Elf64_Phdr> ph(h.e_phnum);
  std::memcpy(ph.data(),original.data()+h.e_phoff,ph.size()*sizeof(Elf64_Phdr));
  size_t relro=0;
  bool sourceRWLOAD=false;
  for(const auto& p:ph){
    if(p.p_type==PT_GNU_RELRO){
      // The source PT_GNU_RELRO spans 0x3db8 to 0x4000, and its
      // authentic GNU 4K page protection is exactly 0x3000 .. 0x4000.
      if(p.p_vaddr!=0x3db8 || p.p_memsz!=0x248)return false;
      relro++;
    }
    if(p.p_type!=PT_LOAD)continue;
    if(p.p_vaddr>UINT64_MAX-p.p_memsz || p.p_offset>UINT64_MAX-p.p_filesz ||
       !contained(p.p_offset,p.p_filesz,original.size()) ||
       p.p_filesz>p.p_memsz)return false;
    if(p.p_vaddr<=0x3db8 && p.p_vaddr+p.p_memsz>=0x4000 &&
       (p.p_flags&PF_W)!=0 && (p.p_flags&PF_X)==0)sourceRWLOAD=true;
    if(p.p_vaddr>UINT64_MAX-p.p_filesz)return false;
    const auto begin=std::max(p.p_vaddr,kGuestPageStart);
    const auto end=std::min(p.p_vaddr+p.p_filesz,kGuestPageEnd);
    if(begin>=end)continue;
    if(begin-p.p_vaddr>SIZE_MAX)return false;
    const auto len=static_cast<size_t>(end-begin);
    const auto sourcePosition=p.p_offset+(begin-p.p_vaddr);
    if(!contained(sourcePosition,len,original.size()))return false;
    std::memcpy(page+(begin-kGuestPageStart),
                original.data()+sourcePosition,len);
  }
  if(relro!=1 || !sourceRWLOAD)return false;
  for(const auto& s:kSlots){
    if(s.guestOffset<kGuestPageStart ||
       s.guestOffset>kGuestPageEnd-sizeof(std::uint64_t) ||
       qword(page+(s.guestOffset-kGuestPageStart))!=s.originalFileValue)
      return false;
  }
  return true;
}
}

int main(int argc,char** argv) {
  if(argc!=2) {
    std::fputs("usage: source-relro-test SOURCE_SHA256_VERIFIED_X86_ELF\n",stderr);
    return 2;
  }
  const long nativePage=::sysconf(_SC_PAGESIZE);
  // An intentional refusal of bare 4K guest mprotect via 16K host rounding.
  if(nativePage!=static_cast<long>(kPageSize)){
    std::fputs("KERNIX_G0_SOURCE_ELF_4K_GUEST_MPROTECT_NOT_AUTHORIZED_ON_NON4K_HOST_PAGE\n",stderr);
    return 4;
  }
  std::ifstream file(argv[1],std::ios::binary);
  if(!file)return 5;
  std::vector<std::uint8_t> source((std::istreambuf_iterator<char>(file)),
                                   std::istreambuf_iterator<char>());
  if(source.empty())return 6;
  void* mapped=::mmap(nullptr,2*kPageSize,PROT_READ|PROT_WRITE,
                      MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
  if(mapped==MAP_FAILED)return 7;
  auto* data=static_cast<std::uint8_t*>(mapped);
  auto release=[&]{return ::munmap(mapped,2*kPageSize)==0;};
  if(!sourceELFPage(source,data)) {
    release();
    std::fputs("KERNIX_G0_SOURCE_ELF_MAIN_RELRO_SOURCE_PROVENANCE_OR_FILE_VALUES_MISMATCH\n",stderr);
    return 8;
  }
  auto* neighbor=data+kPageSize;
  constexpr std::uint64_t neighborMagic=0x4b45524e49583136ULL;
  setqword(neighbor,neighborMagic);
  for(const auto& slot:kSlots)
    setqword(data+(slot.guestOffset-kGuestPageStart),slot.resolvedGuestValue);
  if(rights(reinterpret_cast<std::uintptr_t>(data))!="rw-p" ||
     rights(reinterpret_cast<std::uintptr_t>(neighbor))!="rw-p"){
    release();return 9;
  }
  for(const auto& slot:kSlots)
    if(qword(data+(slot.guestOffset-kGuestPageStart))!=slot.resolvedGuestValue){
      release();return 10;
    }
  // Host-only dedicated source-ELF owned *surrogate* page. This is not
  // original FEX guest memory, so no x86 guest syscall completion claimed.
  if(::mprotect(data,kPageSize,PROT_READ)!=0) {
    release();return 11;
  }
  if(rights(reinterpret_cast<std::uintptr_t>(data))!="r--p" ||
     rights(reinterpret_cast<std::uintptr_t>(neighbor))!="rw-p"){
    release();return 12;
  }
  for(const auto& slot:kSlots)
    if(qword(data+(slot.guestOffset-kGuestPageStart))!=slot.resolvedGuestValue){
      release();return 13;
    }
  // Safe child probes true kernel write denial on the already-readonly page
  // without endangering the parent or any real guest / game mapping.
  struct rlimit noCore{0,0};
  if(::setrlimit(RLIMIT_CORE,&noCore)!=0){release();return 14;}
  pid_t pid=::fork();
  if(pid<0){release();return 15;}
  if(pid==0) {
    volatile std::uint8_t* writable=data;
    writable[0]=std::uint8_t(writable[0]^1);
    _exit(89); // write unexpectedly succeeded => fail parent
  }
  int status=0;
  if(::waitpid(pid,&status,0)!=pid){release();return 16;}
  if(!(WIFSIGNALED(status) && WTERMSIG(status)==SIGSEGV)){
    release();
    std::fputs("KERNIX_G0_SOURCE_MAIN_RELRO_NATIVE_POSTPROTECT_WRITE_WAS_NOT_DENIED\n",stderr);
    return 17;
  }
  // Second native 4K page (a deliberately distinct live guest-owned
  // neighbor surrogate) MUST retain its original RW rights.
  setqword(neighbor,neighborMagic+1);
  if(qword(neighbor)!=neighborMagic+1 ||
     rights(reinterpret_cast<std::uintptr_t>(neighbor))!="rw-p"){
    release();return 18;
  }
  if(!release())return 19;
  std::puts("KERNIX_G0_SOURCE_PINNED_MAIN_ELF_4K_OWNED_NATIVE_RELRO_SURROGATE_KERNEL_MPROTECT_RO_CHILD_SIGSEGV_AND_RW_NEIGHBOR_PASS_NOT_FEX_GUEST");
}
