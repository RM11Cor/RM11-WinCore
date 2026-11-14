// SPDX-License-Identifier: MIT
// R3C24: transient source-verified Wine64/Linux ld.so native 4KiB PT_LOAD
// installation on Android ARM64. Exact guest VA MAP_FIXED_NOREPLACE only;
// never overwrite host VA; no Wine/FEX execution or guest syscall dispatch.
// Java authenticates both input byte[] SHA-256 against immutable source hash,
// then passes the very same bytes to this JNI child-memory proof.
#include <elf.h>
#include <sys/mman.h>
#include <unistd.h>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <array>
#include <algorithm>
#include <limits>
#include <cerrno>
#include <cstdio>

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif
#ifndef CARX_WINE_HOST_MAPPING_HOST_TEST
#include <jni.h>
#endif

namespace carx24 {
constexpr uint64_t PAGE=4096;
constexpr uint64_t STACK_TOP=0x0000007000000000ULL;
constexpr uint64_t STACK_LEN=65536;
constexpr uint64_t MAIN_BIAS=0x0000004000000000ULL;
constexpr uint64_t LDSO_BIAS=0x0000004100000000ULL;
constexpr uint64_t MAX_IMG_BYTES=16*1024*1024;
constexpr uint64_t MAX_FILE_BYTES=2*1024*1024;
static_assert(sizeof(Elf64_Ehdr)==64 && sizeof(Elf64_Phdr)==56);

struct Region {
  void *ptr{MAP_FAILED}; size_t len{0};
  ~Region(){if(ptr!=MAP_FAILED) ::munmap(ptr,len);}
  Region()=default;
  Region(const Region&)=delete;Region&operator=(const Region&)=delete;
  bool reserve(uint64_t va,size_t size,std::string &why){
    if(!va || !size || (va&(PAGE-1)) || (size&(PAGE-1))) {
      why="INVALID_RESERVE_ALIGNMENT";return false;
    }
    void *at=reinterpret_cast<void*>(static_cast<uintptr_t>(va));
    void *p=::mmap(at,size,PROT_NONE,
      MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0);
    if(p==MAP_FAILED){
      why="KERNEL_GUEST_VA_RESERVATION_DENIED_"+std::to_string(errno);
      return false;
    }
    // On a kernel not recognizing MAP_FIXED_NOREPLACE, never accept an
    // arbitrary address as the planned x86 virtual address.
    if(p!=at){
      ::munmap(p,size);why="KERNEL_DID_NOT_HONOR_NOREPLACE";return false;
    }
    ptr=p;len=size;return true;
  }
};
bool alignUp(uint64_t value,uint64_t &out){
  if(value>UINT64_MAX-(PAGE-1))return false;
  out=(value+(PAGE-1))&~(PAGE-1);return true;
}
uint64_t alignDown(uint64_t v){return v&~(PAGE-1);}
bool full(uint64_t o,uint64_t n,uint64_t cap){
  return o<=cap && n<=cap-o;
}
struct Load {
  uint64_t va{},fileOff{},fileSize{},memSize{},start{},end{};
  int permission{};
};
struct Elf {
  uint64_t entry{},min{},max{};
  std::vector<Load> segments;
};
bool decode(const std::vector<uint8_t> &source,Elf& e,std::string &why){
  if(source.size()<sizeof(Elf64_Ehdr) || source.size()>MAX_FILE_BYTES){
    why="ORIGINAL_GUEST_ELF_SIZE_REJECTED";return false;
  }
  Elf64_Ehdr head{};
  std::memcpy(&head,source.data(),sizeof(head));
  if(std::memcmp(head.e_ident,ELFMAG,SELFMAG)!=0 ||
     head.e_ident[EI_CLASS]!=ELFCLASS64 ||
     head.e_ident[EI_DATA]!=ELFDATA2LSB ||
     head.e_ident[EI_VERSION]!=EV_CURRENT ||
     head.e_type!=ET_DYN || head.e_machine!=EM_X86_64 ||
     head.e_version!=EV_CURRENT || head.e_ehsize!=sizeof(Elf64_Ehdr) ||
     head.e_phentsize!=sizeof(Elf64_Phdr) ||
     head.e_phnum<1 || head.e_phnum>96 ||
     !full(head.e_phoff,uint64_t(head.e_phnum)*sizeof(Elf64_Phdr),source.size())){
    why="ORIGINAL_GUEST_ELF64_HEADER_INVALID";return false;
  }
  e.entry=head.e_entry;
  e.min=UINT64_MAX;e.max=0;
  bool entryFileBackedRX=false;
  for(unsigned i=0;i<head.e_phnum;i++){
    Elf64_Phdr ph{};
    std::memcpy(&ph,source.data()+head.e_phoff+
      uint64_t(i)*sizeof(ph),sizeof(ph));
    if(ph.p_type!=PT_LOAD)continue;
    if(ph.p_filesz>ph.p_memsz ||
       !full(ph.p_offset,ph.p_filesz,source.size()) ||
       ph.p_vaddr>MAX_IMG_BYTES || ph.p_memsz>MAX_IMG_BYTES ||
       ph.p_vaddr>MAX_IMG_BYTES-ph.p_memsz ||
       ((ph.p_flags&PF_X)!=0 && (ph.p_flags&PF_W)!=0) ||
       ((ph.p_flags & ~(PF_R|PF_W|PF_X))!=0) ||
       (ph.p_align && ((ph.p_align&(ph.p_align-1))!=0 ||
         (ph.p_vaddr%ph.p_align)!=(ph.p_offset%ph.p_align)))) {
      why="ORIGINAL_GUEST_PTLOAD_INVALID_WX_ALIGN_OR_BOUNDS";return false;
    }
    uint64_t end=0;
    if(!alignUp(ph.p_vaddr+ph.p_memsz,end)){
      why="ORIGINAL_GUEST_PTLOAD_END_OVERFLOW";return false;
    }
    int permission=0;
    if(ph.p_flags&PF_R)permission|=PROT_READ;
    if(ph.p_flags&PF_W)permission|=PROT_WRITE;
    if(ph.p_flags&PF_X)permission|=PROT_EXEC;
    if(ph.p_memsz==0)continue;
    Load seg{ph.p_vaddr,ph.p_offset,ph.p_filesz,ph.p_memsz,
      alignDown(ph.p_vaddr),end,permission};
    for(const auto& already:e.segments){
      if(seg.start<already.end && already.start<seg.end){
        why="ORIGINAL_GUEST_PTLOAD_HOST_PAGE_OVERLAP_REJECTED";
        return false;
      }
    }
    e.segments.push_back(seg);
    e.min=std::min(e.min,seg.start);
    e.max=std::max(e.max,seg.end);
    if((ph.p_flags & PF_X) && head.e_entry>=ph.p_vaddr &&
       head.e_entry-ph.p_vaddr<ph.p_filesz)entryFileBackedRX=true;
  }
  if(e.segments.size()!=4 || !entryFileBackedRX ||
     e.min==UINT64_MAX || e.max<=e.min ||
     e.max-e.min>MAX_IMG_BYTES) {
    why="AUTHENTIC_WINE_4_PTLOAD_OR_ENTRY_NOT_PRESENT";return false;
  }
  return true;
}
bool copyAndSeal(uint64_t bias,const std::vector<uint8_t>& source,
                 const Elf& e,Region& region,std::string &why) {
  const uint64_t start=bias+e.min;
  if(start<bias || e.max-e.min>MAX_IMG_BYTES){
    why="GUEST_MAPPING_PLAN_OVERFLOW";return false;
  }
  if(!region.reserve(start,static_cast<size_t>(e.max-e.min),why))return false;
  // Every page is RW only for the short load from original authenticated
  // byte[] and never RWX. Immediately seal holes PROT_NONE and each
  // original ELF PT_LOAD with its precise R-X / R-- / RW- rights.
  if(::mprotect(region.ptr,region.len,PROT_READ|PROT_WRITE)!=0){
    why="NATIVE_GUEST_MAPPING_INITIAL_RW_MPROTECT_DENIED";return false;
  }
  for(const Load& seg:e.segments){
    uint64_t offset=seg.va-e.min;
    if(!full(offset,seg.memSize,region.len)){
      why="GUEST_PTLOAD_OUTSIDE_NATIVE_RESERVED_WINDOW";return false;
    }
    uint8_t* dest=static_cast<uint8_t*>(region.ptr)+offset;
    if(seg.fileSize)
      std::memcpy(dest,source.data()+seg.fileOff,size_t(seg.fileSize));
    for(uint64_t z=seg.fileSize;z<seg.memSize;z++){
      if(dest[z]!=0){why="GUEST_ANON_BSS_NOT_ZERO";return false;}
    }
    if(seg.fileSize && std::memcmp(dest,source.data()+seg.fileOff,
                                   size_t(seg.fileSize))!=0){
      why="ORIGINAL_ELF_PTLOAD_MEMORY_SOURCE_BYTES_CHANGED";return false;
    }
  }
  if(::mprotect(region.ptr,region.len,PROT_NONE)!=0){
    why="GUEST_PTLOAD_HOLES_PROTNONE_DENIED";return false;
  }
  for(const Load& seg:e.segments){
    uint8_t* startByte=static_cast<uint8_t*>(region.ptr)+(seg.start-e.min);
    if(::mprotect(startByte,size_t(seg.end-seg.start),seg.permission)!=0){
      why="GUEST_PTLOAD_NATIVE_WX_SEAL_DENIED_"+std::to_string(errno);
      return false;
    }
  }
  for(const Load& seg:e.segments){
    if(!(seg.permission&PROT_READ) && seg.fileSize)continue;
    const uint8_t* addr=static_cast<uint8_t*>(region.ptr)+(seg.va-e.min);
    if(seg.fileSize && std::memcmp(addr,source.data()+seg.fileOff,
                    size_t(seg.fileSize))!=0){
      why="SEALED_ORIGINAL_WINE_ELF_PTLOAD_BYTES_MISMATCH";return false;
    }
  }
  return true;
}
bool copyStack(const std::vector<uint8_t> &stack,uint64_t rsp,Region& region,
               std::string &why){
  if(stack.size()!=STACK_LEN ||
     rsp<(STACK_TOP-STACK_LEN) || rsp>=STACK_TOP || (rsp&15)) {
    why="REAL_GUEST_STACK_SIZE_RSP_OR_ALIGN_INVALID";return false;
  }
  if(!region.reserve(STACK_TOP-STACK_LEN,STACK_LEN,why))return false;
  if(::mprotect(region.ptr,region.len,PROT_READ|PROT_WRITE)!=0){
    why="GUEST_STACK_NATIVE_RW_MPROTECT_DENIED";return false;
  }
  std::memcpy(region.ptr,stack.data(),stack.size());
  if(std::memcmp(region.ptr,stack.data(),stack.size())!=0){
    why="REAL_GUEST_STACK_NATIVE_COPY_MISMATCH";return false;
  }
  const uint64_t offset=rsp-(STACK_TOP-STACK_LEN);
  if(offset>stack.size()-8){
    why="INITIAL_GUEST_RSP_OUTSIDE_NATIVE_MAPPED_STACK";return false;
  }
  uint64_t argc=0;
  std::memcpy(&argc,static_cast<const uint8_t*>(region.ptr)+offset,8);
  if(argc!=2){why="INITIAL_GUEST_STACK_ARGC_NOT_TWO";return false;}
  return true;
}
bool run(const std::vector<uint8_t> &wine,const std::vector<uint8_t> &ldso,
         const std::vector<uint8_t> &stack,uint64_t expectedWineEntry,
         uint64_t expectedLdsoEntry,uint64_t rsp,std::string &message){
  if(::sysconf(_SC_PAGESIZE)!=int64_t(PAGE)){
    message="NATIVE_HOST_NOT_4K_GUEST_PAGE";return false;
  }
  Elf we{},le{};std::string why;
  if(!decode(wine,we,why)){message="WINE_"+why;return false;}
  if(!decode(ldso,le,why)){message="LDSO_"+why;return false;}
  if(MAIN_BIAS+we.entry!=expectedWineEntry ||
     LDSO_BIAS+le.entry!=expectedLdsoEntry){
    message="AUTHENTIC_ELF_SOURCE_ENTRY_NOT_MATCH_ABI_PLAN";return false;
  }
  Region wm,lm,sm;
  if(!copyAndSeal(MAIN_BIAS,wine,we,wm,why)){
    message="WINE_"+why;return false;
  }
  if(!copyAndSeal(LDSO_BIAS,ldso,le,lm,why)){
    message="LDSO_"+why;return false;
  }
  if(!copyStack(stack,rsp,sm,why)){
    message="STACK_"+why;return false;
  }
  const auto* entryWine=reinterpret_cast<const uint8_t*>(
      uintptr_t(expectedWineEntry));
  const auto* entryLdso=reinterpret_cast<const uint8_t*>(
      uintptr_t(expectedLdsoEntry));
  const uint8_t* expectedWineSource=nullptr;
  const uint8_t* expectedLdsoSource=nullptr;
  for(const Load& seg:we.segments)
    if(seg.permission&PROT_EXEC && we.entry>=seg.va &&
       we.entry-seg.va<seg.fileSize)
      expectedWineSource=wine.data()+seg.fileOff+(we.entry-seg.va);
  for(const Load& seg:le.segments)
    if(seg.permission&PROT_EXEC && le.entry>=seg.va &&
       le.entry-seg.va<seg.fileSize)
      expectedLdsoSource=ldso.data()+seg.fileOff+(le.entry-seg.va);
  if(!expectedWineSource || !expectedLdsoSource ||
     std::memcmp(entryWine,expectedWineSource,1)!=0 ||
     std::memcmp(entryLdso,expectedLdsoSource,1)!=0){
    message="LIVE_HOST_RX_GUEST_ENTRY_NOT_SOURCE_IDENTICAL";return false;
  }
  message="PASS_ORIGINAL_WINE64_GNU_LDSO_GUEST_VA_NATIVE_4K_SOURCE_PTLS_AND_STACK_MAPPED_SEALED_NO_EXEC";
  return true;
}
} // namespace carx24

#ifndef CARX_WINE_HOST_MAPPING_HOST_TEST
extern "C" JNIEXPORT jstring JNICALL
Java_com_r4_carxpc_WineX86HostMappingProbe_nativeProbe(
  JNIEnv *env,jclass,jbyteArray wineArray,jbyteArray ldsoArray,
  jbyteArray stackArray,jlong wineEntry,jlong ldsoEntry,jlong rsp){
  auto bytes=[env](jbyteArray src,size_t max)->std::vector<uint8_t>{
    if(!src)return {};
    jsize n=env->GetArrayLength(src);
    if(n<=0 || size_t(n)>max)return {};
    std::vector<uint8_t> b(static_cast<size_t>(n));
    env->GetByteArrayRegion(src,0,n,reinterpret_cast<jbyte*>(b.data()));
    if(env->ExceptionCheck())return {};
    return b;
  };
  const auto w=bytes(wineArray,carx24::MAX_FILE_BYTES);
  const auto l=bytes(ldsoArray,carx24::MAX_FILE_BYTES);
  const auto st=bytes(stackArray,carx24::STACK_LEN);
  std::string msg;
  if(w.empty()||l.empty()||st.size()!=carx24::STACK_LEN)
    msg="SOURCE_INPUT_BYTE_ARRAY_SIZE_INVALID";
  else{
    const bool ok=carx24::run(w,l,st,uint64_t(wineEntry),
                             uint64_t(ldsoEntry),uint64_t(rsp),msg);
    if(!ok)msg="FAIL_"+msg;
  }
  return env->NewStringUTF(msg.c_str());
}
#else
#include <fstream>
#include <iterator>
static std::vector<uint8_t> file(const char* path){
  std::ifstream f(path,std::ios::binary);
  return {std::istreambuf_iterator<char>{f},std::istreambuf_iterator<char>{}};
}
int main(int argc,char** argv){
  if(argc!=3)return 2;
  auto a=file(argv[1]),b=file(argv[2]);
  std::vector<uint8_t> stack(carx24::STACK_LEN,0);
  const uint64_t rsp=carx24::STACK_TOP-1024;
  uint64_t two=2;
  std::memcpy(stack.data()+(rsp-(carx24::STACK_TOP-carx24::STACK_LEN)),
              &two,sizeof(two));
  carx24::Elf ae{},be{};std::string why;
  if(!carx24::decode(a,ae,why) || !carx24::decode(b,be,why)){
    std::fprintf(stderr,"CARX_R3C24_SOURCE_REJECTED %s\n",why.c_str());
    return 3;
  }
  std::string result;
  bool pass=carx24::run(a,b,stack,carx24::MAIN_BIAS+ae.entry,
                   carx24::LDSO_BIAS+be.entry,rsp,result);
  if(!pass){std::fprintf(stderr,"CARX_R3C24_FAILED %s\n",result.c_str());return 4;}
  std::printf("CARX_R3C24_ACTUAL_NATIVE_HOST_MMAP4K_ORIGINAL_WINE64_LDSO_4PTLOAD_STACK_WX_PASS %s\n",
    result.c_str());
  a[1]=0;
  bool rejected=carx24::run(a,b,stack,carx24::MAIN_BIAS+ae.entry,
                      carx24::LDSO_BIAS+be.entry,rsp,result);
  if(rejected){std::fputs("CARX_R3C24_TAMPER_NOT_REJECTED\n",stderr);return 5;}
  std::puts("CARX_R3C24_WINE_ORIGINAL_ELF_HEADER_CORRUPTION_FAILCLOSED_PASS");
  std::puts("CARX_R3C24_NO_GUEST_FEX_WINE_EXECUTION_OR_WINDOWS_PE_PROOF");
  return 0;
}
#endif
