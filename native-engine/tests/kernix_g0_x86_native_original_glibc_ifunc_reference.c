// SPDX-License-Identifier: MIT
// KERNIX: independent native x86_64 comparison for exact SHA-pinned
// GNU ld-linux + libc used by Linux ARM64/FEX G0. READ ONLY.
// The native outcome is a reference on one CPU, not proof of
// equivalence of guest CPUID, IFUNC dispatch, Wine or games.
#define _GNU_SOURCE
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <link.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

struct NativeImages {
  const char* libc_path;
  const char* ldso_path;
  uintptr_t libc_base;
  uintptr_t ldso_base;
  unsigned libc_count;
  unsigned ldso_count;
  unsigned wrong_libc_count;
  unsigned wrong_ldso_count;
};
static int FindOriginalModule(struct dl_phdr_info* info,size_t size,void* data){
  (void)size;
  struct NativeImages* s=(struct NativeImages*)data;
  if(!info || !info->dlpi_name)return 0;
  const char* p=info->dlpi_name;
  if(strstr(p,"/libc.so.6")){
    if(strcmp(p,s->libc_path)==0){
      s->libc_base=(uintptr_t)info->dlpi_addr;
      ++s->libc_count;
    }else ++s->wrong_libc_count;
  }
  if(strstr(p,"/ld-linux-x86-64.so.2")){
    if(strcmp(p,s->ldso_path)==0){
      s->ldso_base=(uintptr_t)info->dlpi_addr;
      ++s->ldso_count;
    }else ++s->wrong_ldso_count;
  }
  return 0;
}
static int VAFileOffset(const unsigned char* b,size_t n,
                        const Elf64_Ehdr* eh,
                        uint64_t va,size_t length,size_t* offset){
  for(unsigned i=0;i<eh->e_phnum;i++){
    Elf64_Phdr p;
    memcpy(&p,b+eh->e_phoff+(size_t)i*sizeof(p),sizeof(p));
    if(p.p_type!=PT_LOAD || va<p.p_vaddr ||
       va-p.p_vaddr>p.p_filesz ||
       length>p.p_filesz-(va-p.p_vaddr) ||
       p.p_offset>n || va-p.p_vaddr>n-p.p_offset)
      continue;
    uint64_t fileoff=p.p_offset+(va-p.p_vaddr);
    if(fileoff>n || length>n-fileoff)continue;
    *offset=(size_t)fileoff;
    return 1;
  }
  return 0;
}
static int InOriginalRX(const unsigned char* b,const Elf64_Ehdr* eh,
                        uint64_t va,uint64_t size){
  for(unsigned i=0;i<eh->e_phnum;i++){
    Elf64_Phdr p;
    memcpy(&p,b+eh->e_phoff+(size_t)i*sizeof(p),sizeof(p));
    if(p.p_type==PT_LOAD &&
       (p.p_flags&(PF_R|PF_W|PF_X))==(PF_R|PF_X) &&
       va>=p.p_vaddr &&
       va-p.p_vaddr<=p.p_filesz &&
       size<=p.p_filesz-(va-p.p_vaddr))return 1;
  }
  return 0;
}
static int InOriginalRW(const unsigned char* b,const Elf64_Ehdr* eh,
                        uint64_t va,uint64_t size){
  for(unsigned i=0;i<eh->e_phnum;i++){
    Elf64_Phdr p;
    memcpy(&p,b+eh->e_phoff+(size_t)i*sizeof(p),sizeof(p));
    if(p.p_type==PT_LOAD &&
       (p.p_flags&(PF_R|PF_W|PF_X))==(PF_R|PF_W) &&
       va>=p.p_vaddr &&
       va-p.p_vaddr<=p.p_memsz &&
       size<=p.p_memsz-(va-p.p_vaddr))return 1;
  }
  return 0;
}

// Source-attested real GNU ld-linux relocation reference, READ ONLY.
// Inspect every compact DT_RELR record in the *same original libc* and
// compare its source file qword with the native-loaded qword. This runs
// after native x86 GNU ld-linux relocated libc; it never writes a slot,
// traces a guest store RIP or proves FEX's independent loader semantics.
#ifndef DT_RELR
#define DT_RELR 36
#endif
#ifndef DT_RELRSZ
#define DT_RELRSZ 35
#endif
#ifndef DT_RELRENT
#define DT_RELRENT 37
#endif
static int RejectRELRReference(unsigned line){
  fprintf(stderr,"KERNIX_G0_X86_NATIVE_RELR_SOURCE_READONLY_REJECT source_line=%u\n",line);
  return 0;
}
struct RelrReadOnly {
  unsigned targets;
  unsigned source_backed;
  unsigned native_matches;
  unsigned native_unrelocated;
  uint64_t last_target;
};
static int AuditRELRSlot(const unsigned char* b,size_t n,
                         const Elf64_Ehdr* elf,uintptr_t base,
                         uint64_t va,struct RelrReadOnly* out){
  if(!out || (va&7) || va>UINT64_MAX-base ||
     va>0x212000u-8 || !InOriginalRW(b,elf,va,8) ||
     out->targets>=1067 ||
     (out->targets && va<=out->last_target))
    return RejectRELRReference(__LINE__);
  size_t off=0;
  if(!VAFileOffset(b,n,elf,va,8,&off))return RejectRELRReference(__LINE__);
  uint64_t addend=0,live=0;
  memcpy(&addend,b+off,8);
  if(addend>UINT64_MAX-base)return RejectRELRReference(__LINE__);
  memcpy(&live,(const void*)(uintptr_t)(base+va),8);
  ++out->targets;
  ++out->source_backed;
  out->native_matches+=(live==(uint64_t)base+addend);
  out->native_unrelocated+=(live==addend);
  out->last_target=va;
  return 1;
}
static int AuditOriginalLibcRelr(const unsigned char* b,size_t n,
                                 const Elf64_Ehdr* elf,uintptr_t base){
  uint64_t relrVA=0,relrSize=0,relrEnt=0;
  unsigned found=0,tags=0;
  for(unsigned k=0;k<elf->e_phnum;k++){
    Elf64_Phdr ph;
    memcpy(&ph,b+elf->e_phoff+(size_t)k*sizeof(ph),sizeof(ph));
    if(ph.p_type!=PT_DYNAMIC)continue;
    if(++found!=1 || !ph.p_filesz || ph.p_filesz>65536 ||
       ph.p_offset>n || ph.p_filesz>n-ph.p_offset ||
       ph.p_filesz%sizeof(Elf64_Dyn))return RejectRELRReference(__LINE__);
    int terminated=0;
    for(uint64_t off=0;off<ph.p_filesz;off+=sizeof(Elf64_Dyn)){
      Elf64_Dyn tag;
      memcpy(&tag,b+ph.p_offset+off,sizeof(tag));
      if(tag.d_tag==DT_NULL){terminated=1;break;}
      unsigned bit=0;
      if(tag.d_tag==DT_RELR){bit=1;relrVA=tag.d_un.d_ptr;}
      else if(tag.d_tag==DT_RELRSZ){bit=2;relrSize=tag.d_un.d_val;}
      else if(tag.d_tag==DT_RELRENT){bit=4;relrEnt=tag.d_un.d_val;}
      if(bit){if(tags&bit)return RejectRELRReference(__LINE__);tags|=bit;}
    }
    if(!terminated)return RejectRELRReference(__LINE__);
  }
  if(found!=1 || tags!=7 || !relrVA || relrEnt!=8 ||
     relrSize!=32u*8u)return RejectRELRReference(__LINE__);
  size_t pos=0;
  if(!VAFileOffset(b,n,elf,relrVA,(size_t)relrSize,&pos))return RejectRELRReference(__LINE__);
  uint64_t cursor=0;
  int have_base=0;
  struct RelrReadOnly out={0};
  for(unsigned k=0;k<32;k++){
    uint64_t word=0;
    memcpy(&word,b+pos+k*8,8);
    if((word&1)==0){
      if(word>UINT64_MAX-8 ||
         !AuditRELRSlot(b,n,elf,base,word,&out))return RejectRELRReference(__LINE__);
      cursor=word+8;
      have_base=1;
    }else{
      if(!have_base || cursor>UINT64_MAX-63u*8u)return RejectRELRReference(__LINE__);
      for(unsigned bit=1;bit<64;bit++){
        if(!(word&(UINT64_C(1)<<bit)))continue;
        const uint64_t va=cursor+(uint64_t)(bit-1)*8;
        if(!AuditRELRSlot(b,n,elf,base,va,&out))return RejectRELRReference(__LINE__);
      }
      cursor+=63u*8u;
    }
  }
  fprintf(stderr,
     "KERNIX_G0_X86_NATIVE_LIBC_RELR_COUNTS_OBSERVATION"
     " source_words=32 source_targets=%u source_backed=%u"
     " native_matches=%u native_unrelocated=%u"
     " main_started_after_loader=1 not_FEX=1\n",
     out.targets,out.source_backed,
     out.native_matches,out.native_unrelocated);
  if(out.targets!=1067 || out.source_backed!=1067 ||
     out.native_matches!=1067 || out.native_unrelocated!=0)
    return RejectRELRReference(__LINE__);
  printf("KERNIX_G0_X86_NATIVE_LIBC_1067_RELR_REFERENCE_SUMMARY"
         " words=32 targets=%u source_backed=%u"
         " native_matches=%u native_unrelocated=%u"
         " original_libc_native_relocated=1"
         " original_source_libc_sha_externally_attested=1"
         " no_guest_FEX_store_RIP_trace=1"
         " no_guest_or_native_relocation_writes_by_audit=1\n",
         out.targets,out.source_backed,
         out.native_matches,out.native_unrelocated);
  return 1;
}

int main(int argc,char** argv){
  if(argc!=3){fputs("KERNIX_X86_NATIVE_ORACLE_REJECT args\n",stderr);return 2;}
  struct NativeImages s={0};
  s.libc_path=argv[1];s.ldso_path=argv[2];
  dl_iterate_phdr(FindOriginalModule,&s);
  if(s.libc_count!=1 || s.ldso_count!=1 ||
     s.wrong_libc_count || s.wrong_ldso_count ||
     !s.libc_base || !s.ldso_base){
    fprintf(stderr,"KERNIX_X86_NATIVE_ORACLE_REJECT interpreter_or_libc"
       " libc=%u ldso=%u other_libc=%u other_ldso=%u\n",
       s.libc_count,s.ldso_count,
       s.wrong_libc_count,s.wrong_ldso_count);
    return 3;
  }
  int fd=open(argv[1],O_RDONLY|O_CLOEXEC);
  if(fd<0){perror("open source");return 4;}
  struct stat st={0};
  if(fstat(fd,&st)!=0 || st.st_size!=2118168){
    fputs("KERNIX_X86_NATIVE_ORACLE_REJECT source_size\n",stderr);
    close(fd);return 5;
  }
  const size_t n=(size_t)st.st_size;
  const unsigned char* b=(const unsigned char*)mmap(
     NULL,n,PROT_READ,MAP_PRIVATE,fd,0);
  close(fd);
  if(b==MAP_FAILED)return 6;
  Elf64_Ehdr eh={0};
  memcpy(&eh,b,sizeof(eh));
  if(memcmp(eh.e_ident,ELFMAG,SELFMAG)!=0 ||
     eh.e_ident[EI_CLASS]!=ELFCLASS64 ||
     eh.e_ident[EI_DATA]!=ELFDATA2LSB ||
     eh.e_machine!=EM_X86_64 || eh.e_type!=ET_DYN ||
     eh.e_phentsize!=sizeof(Elf64_Phdr) ||
     eh.e_phnum==0 || eh.e_phnum>128 ||
     eh.e_phoff>n ||
     (size_t)eh.e_phnum>(n-eh.e_phoff)/sizeof(Elf64_Phdr))
     return 7;
  if(!AuditOriginalLibcRelr(b,n,&eh,s.libc_base))return 15;
  uint64_t relaVA=0,relaSize=0,jmprelVA=0,jmprelSize=0;
  uint64_t relaEnt=0,pltType=0;
  unsigned tags=0,found=0;
  for(unsigned i=0;i<eh.e_phnum;i++){
    Elf64_Phdr p;
    memcpy(&p,b+eh.e_phoff+(size_t)i*sizeof(p),sizeof(p));
    if(p.p_type!=PT_DYNAMIC)continue;
    if(++found!=1 || p.p_offset>n || p.p_filesz>n-p.p_offset ||
       p.p_filesz%sizeof(Elf64_Dyn))return 8;
    for(uint64_t k=0;k<p.p_filesz;k+=sizeof(Elf64_Dyn)){
      Elf64_Dyn d;
      memcpy(&d,b+p.p_offset+k,sizeof(d));
      if(d.d_tag==DT_NULL)break;
      unsigned bit=0;
      if(d.d_tag==DT_RELA){relaVA=d.d_un.d_ptr;bit=1;}
      if(d.d_tag==DT_RELASZ){relaSize=d.d_un.d_val;bit=2;}
      if(d.d_tag==DT_RELAENT){relaEnt=d.d_un.d_val;bit=4;}
      if(d.d_tag==DT_JMPREL){jmprelVA=d.d_un.d_ptr;bit=8;}
      if(d.d_tag==DT_PLTRELSZ){jmprelSize=d.d_un.d_val;bit=16;}
      if(d.d_tag==DT_PLTREL){pltType=d.d_un.d_val;bit=32;}
      if(bit){if(tags&bit)return 9;tags|=bit;}
    }
  }
  if(found!=1 || tags!=63 || relaEnt!=sizeof(Elf64_Rela) ||
     pltType!=DT_RELA ||
     relaSize!=86*sizeof(Elf64_Rela) ||
     jmprelSize!=61*sizeof(Elf64_Rela))return 10;
  size_t relaOff=0,pltOff=0;
  if(!VAFileOffset(b,n,&eh,relaVA,(size_t)relaSize,&relaOff) ||
     !VAFileOffset(b,n,&eh,jmprelVA,(size_t)jmprelSize,&pltOff))
     return 11;
  unsigned ifunc=0,nonzero=0,zero=0,rx_result=0,non_rx_result=0;
  unsigned native_slot85_zero=0;
  uint64_t native_slot85_value=0;
  for(size_t t=0;t<147;t++){
    Elf64_Rela r;
    size_t off=(t<86?relaOff+t*sizeof(r):pltOff+(t-86)*sizeof(r));
    memcpy(&r,b+off,sizeof(r));
    if(ELF64_R_TYPE(r.r_info)!=R_X86_64_IRELATIVE)continue;
    if(ELF64_R_SYM(r.r_info)!=0 ||
       r.r_addend<=0 || !InOriginalRW(b,&eh,r.r_offset,8) ||
       !InOriginalRX(b,&eh,(uint64_t)r.r_addend,8))
       return 12;
    uint64_t guest_slot=0;
    memcpy(&guest_slot,(const void*)(s.libc_base+r.r_offset),8);
    unsigned result_rx=0;
    if(guest_slot>=s.libc_base)
       result_rx=InOriginalRX(b,&eh,guest_slot-s.libc_base,1);
    ++ifunc;
    nonzero+=(guest_slot!=0);
    zero+=(guest_slot==0);
    rx_result+=(guest_slot!=0 && result_rx);
    non_rx_result+=(guest_slot!=0 && !result_rx);
    if(t==85){
      native_slot85_zero=(guest_slot==0);
      native_slot85_value=guest_slot;
      if(r.r_offset!=0x2014c8 || (uint64_t)r.r_addend!=0xc8570)
         return 13;
    }
    printf("KERNIX_G0_X86_NATIVE_IFUNC_REFERENCE_ROW"
       " source_rela_index=%zu target_va=%" PRIx64
       " resolver_va=%" PRIx64 " zero=%u result_in_source_rx=%u\n",
       t,r.r_offset,(uint64_t)r.r_addend,
       (unsigned)(guest_slot==0),result_rx);
  }
  if(ifunc!=46 || nonzero+zero!=46 ||
     rx_result+non_rx_result!=nonzero)return 14;
  printf("KERNIX_G0_X86_NATIVE_IFUNC_REFERENCE_SUMMARY"
     " source_rela=86 source_jmprel=61 ifunc_total=%u"
     " native_nonzero=%u native_zero=%u"
     " native_nonzero_result_inside_source_rx=%u"
     " native_nonzero_result_outside_source_rx=%u"
     " source_index85_native_zero=%u"
     " source_index85_native_value=%" PRIx64
     " pinned_original_ldso_loaded=1 pinned_original_libc_loaded=1"
     " native_x86_64_execution=1"
     " fex_arm64_cpuid_may_differ=1"
     " no_fex_guest_execution_proof=1"
     " no_ifunc_semantic_equivalence_claim=1\n",
     ifunc,nonzero,zero,rx_result,non_rx_result,
     native_slot85_zero,native_slot85_value);
  munmap((void*)b,n);
  return 0;
}
