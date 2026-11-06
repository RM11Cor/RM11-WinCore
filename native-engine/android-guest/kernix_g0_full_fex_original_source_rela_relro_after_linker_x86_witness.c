// SPDX-License-Identifier: MIT
// Runs INSIDE a real x86-64 Linux guest under full upstream FEX + original
// glibc ld-linux via --preload. Check exact source-pinned main PIE's
// source-authenticated main ELF R_X86_64_RELATIVE writes AND original
// GNU ld-linux post-relocation PT_GNU_RELRO native read-only page rights
// BEFORE main(). This is full Linux FEX, NOT embedded FEXCore/Android.
#define _GNU_SOURCE
#include <elf.h>
#include <link.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>

#define KERNIX_ORIGINAL_MAIN_FILE "/bin/kernix-g2e-dynamic-guest"
enum { MAIN_SOURCE_BYTES = 15976, EXPECTED_SOURCE_RELATIVE = 3 };
static unsigned char original_main[MAIN_SOURCE_BYTES];
static unsigned long main_seen;
static unsigned long checked_relative;
static unsigned long changed_relative;
static unsigned long proven_relro_pages;
static unsigned long relocated_qwords_in_relro;
static unsigned long untouched_guest_rw_pages;
static int rejected;

static void message(int fd, const char *s) {
  if (!s) return;
  const size_t n = strlen(s);
  if(n) {
    const ssize_t written=write(fd,s,n);
    if(written!=(ssize_t)n)_exit(90);
  }
}
static int span(uint64_t at, uint64_t length, uint64_t total) {
  return at<=total && length<=total-at;
}
static int source_offset_for_va(const Elf64_Ehdr* eh, uint64_t va,
                               uint64_t length, uint64_t *result) {
  const unsigned char* bytes=original_main;
  if (!span(eh->e_phoff,(uint64_t)eh->e_phnum*sizeof(Elf64_Phdr),MAIN_SOURCE_BYTES))
    return 0;
  for (unsigned i=0; i<eh->e_phnum; ++i) {
    Elf64_Phdr ph;
    memcpy(&ph,bytes+eh->e_phoff+i*sizeof(ph),sizeof(ph));
    if (ph.p_type!=PT_LOAD || va<ph.p_vaddr ||
        va-ph.p_vaddr>ph.p_filesz ||
        length>ph.p_filesz-(va-ph.p_vaddr))continue;
    if (!span(ph.p_offset+(va-ph.p_vaddr),length,MAIN_SOURCE_BYTES))
      return 0;
    *result=ph.p_offset+(va-ph.p_vaddr);
    return 1;
  }
  return 0;
}
static int source_is_writable_target(const Elf64_Ehdr* eh, uint64_t va) {
  if (!span(eh->e_phoff,(uint64_t)eh->e_phnum*sizeof(Elf64_Phdr),MAIN_SOURCE_BYTES))
    return 0;
  for (unsigned i=0; i<eh->e_phnum; ++i) {
    Elf64_Phdr p;
    memcpy(&p,original_main+eh->e_phoff+i*sizeof(p),sizeof(p));
    if(p.p_type==PT_LOAD && (p.p_flags&PF_W)!=0 &&
       (p.p_flags&PF_X)==0 && va>=p.p_vaddr &&
       va-p.p_vaddr<=p.p_memsz &&
       sizeof(uint64_t)<=p.p_memsz-(va-p.p_vaddr))
      return 1;
  }
  return 0;
}
// Actual Linux guest /proc/self/maps permission accounting. Never infer
// mprotect success from ELF metadata alone. Private mappings are expected
// for GNU loader image pages; guest mapping may be split at RELRO.
static int live_guest_page_rights(uint64_t at, char mode[5]) {
  FILE *f=fopen("/proc/self/maps","r");
  if(!f)return 0;
  char line[640];
  int found=0;
  while(fgets(line,sizeof(line),f)) {
    unsigned long long low=0,high=0;
    char perms[5]={0};
    if(sscanf(line,"%llx-%llx %4s",&low,&high,perms)!=3)continue;
    if(at >= low && at < high && high>low){
       memcpy(mode,perms,sizeof(perms));
       found=1;break;
    }
  }
  if(fclose(f)!=0)return 0;
  return found;
}
static int original_source_relro_page(const Elf64_Ehdr *eh,
                                     uint64_t load_bias,
                                     uint64_t target) {
  if(!span(eh->e_phoff,(uint64_t)eh->e_phnum*sizeof(Elf64_Phdr),MAIN_SOURCE_BYTES))
    return 0;
  for(unsigned i=0;i<eh->e_phnum;++i){
    Elf64_Phdr p;
    memcpy(&p,original_main+eh->e_phoff+i*sizeof(p),sizeof(p));
    if(p.p_type!=PT_GNU_RELRO || !p.p_memsz ||
       p.p_vaddr>UINT64_MAX-load_bias ||
       p.p_memsz>UINT64_MAX-(load_bias+p.p_vaddr))continue;
    const uint64_t begin=(load_bias+p.p_vaddr)&~uint64_t(4095);
    const uint64_t end=(load_bias+p.p_vaddr+p.p_memsz)&~uint64_t(4095);
    if(end>begin && target>=begin && target<end)return 1;
  }
  return 0;
}
static int visit(struct dl_phdr_info *info, size_t ignored, void *arg) {
  (void)ignored; (void)arg;
  if (rejected)return 1;
  int has_interp=0;
  for (Elf64_Half i=0; i<info->dlpi_phnum; ++i)
    if(info->dlpi_phdr[i].p_type==PT_INTERP)has_interp=1;
  if(!has_interp)return 0; // excludes ld-linux, libc, witness DSO
  ++main_seen;
  if(main_seen!=1 || !info->dlpi_addr){rejected=1;return 1;}
  const Elf64_Ehdr* eh=(const Elf64_Ehdr*)original_main;
  if(memcmp(eh->e_ident,ELFMAG,SELFMAG)!=0 ||
     eh->e_ident[EI_CLASS]!=ELFCLASS64 ||
     eh->e_ident[EI_DATA]!=ELFDATA2LSB ||
     eh->e_machine!=EM_X86_64 || eh->e_type!=ET_DYN) {
    rejected=2;return 1;
  }
  uint64_t rela=0,sz=0,ent=0;
  int saw_table=0,saw_size=0,saw_entry=0,saw_dynamic=0;
  for(unsigned i=0;i<eh->e_phnum;++i){
    Elf64_Phdr p;
    memcpy(&p,original_main+eh->e_phoff+i*sizeof(p),sizeof(p));
    if(p.p_type!=PT_DYNAMIC)continue;
    if(saw_dynamic++ || !p.p_filesz ||
       p.p_filesz%sizeof(Elf64_Dyn)!=0 ||
       !span(p.p_offset,p.p_filesz,MAIN_SOURCE_BYTES)){
      rejected=3;return 1;
    }
    int term=0;
    for(uint64_t off=0;off<p.p_filesz;off+=sizeof(Elf64_Dyn)){
      Elf64_Dyn d;
      memcpy(&d,original_main+p.p_offset+off,sizeof(d));
      if(d.d_tag==DT_NULL){term=1;break;}
      if(d.d_tag==DT_RELA){if(saw_table++){rejected=4;return 1;} rela=d.d_un.d_ptr;}
      if(d.d_tag==DT_RELASZ){if(saw_size++){rejected=5;return 1;} sz=d.d_un.d_val;}
      if(d.d_tag==DT_RELAENT){if(saw_entry++){rejected=6;return 1;} ent=d.d_un.d_val;}
    }
    if(!term){rejected=7;return 1;}
  }
  if(saw_dynamic!=1 || saw_table!=1 || saw_size!=1 ||
     saw_entry!=1 || ent!=sizeof(Elf64_Rela) ||
     sz<sizeof(Elf64_Rela) || sz%sizeof(Elf64_Rela) ||
     sz/sizeof(Elf64_Rela)>1024){
    rejected=8;return 1;
  }
  uint64_t source_rela_offset=0;
  if(!source_offset_for_va(eh,rela,sz,&source_rela_offset)){
    rejected=9;return 1;
  }
  const uint64_t base=(uint64_t)info->dlpi_addr;
  int relro_count=0;
  for(unsigned i=0;i<eh->e_phnum;++i){
    Elf64_Phdr p;
    memcpy(&p,original_main+eh->e_phoff+i*sizeof(p),sizeof(p));
    if(p.p_type!=PT_GNU_RELRO)continue;
    if(++relro_count!=1 || !p.p_memsz ||
       p.p_vaddr>UINT64_MAX-base ||
       p.p_memsz>UINT64_MAX-(base+p.p_vaddr)){
      rejected=13;return 1;
    }
    const uint64_t begin=(base+p.p_vaddr)&~uint64_t(4095);
    const uint64_t end=(base+p.p_vaddr+p.p_memsz)&~uint64_t(4095);
    if(end<=begin || end-begin>32768) {
      rejected=14;return 1;
    }
    for(uint64_t addr=begin;addr<end;addr+=4096) {
      char rights[5]={0};
      if(!live_guest_page_rights(addr,rights) ||
         strcmp(rights,"r--p")!=0) {
         rejected=15;return 1;
      }
      ++proven_relro_pages;
    }
  }
  if(relro_count!=1 || !proven_relro_pages){rejected=16;return 1;}
  for(uint64_t i=0;i<sz/sizeof(Elf64_Rela);++i){
    Elf64_Rela r;
    memcpy(&r,original_main+source_rela_offset+i*sizeof(r),sizeof(r));
    if(ELF64_R_TYPE(r.r_info)!=R_X86_64_RELATIVE)continue;
    if(ELF64_R_SYM(r.r_info)!=0 ||
       r.r_addend<0 || r.r_offset>UINT64_MAX-base ||
       (uint64_t)r.r_addend>UINT64_MAX-base ||
       (r.r_offset&7) ||
       !source_is_writable_target(eh,r.r_offset)){
      rejected=10;return 1;
    }
    const uint64_t target=base+r.r_offset;
    const uint64_t expected=base+(uint64_t)r.r_addend;
    uint64_t from_source=0;
    uint64_t target_source_off=0;
    if(!source_offset_for_va(eh,r.r_offset,8,&target_source_off)){
      rejected=11;return 1;
    }
    memcpy(&from_source,original_main+target_source_off,8);
    const uint64_t observed=*(volatile const uint64_t*)(uintptr_t)target;
    if(observed!=expected || observed==from_source){
      rejected=12;return 1;
    }
    if(original_source_relro_page(eh,base,target)) {
      char rights[5]={0};
      if(!live_guest_page_rights(target,rights) || strcmp(rights,"r--p")!=0){
        rejected=17;return 1;
      }
      ++relocated_qwords_in_relro;
    }
    ++checked_relative;++changed_relative;
  }
  // A non-RELRO writable PT_LOAD page must remain RW: original GNU
  // linker seals only full GNU_RELRO pages, not entire guest data.
  for(unsigned i=0;i<eh->e_phnum;++i){
    Elf64_Phdr p;
    memcpy(&p,original_main+eh->e_phoff+i*sizeof(p),sizeof(p));
    if(p.p_type!=PT_LOAD || !(p.p_flags&PF_W) ||
       p.p_memsz<4096 || p.p_vaddr>UINT64_MAX-base)continue;
    const uint64_t begin=(base+p.p_vaddr+4095)&~uint64_t(4095);
    const uint64_t last=(base+p.p_vaddr+p.p_memsz-1)&~uint64_t(4095);
    if(begin<=last && !original_source_relro_page(eh,base,last)){
      char rights[5]={0};
      if(live_guest_page_rights(last,rights) && strcmp(rights,"rw-p")==0)
        ++untouched_guest_rw_pages;
    }
  }
  return 1;
}
__attribute__((constructor))
static void kernix_verify_actual_ldso_relocations(void) {
  FILE *f=fopen(KERNIX_ORIGINAL_MAIN_FILE,"rb");
  if(!f){message(2,"KERNIX_ORIGINAL_LDSO_RELA_GUEST_SOURCE_OPEN_REJECT\n");_exit(81);}
  const size_t got=fread(original_main,1,MAIN_SOURCE_BYTES,f);
  const int extra=fgetc(f);
  const int closed=fclose(f);
  if(got!=MAIN_SOURCE_BYTES || extra!=EOF || closed!=0){
    message(2,"KERNIX_ORIGINAL_LDSO_RELA_GUEST_SOURCE_SIZE_REJECT\n");_exit(82);
  }
  if(dl_iterate_phdr(visit,NULL)<0 ||
     rejected || main_seen!=1 ||
     checked_relative!=EXPECTED_SOURCE_RELATIVE ||
     changed_relative!=EXPECTED_SOURCE_RELATIVE ||
     !proven_relro_pages || !relocated_qwords_in_relro){
    message(2,"KERNIX_ORIGINAL_LDSO_RELA_GUEST_DYNAMIC_AFTER_RELOCATION_REJECT\n");
    _exit(83);
  }
  message(1,
    "KERNIX_REAL_ORIGINAL_GNU_LDSO_MAIN_SOURCE_RELATIVE_AND_RELRO_AFTER_REAL_LINKER_BEFORE_MAIN_FEX_LINUX_ARM64\n");
}
