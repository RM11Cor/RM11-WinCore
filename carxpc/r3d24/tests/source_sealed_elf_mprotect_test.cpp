#include "carxpc/r3d24/native/source_sealed_elf_mprotect.hpp"
#include <cassert>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <sys/mman.h>
int main(){
 using namespace carx_r3d24;
 constexpr uint64_t P=4096;
 void* mem=::mmap(nullptr,8*P,PROT_READ|PROT_WRITE,
                  MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
 assert(mem!=MAP_FAILED);
 const uint64_t base=reinterpret_cast<uintptr_t>(mem);
 assert(::mprotect(reinterpret_cast<void*>(base+4*P),
                   P,PROT_READ|PROT_EXEC)==0);
 SourceSealedELFProtections wine{};
 assert(wine.register_sealed_ptload(base,4*P,PROT_READ|PROT_WRITE));
 assert(wine.register_sealed_ptload(base+4*P,P,PROT_READ|PROT_EXEC));
 assert(wine.size()==2);
 assert(!wine.register_sealed_ptload(base+2*P,P,PROT_READ));
 assert(!wine.register_sealed_ptload(base+P+1,P,PROT_READ));
 assert(!wine.register_sealed_ptload(base+6*P,P,PROT_WRITE|PROT_EXEC));
 assert(!wine.executable_at(base+P).length);
 assert(wine.executable_at(base+4*P).base==base+4*P);
 assert(wine.covers(base+3*P,P));
 assert(!wine.covers(base+5*P,P));
 // Exact observed R3D23 case: presealed original Wine RELRO page to R-only.
 assert(wine.narrow_protection(base+3*P,P,PROT_READ)==0);
 assert(wine.size()==3);
 assert(wine.narrow_protection(base+3*P,P,PROT_READ)==0);
 assert(wine.narrow_protection(base+3*P,P,PROT_READ|PROT_WRITE)
        ==-EACCES); // cannot reintroduce write rights
 assert(wine.narrow_protection(base+4*P,P,PROT_READ)==0);
 assert(!wine.executable_at(base+4*P).length);
 assert(wine.narrow_protection(base+4*P,P,PROT_EXEC)==-EACCES);
 // An untracked hole and host arbitrary address must never reach mprotect.
 assert(wine.narrow_protection(base+6*P,P,PROT_READ)==-EACCES);
 assert(wine.narrow_protection(0x1000,P,PROT_READ)==-EACCES);
 assert(wine.narrow_protection(base+2*P,2*P,PROT_READ)==-EACCES);
 assert(wine.narrow_protection(base+P+1,P,PROT_READ)==-EINVAL);
 assert(wine.narrow_protection(base+P,P,PROT_READ|PROT_EXEC)==-EACCES);
 assert(wine.narrow_protection(base+P,P,PROT_WRITE|PROT_EXEC)==-EACCES);
 assert(::munmap(mem,8*P)==0);
 std::puts("R3D24_SOURCE_SEALED_WINE_ELF_PTLOAD_RELRO_MONOTONIC_PROTECTION_TEST_PASS");
}
