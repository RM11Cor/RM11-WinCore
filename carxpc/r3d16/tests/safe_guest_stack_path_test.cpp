#include "carxpc/r3d16/native/safe_guest_stack_path.hpp"
#include <sys/mman.h>
#include <cassert>
#include <cstring>
#include <cstdio>
int main() {
  using namespace carx_r3d16;
  char out[256];
  assert(!capture_guest_stack_ascii_path(0,out));
  assert(!capture_guest_stack_ascii_path(kStackTop,out));
  assert(!capture_guest_stack_ascii_path(kStackTop-kStackSize-1,out));
  void* p=mmap(reinterpret_cast<void*>(kStackTop-kStackSize),
    kStackSize,PROT_READ|PROT_WRITE,
    MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0);
  assert(p==reinterpret_cast<void*>(kStackTop-kStackSize));
  char* path=reinterpret_cast<char*>(p)+0xee80;
  std::strcpy(path,"/lib/x86_64-linux-gnu/libc.so.6");
  assert(capture_guest_stack_ascii_path(reinterpret_cast<uintptr_t>(path),out));
  assert(std::strcmp(out,"/lib/x86_64-linux-gnu/libc.so.6")==0);
  path[0]='\n';
  assert(!capture_guest_stack_ascii_path(reinterpret_cast<uintptr_t>(path),out));
  std::memset(path,'a',256);
  assert(!capture_guest_stack_ascii_path(reinterpret_cast<uintptr_t>(path),out));
  assert(munmap(p,kStackSize)==0);
  assert(!capture_guest_stack_ascii_path(kStackTop-kStackSize+0xee80,out));
  std::puts("R3D16_BOUNDED_SOURCE_STACK_CAPTURE_HOST_TEST_PASS");
}
