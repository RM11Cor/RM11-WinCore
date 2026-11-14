// Host tests: no FEX/Android needed, compile -fsanitize=address,undefined.
#include "carxpc/r3d12/native/source_guest_path.hpp"
#include <array>
#include <cassert>
#include <cstring>
#include <cstdint>
#include <limits>
int main() {
  using carx_r3d12::ReadableLoad;
  using carx_r3d12::source_guest_path_equals;
  std::array<uint8_t,512> img{};
  constexpr char path[]="/etc/ld.so.preload";
  constexpr uint64_t bias=0x4100000000ULL;
  constexpr uint64_t va=0x2000ULL;
  std::memcpy(img.data()+80,path,sizeof(path));
  ReadableLoad seg{bias,va,64,160,true};
  const uint64_t guest=bias+va+16;
  assert(source_guest_path_equals(img.data(),img.size(),&seg,1,guest,path));
  assert(!source_guest_path_equals(img.data(),img.size(),&seg,1,guest,"/etc/ld.so.cache"));
  assert(!source_guest_path_equals(img.data(),img.size(),&seg,1,guest+1,path));
  assert(!source_guest_path_equals(img.data(),img.size(),&seg,1,0,path));
  assert(!source_guest_path_equals(img.data(),img.size(),&seg,1,bias+va+159,path));
  assert(!source_guest_path_equals(img.data(),img.size(),&seg,1,guest,nullptr));
  assert(!source_guest_path_equals(img.data(),img.size(),&seg,0,guest,path));
  ReadableLoad unread=seg; unread.readable=false;
  assert(!source_guest_path_equals(img.data(),img.size(),&unread,1,guest,path));
  ReadableLoad corrupt=seg; corrupt.file_offset=500;
  assert(!source_guest_path_equals(img.data(),img.size(),&corrupt,1,guest,path));
  corrupt.file_offset=UINT64_MAX;
  assert(!source_guest_path_equals(img.data(),img.size(),&corrupt,1,guest,path));
  ReadableLoad overlap[2]={seg,seg};
  assert(!source_guest_path_equals(img.data(),img.size(),overlap,2,guest,path));
  ReadableLoad overflow=seg; overflow.bias=UINT64_MAX;
  assert(!source_guest_path_equals(img.data(),img.size(),&overflow,1,guest,path));
  img[80+sizeof(path)-1]='X'; 
  assert(!source_guest_path_equals(img.data(),img.size(),&seg,1,guest,path));
  return 0;
}
