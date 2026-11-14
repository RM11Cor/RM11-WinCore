// SPDX-License-Identifier: MIT
// R3D12: Match an x86 guest pathname to a NUL-terminated string stored in
// immutable original GNU ld.so PT_LOAD file bytes. NO guest-pointer deref.
#pragma once
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
namespace carx_r3d12 {
struct ReadableLoad {
  uint64_t bias;
  uint64_t vaddr;
  uint64_t file_offset;
  uint64_t file_bytes;
  bool readable;
};
inline bool source_guest_path_equals(const uint8_t* image,size_t image_len,
                                     const ReadableLoad* segs,size_t seg_count,
                                     uint64_t guest_ptr,const char* expected) noexcept {
  if(!image || !segs || !expected || !guest_ptr || seg_count==0 ||
     seg_count>96)return false;
  const size_t length=std::strlen(expected);
  if(length<2 || length>=255)return false;
  const size_t bytes=length+1;
  size_t matches=0;
  for(size_t i=0;i<seg_count;++i) {
    const auto& s=segs[i];
    if(!s.readable ||
       s.bias>std::numeric_limits<uint64_t>::max()-s.vaddr)continue;
    const uint64_t start=s.bias+s.vaddr;
    if(guest_ptr<start || s.file_bytes<bytes ||
       s.file_offset>image_len ||
       s.file_bytes>image_len-s.file_offset) continue;
    const uint64_t delta=guest_ptr-start;
    if(delta>s.file_bytes-bytes) continue;
    const size_t idx=static_cast<size_t>(s.file_offset+delta);
    if(std::memcmp(image+idx,expected,bytes)==0) {
      ++matches;
      if(matches>1)return false;
    }
  }
  return matches==1;
}
} // namespace carx_r3d12
