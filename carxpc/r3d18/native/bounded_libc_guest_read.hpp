// SPDX-License-Identifier: MIT
// R3D18: original x86 ld.so read(0) backed by app-private read-only guest libc.
// This adapter writes ONLY to the previously mapped, app-owned 64KiB guest
// Linux ABI stack, with exact address and length checks. No syscall passthrough.
#pragma once
#include "carxpc/r3d17/native/verified_libc_fd.hpp"
#include "carxpc/r3d16/native/safe_guest_stack_path.hpp"
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <unistd.h>
namespace carx_r3d18 {
constexpr size_t kMaxReadBytes=4096;
struct Result { bool ok{false}; ssize_t n{-1}; };
inline bool owned_stack_write_bounds(uint64_t dst,uint64_t length) noexcept {
  return length>0 && length<=kMaxReadBytes &&
         dst>=carx_r3d16::kStackTop-carx_r3d16::kStackSize &&
         dst<carx_r3d16::kStackTop &&
         length<=carx_r3d16::kStackTop-dst;
}
inline Result read_libc_to_owned_guest_stack(int hostFd,uint64_t guestFd,
                                            uint64_t guestDst,uint64_t count,
                                            uint64_t& cursor) noexcept {
  if(guestFd!=uint64_t(carx_r3d17::kGuestLibcFd) ||
     !owned_stack_write_bounds(guestDst,count) ||
     cursor>carx_r3d17::kMaxLibcLength ||
     !carx_r3d17::verified_readonly_libc_fd(hostFd))return {};
  unsigned char temp[kMaxReadBytes]{};
  const ssize_t n=::pread(hostFd,temp,static_cast<size_t>(count),
                          static_cast<off_t>(cursor));
  if(n<0 || uint64_t(n)>count ||
     uint64_t(n)>carx_r3d17::kMaxLibcLength-cursor)return {};
  if(n>0){
    // Guest stack was installed at these exact addresses by copyStack()
    // and remains owned and writable until the FEX probe child exits.
    void* guest=reinterpret_cast<void*>(static_cast<uintptr_t>(guestDst));
    std::memcpy(guest,temp,static_cast<size_t>(n));
    if(std::memcmp(guest,temp,static_cast<size_t>(n))!=0)return {};
  }
  cursor+=static_cast<uint64_t>(n);
  return {true,n};
}
} // namespace carx_r3d18
