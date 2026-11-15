#pragma once
// R3D47: source-witnessed x86_64 Linux fstat(5) for guest fd 0, 1, 2.
// These descriptors are the isolated worker's already-attached standard
// streams; read only their kernel metadata with fstat(2), NEVER forward
// arbitrary guest descriptor/path/pointer syscalls to Android host.
// Convert host native stat to the 144-byte x86_64 Linux ABI owned by guest.
// R3D46 phone: original glibc x86 fstat(1,0x6FFFFFFA10) at callback index79,
// after HOME=/tmp envp fix redirected Wine to guest stdout inspection.
#include <cstdint>
#include <cstring>
#include <cerrno>
#include <sys/stat.h>
#include <unistd.h>
#include "carxpc/r3d45/native/source_verified_newfstatat262.hpp"

namespace carx_r3d47 {
constexpr uint64_t kX86Fstat=5;
constexpr uint64_t kGuestStdIn=0, kGuestStdOut=1, kGuestStdErr=2;
enum class Reason : uint8_t {
 NotApplicable=0, SuccessRealAttachedStream=1, UnownedGuestStatBuffer=2,
 AttachedStdStreamNotOpen=3, HostMetadataError=4, DestinationCopyChanged=5
};
struct Result {
 bool handled{false};
 int64_t value{-ENOSYS};
 Reason reason{Reason::NotApplicable};
 uint32_t mode{0};
};
template<class GuestWritable>
inline Result handle_attached_stdio_fstat(uint64_t number,uint64_t guestFd,
 uint64_t guestDst,GuestWritable ownedGuestWritable) noexcept {
 Result r{};
 if(number!=kX86Fstat || guestFd>kGuestStdErr)return r;
 r.reason=Reason::UnownedGuestStatBuffer;
 if(!ownedGuestWritable(guestDst,sizeof(carx_r3d19::LinuxX64Stat)))
   return r; // fail-closed; no dereference of arbitrary guest pointer
 struct stat native{};
 if(::fstat(static_cast<int>(guestFd),&native)!=0){
   if(errno==EBADF) {
      r.handled=true;r.value=-EBADF;
      r.reason=Reason::AttachedStdStreamNotOpen;
   } else r.reason=Reason::HostMetadataError;
   return r;
 }
 const carx_r3d19::LinuxX64Stat abi=carx_r3d45::as_x86_64_stat(native);
 std::memcpy(reinterpret_cast<void*>(static_cast<uintptr_t>(guestDst)),
             &abi,sizeof(abi));
 r.reason=Reason::DestinationCopyChanged;
 if(std::memcmp(reinterpret_cast<const void*>(
               static_cast<uintptr_t>(guestDst)),&abi,sizeof(abi))!=0)
     return r;
 r.mode=abi.mode;
 r.value=0;
 r.handled=true;
 r.reason=Reason::SuccessRealAttachedStream;
 return r;
}
} // namespace carx_r3d47
