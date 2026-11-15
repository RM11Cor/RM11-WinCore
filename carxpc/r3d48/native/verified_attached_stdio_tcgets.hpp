#pragma once
// R3D48: original x86_64 Linux ioctl(16, TCGETS=0x5401) for attached
// guest standard descriptors 0..2 only. The kernel UAPI termios layout is
// 4 x u32 flags + u8 line + 19 control bytes = exactly 36 bytes.
// Never pass a guest pointer or arbitrary request/fd into the host kernel.
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cerrno>
#include <sys/ioctl.h>

namespace carx_r3d48 {
constexpr uint64_t kX86Ioctl=16;
constexpr uint64_t kLinuxTcgets=0x5401;
constexpr uint64_t kGuestStdIn=0, kGuestStdOut=1, kGuestStdErr=2;
struct X86KernelTermios {
 uint32_t c_iflag;
 uint32_t c_oflag;
 uint32_t c_cflag;
 uint32_t c_lflag;
 uint8_t c_line;
 uint8_t c_cc[19];
};
static_assert(offsetof(X86KernelTermios,c_line)==16,
              "x86 Linux kernel termios c_line ABI offset");
static_assert(offsetof(X86KernelTermios,c_cc)==17,
              "x86 Linux kernel termios c_cc ABI offset");
static_assert(sizeof(X86KernelTermios)==36,
              "x86 Linux TCGETS kernel UAPI struct must be 36 bytes");
enum class Reason : uint8_t {
 NotApplicable=0, SuccessRealAttachedStream=1, UnownedGuestBuffer=2,
 HostNotTty=3, HostBadDescriptor=4, HostOtherIoctlError=5,
 GuestCopyMismatch=6
};
struct Result {
 bool handled{false};
 int64_t value{-ENOSYS};
 Reason reason{Reason::NotApplicable};
 uint32_t bytesCopied{0};
 int32_t hostErrno{0};
};
template<class GuestWritable>
inline Result handle_attached_stdio_tcgets(uint64_t number,uint64_t guestFd,
 uint64_t request,uint64_t guestDst,GuestWritable ownedGuestWritable) noexcept {
 Result r{};
 if(number!=kX86Ioctl || guestFd>kGuestStdErr ||
    request!=kLinuxTcgets) return r;
 r.reason=Reason::UnownedGuestBuffer;
 if(!ownedGuestWritable(guestDst,sizeof(X86KernelTermios)))
   return r; // no guest dereference and no host ioctl on unowned output
 X86KernelTermios kernelTermios{};
 errno=0;
 const int rc=::ioctl(static_cast<int>(guestFd),
                      static_cast<unsigned long>(kLinuxTcgets),
                      &kernelTermios);
 if(rc<0) {
   int e=errno;
   if(e<=0 || e>4095)e=EIO;
   r.handled=true;
   r.value=-static_cast<int64_t>(e);
   r.hostErrno=e;
   r.reason=(e==ENOTTY)?Reason::HostNotTty:
            (e==EBADF)?Reason::HostBadDescriptor:
                       Reason::HostOtherIoctlError;
   return r; // real kernel errno, no bytes copied on failure
 }
 std::memcpy(reinterpret_cast<void*>(static_cast<uintptr_t>(guestDst)),
             &kernelTermios,sizeof(kernelTermios));
 r.reason=Reason::GuestCopyMismatch;
 if(std::memcmp(reinterpret_cast<const void*>(
       static_cast<uintptr_t>(guestDst)),&kernelTermios,
       sizeof(kernelTermios))!=0) return r;
 r.handled=true;
 r.value=0;
 r.bytesCopied=sizeof(kernelTermios);
 r.reason=Reason::SuccessRealAttachedStream;
 return r;
}
} // namespace carx_r3d48
