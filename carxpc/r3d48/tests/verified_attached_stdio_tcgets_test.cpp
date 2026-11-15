// R3D48: actual host-kernel TCGETS test and exact x86 Linux termios36 ABI.
#include <array>
#include <cassert>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <sys/ioctl.h>
#include "carxpc/r3d48/native/verified_attached_stdio_tcgets.hpp"

int main() {
 using namespace carx_r3d48;
 alignas(4) std::array<unsigned char,sizeof(X86KernelTermios)> guest{};
 const uint64_t p=reinterpret_cast<uintptr_t>(guest.data());
 const auto writable=[&](uint64_t at,uint64_t n) {
   return at==p && n==sizeof(X86KernelTermios);
 };
 const auto denied=[](uint64_t,uint64_t){return false;};
 X86KernelTermios expected{};
 errno=0;
 const int expectedRc=::ioctl(1,static_cast<unsigned long>(kLinuxTcgets),
                              &expected);
 const int expectedErrno=errno;
 guest.fill(0xA5);
 const auto actual=handle_attached_stdio_tcgets(
     kX86Ioctl,kGuestStdOut,kLinuxTcgets,p,writable);
 assert(actual.handled);
 if(expectedRc>=0) {
   assert(actual.value==0);
   assert(actual.reason==Reason::SuccessRealAttachedStream);
   assert(actual.bytesCopied==36);
   X86KernelTermios copied{};
   std::memcpy(&copied,guest.data(),sizeof(copied));
   assert(std::memcmp(&copied,&expected,sizeof(expected))==0);
 } else {
   assert(expectedErrno>0);
   assert(actual.value==-expectedErrno);
   assert(actual.hostErrno==expectedErrno);
   assert(actual.bytesCopied==0);
   assert(actual.reason==(expectedErrno==ENOTTY?Reason::HostNotTty:
          expectedErrno==EBADF?Reason::HostBadDescriptor:
                                Reason::HostOtherIoctlError));
   for(unsigned char b:guest)assert(b==0xA5);
 }
 // Fail closed before issuing host ioctl or writing guest memory.
 guest.fill(0x5A);
 const auto unsafe=handle_attached_stdio_tcgets(
     kX86Ioctl,kGuestStdOut,kLinuxTcgets,p,denied);
 assert(!unsafe.handled && unsafe.reason==Reason::UnownedGuestBuffer);
 for(unsigned char b:guest)assert(b==0x5A);
 // Only the exact observed Linux ABI tuple is admitted.
 const auto wrongNr=handle_attached_stdio_tcgets(
     5,kGuestStdOut,kLinuxTcgets,p,writable);
 const auto wrongReq=handle_attached_stdio_tcgets(
     kX86Ioctl,kGuestStdOut,0x5402,p,writable);
 const auto fd3=handle_attached_stdio_tcgets(
     kX86Ioctl,3,kLinuxTcgets,p,writable);
 const auto fd100=handle_attached_stdio_tcgets(
     kX86Ioctl,100,kLinuxTcgets,p,writable);
 const auto fd101=handle_attached_stdio_tcgets(
     kX86Ioctl,101,kLinuxTcgets,p,writable);
 assert(!wrongNr.handled && wrongNr.reason==Reason::NotApplicable);
 assert(!wrongReq.handled && wrongReq.reason==Reason::NotApplicable);
 assert(!fd3.handled && fd3.reason==Reason::NotApplicable);
 assert(!fd100.handled && fd100.reason==Reason::NotApplicable);
 assert(!fd101.handled && fd101.reason==Reason::NotApplicable);
 const auto nullDst=handle_attached_stdio_tcgets(
     kX86Ioctl,kGuestStdOut,kLinuxTcgets,0,writable);
 assert(!nullDst.handled && nullDst.reason==Reason::UnownedGuestBuffer);
 assert(kLinuxTcgets==0x5401 && sizeof(X86KernelTermios)==36);
 std::cout<<"R3D48_X86_IOCTL16_TCGETS_ATTACHED_STDIO_REAL_KERNEL_TERMIOS36_FAIL_CLOSED_PASS\n";
}
