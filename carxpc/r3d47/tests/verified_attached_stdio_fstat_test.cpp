// R3D47: independent host C++ tests for original x86 fstat(5)
// attached standard file descriptors, real native metadata and guest stat144.
#include <cassert>
#include <array>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <sys/stat.h>
#include <unistd.h>
#include "carxpc/r3d47/native/verified_attached_stdio_fstat.hpp"

int main() {
 using namespace carx_r3d47;
 using carx_r3d19::LinuxX64Stat;
 alignas(16) std::array<unsigned char,sizeof(LinuxX64Stat)> guest{};
 uint64_t p=reinterpret_cast<uintptr_t>(guest.data());
 const auto writable=[&](uint64_t at,uint64_t n) {
  return at==p && n==sizeof(LinuxX64Stat);
 };
 const auto noWritable=[](uint64_t,uint64_t){return false;};
 struct stat native{};
 const int nativeRc=::fstat(1,&native);
 const auto ok=handle_attached_stdio_fstat(5,1,p,writable);
 if(nativeRc==0) {
  assert(ok.handled && ok.value==0);
  assert(ok.reason==Reason::SuccessRealAttachedStream);
  LinuxX64Stat v{};
  std::memcpy(&v,guest.data(),sizeof(v));
  assert(v.mode==static_cast<uint32_t>(native.st_mode));
  assert(v.uid==static_cast<uint32_t>(native.st_uid));
  assert(v.gid==static_cast<uint32_t>(native.st_gid));
  assert(v.dev==static_cast<uint64_t>(native.st_dev));
  assert(v.ino==static_cast<uint64_t>(native.st_ino));
  assert(v.size==static_cast<int64_t>(native.st_size));
  assert(sizeof(v)==144);
 } else {
  assert(errno==EBADF);
  assert(ok.handled && ok.value==-EBADF);
  assert(ok.reason==Reason::AttachedStdStreamNotOpen);
 }
 // Do not copy any bytes on invalid guest-owned writable range.
 guest.fill(0xA5);
 const auto unsafe=handle_attached_stdio_fstat(5,1,p,noWritable);
 assert(!unsafe.handled && unsafe.reason==Reason::UnownedGuestStatBuffer);
 for(unsigned char b:guest)assert(b==0xA5);
 const auto wrongNumber=handle_attached_stdio_fstat(262,1,p,writable);
 assert(!wrongNumber.handled && wrongNumber.reason==Reason::NotApplicable);
 const auto guestFd3=handle_attached_stdio_fstat(5,3,p,writable);
 assert(!guestFd3.handled && guestFd3.reason==Reason::NotApplicable);
 const auto guestFd100=handle_attached_stdio_fstat(5,100,p,writable);
 assert(!guestFd100.handled && guestFd100.reason==Reason::NotApplicable);
 const auto guestFd101=handle_attached_stdio_fstat(5,101,p,writable);
 assert(!guestFd101.handled && guestFd101.reason==Reason::NotApplicable);
 // Negative guest pointer test; not owned, no host dereference.
 const auto nullDst=handle_attached_stdio_fstat(5,1,0,writable);
 assert(!nullDst.handled && nullDst.reason==Reason::UnownedGuestStatBuffer);
 // Exactly the source observed in the phone report: fd1 and Linux stat144.
 assert(kX86Fstat==5 && kGuestStdOut==1 && sizeof(LinuxX64Stat)==144);
 std::cout<<"R3D47_ATTACHED_STDIO_X86_FSTAT5_REAL_HOST_STAT144_GUEST_OWNED_BYTES_PASS\n";
}
