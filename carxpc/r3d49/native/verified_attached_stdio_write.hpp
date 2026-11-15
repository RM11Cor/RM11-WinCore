#pragma once
// R3D49: source-verified x86_64 Linux write(1) for attached guest stdout only.
// The guest buffer is validated and copied into a bounded local buffer before
// host write(2). Never pass a guest pointer or arbitrary guest descriptor to
// the host kernel. R3D48's exact TCGETS handling remains independent.
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cerrno>
#include <unistd.h>

namespace carx_r3d49 {
constexpr uint64_t kX86Write = 1;
constexpr uint64_t kGuestStdOut = 1;
constexpr uint64_t kMaxWriteBytes = 4096;

enum class Reason : uint8_t {
  NotApplicable = 0,
  Success = 1,
  ZeroLength = 2,
  UnownedGuestBuffer = 3,
  OversizedBuffer = 4,
  HostWriteError = 5
};

struct Result {
  bool handled{false};
  int64_t value{-ENOSYS};
  Reason reason{Reason::NotApplicable};
  uint32_t bytesCopied{0};
  uint32_t bytesWritten{0};
  int32_t hostErrno{0};
};

template<class GuestReadable>
inline Result handle_attached_stdout_write(uint64_t number,
    uint64_t guestFd, uint64_t guestSrc, uint64_t count,
    GuestReadable ownedGuestReadable) noexcept {
  Result r{};
  // Admit only the exact observed Linux write syscall on attached stdout.
  if (number != kX86Write || guestFd != kGuestStdOut) return r;

  // The observed device request is 37 bytes. Bound every local copy and stop
  // rather than attempting an unbounded or multi-chunk guest memory read.
  if (count > kMaxWriteBytes) {
    r.reason = Reason::OversizedBuffer;
    return r;
  }
  // Linux write(fd, any_pointer, 0) has no memory access side effect.
  if (count == 0) {
    r.handled = true;
    r.value = 0;
    r.reason = Reason::ZeroLength;
    return r;
  }

  r.reason = Reason::UnownedGuestBuffer;
  if (!guestSrc || !ownedGuestReadable(guestSrc, count))
    return r; // no guest dereference and no host write on unowned memory

  unsigned char local[kMaxWriteBytes]{};
  std::memcpy(local,
      reinterpret_cast<const void*>(static_cast<uintptr_t>(guestSrc)),
      static_cast<size_t>(count));
  r.bytesCopied = static_cast<uint32_t>(count);

  errno = 0;
  const ssize_t written = ::write(static_cast<int>(kGuestStdOut), local,
                                  static_cast<size_t>(count));
  if (written < 0) {
    int e = errno;
    if (e <= 0 || e > 4095) e = EIO;
    r.handled = true;
    r.value = -static_cast<int64_t>(e);
    r.hostErrno = e;
    r.reason = Reason::HostWriteError;
    return r;
  }

  r.handled = true;
  r.value = static_cast<int64_t>(written);
  r.bytesWritten = static_cast<uint32_t>(written);
  r.reason = Reason::Success;
  return r;
}
} // namespace carx_r3d49
