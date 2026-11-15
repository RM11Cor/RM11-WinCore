// R3D49: bounded guest-buffer copy to the already-attached host stdout.
#include <array>
#include <cassert>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <unistd.h>
#include "carxpc/r3d49/native/verified_attached_stdio_write.hpp"

int main() {
  using namespace carx_r3d49;

  std::array<unsigned char, 37> guest{};
  for (size_t i = 0; i < guest.size(); ++i)
    guest[i] = static_cast<unsigned char>(i + 1);
  const uint64_t guestPtr = reinterpret_cast<uintptr_t>(guest.data());

  int pipefd[2]{-1, -1};
  assert(::pipe(pipefd) == 0);
  const int savedStdout = ::dup(STDOUT_FILENO);
  assert(savedStdout >= 0);
  assert(::dup2(pipefd[1], STDOUT_FILENO) == STDOUT_FILENO);
  assert(::close(pipefd[1]) == 0);

  const auto readable = [&](uint64_t p, uint64_t n) {
    return p == guestPtr && n == guest.size();
  };
  const auto denied = [](uint64_t, uint64_t) { return false; };

  const auto actual = handle_attached_stdout_write(
      kX86Write, kGuestStdOut, guestPtr, guest.size(), readable);
  assert(actual.handled);
  assert(actual.value == 37);
  assert(actual.reason == Reason::Success);
  assert(actual.bytesCopied == 37);
  assert(actual.bytesWritten == 37);

  std::array<unsigned char, 37> captured{};
  const ssize_t got = ::read(pipefd[0], captured.data(), captured.size());
  assert(got == 37);
  assert(std::memcmp(captured.data(), guest.data(), guest.size()) == 0);

  // Unowned memory must fail closed without writing anything.
  const int flags = ::fcntl(pipefd[0], F_GETFL);
  assert(flags >= 0);
  assert(::fcntl(pipefd[0], F_SETFL, flags | O_NONBLOCK) == 0);
  const auto unsafe = handle_attached_stdout_write(
      kX86Write, kGuestStdOut, guestPtr, guest.size(), denied);
  assert(!unsafe.handled);
  assert(unsafe.reason == Reason::UnownedGuestBuffer);
  unsigned char byte = 0;
  assert(::read(pipefd[0], &byte, 1) < 0);
  assert(errno == EAGAIN || errno == EWOULDBLOCK);

  // A zero-length write must not inspect or dereference its guest pointer.
  const auto zero = handle_attached_stdout_write(
      kX86Write, kGuestStdOut, 0, 0, denied);
  assert(zero.handled && zero.value == 0);
  assert(zero.reason == Reason::ZeroLength);

  // Oversized buffers and all other descriptors/syscalls are not admitted.
  const auto large = handle_attached_stdout_write(
      kX86Write, kGuestStdOut, guestPtr, kMaxWriteBytes + 1, readable);
  const auto wrongNr = handle_attached_stdout_write(
      16, kGuestStdOut, guestPtr, guest.size(), readable);
  const auto stderrFd = handle_attached_stdout_write(
      kX86Write, 2, guestPtr, guest.size(), readable);
  const auto unknownFd = handle_attached_stdout_write(
      kX86Write, 100, guestPtr, guest.size(), readable);
  assert(!large.handled && large.reason == Reason::OversizedBuffer);
  assert(!wrongNr.handled && wrongNr.reason == Reason::NotApplicable);
  assert(!stderrFd.handled && stderrFd.reason == Reason::NotApplicable);
  assert(!unknownFd.handled && unknownFd.reason == Reason::NotApplicable);

  // Host errors are returned as real negative errno values.
  assert(::close(STDOUT_FILENO) == 0);
  const auto closed = handle_attached_stdout_write(
      kX86Write, kGuestStdOut, guestPtr, guest.size(), readable);
  assert(closed.handled);
  assert(closed.value == -EBADF);
  assert(closed.hostErrno == EBADF);
  assert(closed.bytesCopied == 37);
  assert(closed.reason == Reason::HostWriteError);
  assert(::dup2(savedStdout, STDOUT_FILENO) == STDOUT_FILENO);
  assert(::close(savedStdout) == 0);

  assert(::close(pipefd[0]) == 0);
  std::cout << "R3D49_X86_WRITE1_ATTACHED_STDOUT_OWNED_BUFFER_LOCAL_COPY_FAIL_CLOSED_PASS\n";
}
