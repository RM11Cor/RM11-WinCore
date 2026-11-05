# KERNIX G0 — Native guest Linux syscall bridge / Android ABI boundary

This phase moves beyond frame counts toward actual x86-64 Linux process behavior.
The separate G1 Android Vulkan 4/48/180 probes already passed on device at the bounded native queue level.

New file `android-host/kernix_g0_guest_syscall_dispatch.h` implements
**restricted functional Linux guest syscalls** behind the existing C1 x86-64
register/stack frame validation:
- `write(1, pointer, size)`: a host-selected output FD, exact owner-held readable guest
  memory interval, 4096-byte cap, bounded pointer arithmetic, real POSIX write
  and Linux negative errno on failure. No user-supplied host FDs.
- `getpid`: actual host PID; no pre-recorded fixture value.
- `exit/exit_group`: records a real guest exit request; does not terminate the Android host.
- `openat/mmap/mprotect/futex/arch_prctl/signals/TLS`: fail with -ENOSYS.
  No wholesale forwarding of x86 Linux syscall numbers into Android arm64.

The test deliberately builds an authenticated *test* trap, maps and seals a
real native read-only VMA, reads exact data from a host pipe, exercises
bad file descriptors, pointer overrun, invalid memory provenance, unsupported
guest syscalls, real PID and safe exit intent. **It does not run FEX or Android**.

Next work: consume only **actual source-pinned FEX CpuStateFrame trap callbacks**
and attach genuine app-private guest process/ld-linux/glibc ownership. Continue
Linux ARM64 runtime reference before Android packaging. The real x86 glibc
dynamic process remains BLOCKED until TLS, relocations, path-safe openat,
and guest syscalls are implemented. No new phone APK is justified from this
host-only primitive. Do not modify KERNIX stable v0.27 or user game files.

## Integrated with the existing native Android/Bionic FEX ELF runner

The earlier `kernix_fexcore_elf64_exec_probe.cpp` contained a private
special-case `::write` and `::getpid` implementation. It now uses the
shared G0 bridge for the **two actual SYSCALLs** of its independently
GNU-as/ld-assembled fixed x86-64 ELF after decoding the live FEX
CpuStateFrame with G2-E/C2's authenticated Linux x86_64 stack/ABI adapter.

The original ELF PT_LOAD readonly message and the host-owned guest stack
are passed as explicit current memory intervals. The bridge validates
that exact data window, writes exact guest bytes to host-selected
stdout, and puts the real PID in guest RAX for the second syscall.
The original x86 ELF remains a fixed glibc-free diagnostic and stops on HLT.

The separate Android NDK original FEXCore workflow cross-compiles this
exact integrated path and attests AArch64+Bionic dependencies. These
checks **do not mean the new integrated path executed on Android yet**;
the preceding FEX getpid bridge actually ran only on a real Linux
ARM64 CI host. This is an integration improvement, not the completion of
a full dynamic Linux `ld-linux`+libc process.
