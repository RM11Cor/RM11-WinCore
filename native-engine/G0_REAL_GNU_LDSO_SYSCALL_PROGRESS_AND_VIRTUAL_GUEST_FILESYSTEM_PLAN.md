# KERNIX G0 — actual unmodified GNU ld-linux syscall progression and unified guest-kernel gate

**Branch:** `kernix-native-engine-v1` only. **2026-11-06**.

## Proven by actual upstream FEXCore guest execution on Linux ARM64

The exact source-pinned original guest x86-64 main executable,
`ld-linux-x86-64.so.2` and `libc.so.6` have been copied into
OS-owned canonical x86 guest VAs with original `PT_LOAD`-derived
W^X permissions and rebased initial stack and AUXV. The original
GNU ld-linux entry and an unmodified original continuation execute
using the upstream FEXCore JIT's source-pinned entire `PT_LOAD PF_X`
executable-page callback. **No KERNIX user game runs here**.

* [Actual source main/ldlinux/libc JIT full PT_LOAD RX range, 15
  prior true x86 guest syscalls, Linux ARM64 PASS #42256352777](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42256352777).
  The bounded source callee still used the historical HLT. It is
  *not* proof of entire GNU loader completion.
* [Unmodified original GNU ld-linux continuation observation #42256712581](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42256712581):
  genuine first post-fixture x86 syscall **12** `brk(0)`, on original
  GNU source RIP, not a synthetic stub.
* [Native original main ELF program-break owner W^X, Linux+Bionic
  build-only PASS #42258367936](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42258367936).
  The actual native `brk` provider never forwards x86 guest
  `brk(12)` to host `brk/sbrk`; it grants RW only to source-permitted,
  spare, originally inaccessible pages of the exact native owner-held
  main image and caps growth at 1MiB. Fail closed on host 16K pages.
* [Original unmodified GNU ld-linux, native original owner-held
  `brk(12)` serviced under live FEX, NEXT syscall 21 `access`,
  PASS #42261852649](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42261852649).
  Exact first `brk(0)` returned original guest `0x800005000`;
  no host `brk` called.
* [Native source SHA locked `access(21)` optional original GNU
  `/etc/ld.so.preload` R_OK, Linux x86+ARM64 and Bionic compile
  PASS #42259918382](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42259918382).
  Only the exact read-only source loader `PT_LOAD` string is accepted;
  isolated source triad virtual root legitimately returns `-ENOENT`.
* [Actual GNU ld-linux under FEX after **both** `brk(12)`
  and `access(21)`, PASS #42262473937](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42262473937).
  Its next unsupported original GNU x86 guest syscall is
  **257 `openat`**, RIP `0x801025b6f`, RDI `0xffffff9c`
  (AT_FDCWD zero extended), RDX `0x80000` (O_RDONLY|O_CLOEXEC).
  The actual opened pathname must be source-verified, never guessed
  from these register values alone.
* [Original exact source `/etc/ld.so.cache` read-only
  `openat(257)` path, Linux x86+ARM64 and Bionic object
  PASS #42263617419](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42263617419).
  It verifies actual original source PT_LOAD pathname and both valid
  AT_FDCWD register forms, rejects writes, malformed pointers, and
  native host FS forwarding. Isolated virtual source triad has no
  cache, so only this exact optional cache path returns `-ENOENT`.
* [Actual real-FEX combined original GNU ld-linux
  `brk+access+openat` continuation observation #42264033595](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42264033595)
  is **PENDING** at this edit; do not claim pass until exact real
  Linux FEX logs show all three source markers and the true next
  unsupported guest syscall.

## Engineering decision: move away from scattered one-syscall patches

Stop multiplying mocked opcode counts and independent guest fixtures.
This triad root is a *bounded first milestone*, **not a substitute for
the real original GNU dynamic-linker's VFS requirements**. The single
next cohesive implementation should be a **SHA-locked guest-only
virtual Linux file system** with no guest-to-host pathname forwarding:

1. One canonical guest `openat(257)` path decoder reading only
   authenticated source original `PT_LOAD`, owned RW guest buffers,
   or other permission-verified guest VM ranges. Do not assume a
   pointer always comes from `ld-linux`. Accept zero-extended or
   sign-extended AT_FDCWD, block guest O_CREAT/O_TRUNC/O_WRONLY.
2. A read-only immutable virtual root with exactly the attested
   guest main interpreter and libc files (and a precise Linux
   `-ENOENT` result for missing `/etc/ld.so.preload`,
   `/etc/ld.so.cache` and unmatched names). Model verified
   guest library search directories as real virtual paths. Do not
   return success on unknown files or use the host's real paths.
3. Synthetic guest FDs with bounded ownership, open/close state,
   `read/pread64`, `fstat/newfstatat`, `lseek` only as needed,
   and precise original ELF backing bytes. Guest fstat flags and
   ELF mapping must be consistent with the source. No native FD
   from a game, user file or Android system is exposed to x86.
4. True source ELF `PT_LOAD` mmap and permission lifecycles:
   preserve genuine guest virtual addresses, `R`/`RW`/`RX`
   ownership, guard holes, bounded syscall errors, `mprotect`,
   `munmap`, then real GNU loader `RELA/RELR` and
   post-relocation `PT_GNU_RELRO`.
5. Original dynamic-linker `DT_NEEDED` graph, symbol lookup
   and versions, `IFUNC`, genuine TLS TCB/DTV and thread
   system calls. Source-derived KERNIX fixture relocation writes
   do **not** count as the GNU loader's own relocation loop.
6. On Android host 16KB pages, never grant conflicting 4KB
   guest subpage W and X; implement an explicit software guest
   subpage model or fail closed. A Linux 4KB native-page pass
   is not a physical REDMAGIC Android execution pass.

**Gates:** exact functional upstream FEX Linux ARM64 guest runtime,
same-source Android/Bionic AArch64 link-only, then carefully scoped
physical device runtime under the existing signed
`org.kernix.diagnostics` identity. Keep existing signed
Diagnostics v2, stable v0.27, prefixes and user game files intact.
Do not build a new partial v3 for another isolated syscall probe.
