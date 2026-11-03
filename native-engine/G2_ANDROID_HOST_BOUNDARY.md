# G2 Android/Bionic host preflight (v0.20)

G1 is preserved. The real user screenshot of v0.19 proved only the bounded ELF64 guest with four syscalls on Android. This separate G2-A probe does NOT execute any Windows PE or Wine code.

G2-A is an original Android arm64-v8a Bionic PIE bundled inside the signed KERNIX APK. It loads the pinned FEXCore library using dlopen, checks the real exported Initialize symbol with dlsym, observes real page size and reads /proc/self/status for Seccomp and NoNewPrivs when present. Missing security fields are recorded as unknown, not guessed. The strict Java verifier requires a successful process exit and exact output.

The probe is read-only and fixed: no external executable paths, no shell, no root, no guest rootfs, no restricted-syscall trial, no GPU stress and no auto repeated tests. The APK build verifies its actual Android ELF interpreter, dependencies and a byte-for-byte packaged SHA-256.

The next separate G2-B target is a reproducible original Wine loader and genuinely executed trivial Windows PE64 program, with source provenance, dependencies, process logs, exit code and import-resolution evidence. A FEXCore dlopen alone does not mean Wine works.

Architecture choices must be proven independently. Wine Linux x86-64 ELF uses glibc and a guest Linux loader/rootfs; WoW64 ARM64EC Wine integration is a distinct bridge. Neither path becomes Android-compatible merely from Linux ARM64 success. Android Bionic, sandbox/SECCOMP and graphics remain separate constraints. Do not use game benchmarks until genuine Windows PE startup and Vulkan/DirectX paths pass.

## User device result of G2-A

The v0.20 G2 host preflight was observed passing once on the real REDMAGIC Android device, reporting real `PAGE_BYTES=4096`, `SECCOMP_MODE=2`, `NO_NEW_PRIVS=0`, `FEX_CORE_LOAD=1`, `FEX_CONFIG_SYMBOL=1`, and explicit `WINE_PE_EXECUTED=0`. See `native-engine/evidence/android-g2a-bionic-fex-v020-device-pass.json`. A successful dlopen is not Windows PE execution. The older G1 button's initial state was reset on entering the app; it does not override the prior on-device G1 pass.

## G2-B foundation: Linux ARM64 source-proven Windows reference and safe private rootfs

A previous genuine [CI ARM64 FEX + Ubuntu Wine 9 run 41599070620](https://github.com/RM11Cor/RM11-WinCore/actions/runs/41599070620) proved x86_64 Linux guest ELF, two independently isolated real Windows PE64 launches (exit 0 with native Windows marker), Windows cmd.exe marker and an actual X11-visible Notepad window. Evidence was downloaded and SHA-256 checked as ZIP `7e6a5096bb2eadd799eb807275aa374902ef771a51fa69014b50bbd375bd75e3` (artifact ID 13213162294). The guest Wine9 archive hash in that evidence is `28956b226714d47ad335138ee0b1faa0a339a89aed659d0141033255bff4a882`. Note this is Linux ARM64 host with a Linux x86_64 guest rootfs, *not* Android Bionic.

**Key difference:** The Linux reference could mirror required Wine 9 files under the Linux host's `/usr/lib/wine`, originally absent. Android's app sandbox must not require global host filesystem writes: KERNIX will resolve guest Linux paths relative to a verified app-private rootfs instead. The first primitive `native-engine/android-host/kernix_guest_rootfs_readonly.h` takes a trusted root directory FD and opens one guest regular file using relative `openat` segments, denying `../`, duplicate separators, symlinks, control bytes and non-regular targets; no `open` path outside the root or write flags. Host unit tests run fail-closed in independent CI.

This is **only a tested resolver primitive**, not hooked to FEXCore syscalls or Wine's ELF dynamic linker. Real glibc rootfs has legitimate symbolic links and process/FD/VFS requirements; those remain unimplemented, and rejected by this strict first version. The next increment must use a source-pinned Wine9 Linux x86_64 guest package and a source-verified guest interpreter/rootfs, implement safe link resolution without host escape, then run a constrained x86_64 guest ELF and Windows PE via a *real* Android process. Do not label G2-B Android runtime as passed until logs show real PE output and exit 0 on the device.

## G2-B guest rootfs symlink resolution: second private-loader primitive (2026-11-03)

Original FEX+Ubuntu Wine 9 on ARM64 Linux has already been shown running real Windows PE64, cmd.exe and Notepad in run 41599070620; that proof was **not Android**. A future app-private guest rootfs needs to support legitimate Linux absolute symlinks such as `/lib64 -> /lib/x86_64-linux-gnu/ld-linux-x86-64.so.2` without dereferencing those targets on Android's host filesystem.

`native-engine/android-host/kernix_guest_rootfs_symlinks.h` adds `OpenGuestFileWithScopedSymlinks(rootfd, guest)`. The rootfd is already opened by trusted app code. The primitive walks with `O_PATH | O_NOFOLLOW` FDs, `fstat`, and `readlinkat(link_fd, "", ...)`. Absolute link destinations restart from the app-owned root FD; relative `..` cannot go above that root. The final open is read-only with `O_NOFOLLOW`, checks a stable inode relative to the prior `O_PATH` FD, and returns a regular-file FD or fails. Symlink expansions, path size, component count, and depth are bounded; directory/loop/control path tests are included. See [Linux readlinkat manual](https://man7.org/linux/man-pages/man2/readlinkat.2.html) for symlink-FD semantics.

**Limits:** This fd-by-fd user-space walk assumes the rootfs has no concurrent untrusted mutator performing directory reparent/mount races. It is NOT equivalent to kernel-enforced `openat2(RESOLVE_IN_ROOT)` on adversarial mutable roots, is not a drop-in ELF/glibc loader, and is not wired into FEX guest syscalls. It is only a validated Linux native host primitive. No claim is made of running Windows/Wine on Android. The next separate gate is to inventory/pin the guest x86_64 ELF interpreter and Wine runtime dependencies, then integrate them only after proving the Bionic host can enforce a safe rootfs boundary with real guest processes.
