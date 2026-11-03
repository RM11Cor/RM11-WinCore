# G2 Android/Bionic host preflight (v0.20)

G1 is preserved. The real user screenshot of v0.19 proved only the bounded ELF64 guest with four syscalls on Android. This separate G2-A probe does NOT execute any Windows PE or Wine code.

G2-A is an original Android arm64-v8a Bionic PIE bundled inside the signed KERNIX APK. It loads the pinned FEXCore library using dlopen, checks the real exported Initialize symbol with dlsym, observes real page size and reads /proc/self/status for Seccomp and NoNewPrivs when present. Missing security fields are recorded as unknown, not guessed. The strict Java verifier requires a successful process exit and exact output.

The probe is read-only and fixed: no external executable paths, no shell, no root, no guest rootfs, no restricted-syscall trial, no GPU stress and no auto repeated tests. The APK build verifies its actual Android ELF interpreter, dependencies and a byte-for-byte packaged SHA-256.

The next separate G2-B target is a reproducible original Wine loader and genuinely executed trivial Windows PE64 program, with source provenance, dependencies, process logs, exit code and import-resolution evidence. A FEXCore dlopen alone does not mean Wine works.

Architecture choices must be proven independently. Wine Linux x86-64 ELF uses glibc and a guest Linux loader/rootfs; WoW64 ARM64EC Wine integration is a distinct bridge. Neither path becomes Android-compatible merely from Linux ARM64 success. Android Bionic, sandbox/SECCOMP and graphics remain separate constraints. Do not use game benchmarks until genuine Windows PE startup and Vulkan/DirectX paths pass.
