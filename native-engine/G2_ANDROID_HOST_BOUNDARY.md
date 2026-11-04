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

## G2-B ELF interpreter and direct dependency audit (third isolated component)

`kernix_guest_elf64_dynamic_audit.h` now uses the previously tested `OpenGuestFileWithScopedSymlinks(rootfd,...)` for actual **x86-64 ELF64** bytes. It reads bounded ELF headers and `PT_INTERP`, parses the genuine `PT_DYNAMIC` segment including `DT_STRTAB`, `DT_STRSZ` and `DT_NEEDED` with virtual-address-to-file-offset translation, rejects malformed offsets and unknown `DT_RPATH/RUNPATH` search behavior, and resolves each **direct** SONAME in limited ordinary Linux guest library directories exclusively inside the private rootfd. It verifies ELF64 x86-64 identity of each resolved interpreter and direct library. It neither invokes `execve` nor loads guest code into FEX; all results explicitly set `guestCodeExecuted=false`, `executableLoaded=false`, `androidWineTested=false`.

The CI generates a real x86-64 dynamically linked PIE with `cc` on an x86-64 runner, copies that fixture and the *test runner's own* glibc loader and libc into a throwaway rootfs, points the guest loader through an absolute symbolic link, and requires actual `PT_INTERP` and `DT_NEEDED libc.so.6` resolution. It also requires fail-closed behavior for missing libraries, absent loader, symlink to host `/etc/passwd`, traversal and corrupted machine ID. The real x86 guest is **never executed** in this gate. The external rootfs files are Linux CI test fixtures, not distributable Android or Wine payloads.

**Limitations:** Direct library existence is not transitive dependency or symbol-version resolution. No FEX syscall handler, Linux guest interpreter execution, Wine code, Windows PE or Android runtime is wired to this reader. RPATH/RUNPATH, TLS, relocations, `ld.so.cache`, dependency closure, legitimate Wine9 path variation, Linux rootfs package pinning and Android seccomp/process behavior remain outstanding. Do not advance G2-B Android execution gate on metadata alone.

## G2-B read-only ELF DT_NEEDED transitive closure gate (2026-11-03)

The previous G2-B source verifier checked an actual x86_64 executable, its PT_INTERP loader and immediate DT_NEEDED dependencies inside a root-FD scoped app-private Linux guest file tree. New `kernix_guest_elf64_dependency_closure.h` now **walks those direct dependencies recursively** using the same constrained ELF metadata parser for each library (shared object mode requires no PT_INTERP). The loader itself is audited as a guest x86_64 ELF DSO. It fails closed if a transitive library is absent, substituted with a symlink pointing outside the guest tree, or has the wrong ELF architecture; visited-path sets, node/edge/queue limits bound cycles. No file is written except disposable CI fixture setup.

Native x86_64 CI compiles **three actual linked ELF binaries** (app, intermediate shared library, leaf shared library) with a real chain `app -> libkernix_mid.so -> libkernix_leaf.so`, stages the runner's glibc interpreter and libc in a disposable rootfs, and requires the complete closure to resolve. Negative cases remove the leaf, change its ELF machine, replace it with a symlink into guest `/etc/passwd`, remove the loader, and attempt traversal. The ELF program is **never executed**. Source and test: `native-engine/android-host/kernix_guest_elf64_dependency_closure.h`, `native-engine/android-host/tests/kernix_guest_elf64_dependency_closure_test.cpp`.

**Still blocked:** guest dynamic linker relocation, TLS, GNU symbol versions, `dlopen`, legitimate `RUNPATH/RPATH`, complete guest syscalls, Wine process services, full runtime rootfs pinning and any Windows program on Android. This static closure does not upgrade G2-B to an on-device execution PASS.

### glibc libc dynamic-interpreter exception

The initial real-ELF closure test failed because real Ubuntu x86-64 `libc.so.6` also contains `PT_INTERP` (it can run to print its version), whereas our DSO parser incorrectly demanded zero interpreters. This is not a translation defect. The corrected parser allows zero or one `PT_INTERP` in a DSO and requires that any present interpreter is a valid ELF inside the guest root. The recursive scanner audits this interpreter too, with a cycle-safe visited set and the same limits. Re-run actual full dependency-chain and negative tests; this is still a metadata test, not Android FEX/Wine execution.

## G2-B Android ARM64 cross-link proof (build-only)

The read-only ELF64 transitive dependency closure is now exposed through a narrow C ABI in `native-engine/android-host/kernix_g2b_android_elf_closure_entry.cpp`. It accepts a caller-owned trusted app-private root FD plus a bounded absolute guest path and returns counts of audited files and dependency edges only on a successful static closure. Invalid inputs, missing libraries or unexpected execution claims return errors. All guest files are opened relative to the root FD; the caller's FD remains owned by the caller.

The independent signed-APK CI workflow separately cross-links that source against **Android NDK API 26 ARM64/Bionic**, checks the resulting ELF64 target, Bionic libc and absence of unbundled shared C++ runtime, then uploads the exact binary, SHA-256 and provenance **as a build-only evidence artifact**. The library is deliberately NOT included in the APK or enabled in the UI yet. Linking on Bionic is not running the code or loading glibc under FEX. On-device G2-B remains unverified until a source-pinned Linux guest rootfs and real FEX guest execution can be safely connected.

## G2-B next execution prerequisite: non-executable ELF64 PT_LOAD staging (2026-11-03)

The new `native-engine/android-host/kernix_guest_elf64_readonly_image.h` stages actual ELF64 x86-64 `PT_LOAD` **file bytes** from a previously scoped app-private rootfs FD into a bounded anonymous host memory view. It validates the real program headers, file-to-virtual offsets, host page alignment (4KiB/16KiB), nonoverlapping segments, checked 32MiB image limit, absence of writable+executable guest segments, absence of an executable stack, and that the main executable's entry falls in its single x86 text load segment. BSS is left zero-initialized by anonymous mmap. After copying, the entire host image is protected `PROT_READ`; no `PROT_EXEC` permission is ever granted. RAII unmaps the region after inspection. This code is **not** yet a FEX guest virtual address mapping, ELF relocation engine, or execution loader. The mapping is not persisted across processes and cannot be mistaken for a running Linux guest.

The native x86_64 CI test compares every staged segment's exact bytes against the original real executable, glibc `libc.so.6`, and `ld-linux-x86-64.so.2`, verifies zero-filled BSS and rejects a deliberately corrupted ELF segment with `W|X`. It does **not** execute the real guest. An independent Android NDK API26/Bionic ARM64 shared library wraps this bounded operation for **build-only** cross-link evidence; it is not bundled inside a distributable APK and is not exposed to device UI. Source: `native-engine/android-host/kernix_g2b_android_readonly_elf_image_entry.cpp`.

**Unresolved G2-B execution gate:** establish FEX guest address-space ownership, map x86 guest PT_LOAD segments with correct *guest* permissions, initialize proper `AT_` AUXV/stack/TLS/argv, handle glibc dynamic linker relocation/symbol resolution, guest syscall forwarding, Android seccomp/process requirements and lifecycle. Only then attempt execution of a tiny dynamic Linux ELF through original FEXCore on Android. Previous G1/G2-A on-device PASS claims remain scoped and unchanged.

## G2-B Linux x86-64 initial process stack and AUXV layout (2026-11-03)

`native-engine/android-host/kernix_guest_linux_x86_initial_stack.h` now prepares bounded **host-memory bytes** for the x86-64 Linux process entry stack. The byte layout follows `argc, argv[], NULL, envp[], NULL, (AT_key, value)*, AT_NULL, 0`, with x86-64 little-endian 8-byte words and 16-byte aligned guest `RSP`. Strings and the caller-supplied 16-byte `AT_RANDOM` blob live at valid guest-stack pointers. It explicitly includes `AT_PHDR`, `AT_PHENT`, `AT_PHNUM`, `AT_PAGESZ`, `AT_BASE`, `AT_ENTRY`, UID/GID/EUID/EGID, `AT_SECURE=0`, `AT_RANDOM`, and `AT_EXECFN`. **The caller must provide independently verified runtime guest load addresses and entropy**; this builder does not invent a Linux process image, interpreter load bias, entropy, or credentials. It refuses out-of-bounds, empty, NUL/control-containing argument and environment strings, noncanonical guest pointers, missing or contradictory ELF identity, zero randomness, excessive counts, and memory overflow.

The Linux x86-64 CI unit test reads the actual binary ELF64 header and `PT_PHDR` of the independently compiled real dynamic PIE, derives *fixture-only* relocated main entry/PHDR addresses, builds the stack, and checks every argument pointer, environment string, ABI word, auxiliary entry, `AT_RANDOM` copy and 16-byte stack alignment. It runs negative cases for malformed inputs. The result is **not installed in FEX guest memory**, and the original dynamic ELF is not executed. All guest execution flags remain false. The Android API26 ARM64/Bionic CI separately cross-links `kernix_g2b_android_linux_stack_entry.cpp` to native code as a **build-only**, signed-APK-workflow evidence file: it is **not packaged or activated** in the phone app.

**Next genuine runtime gate:** reserve and own x86 guest virtual memory addresses under FEX, install verified `PT_LOAD` images and the initial stack into the same guest address space, place correct `AT_PHDR`, `AT_BASE`, TLS, loader entrypoint and signal/syscall callbacks, and perform a real dynamic x86 ELF process launch on Android. Missing `AT_HWCAP`/HWCAP2, VDSO, symbol-version information, glibc interpreter relocations and process services remain unresolved. This module alone does not demonstrate Linux glibc, Wine or Windows games.

## G2-B dynamic ELF launch plan integration (2026-11-03)

The next unit combines the prior distinct audits into `native-engine/android-host/kernix_g2b_guest_launch_plan.h`: it first checks the executable, its interpreter and direct/transitive ELF objects within an app-owned immutable rootfs. It stages actual executable/ld-linux `PT_LOAD` bytes in host **read-only, nonexecutable memory** and then derives the **relocated guest virtual** `PT_PHDR`, main `AT_ENTRY`, loader entry RIP and `AT_BASE` from the *actual* file-backed ELF headers with explicit fixture-address load biases. It rejects overlapping guest PT_LOAD segments, main/interpreter/stack collisions, noncanonical pointers, truncated/unmapped PHDR, main/loader entries outside executable file-backed bytes, and missing libraries. It creates the actual in-memory `argv/envp/AUXV` byte layout from those verified runtime addresses with 16-byte aligned guest `RSP`, then checks no executable pages or guest memory were installed. It clears the staged RO host views before returning a pure plan. The unit is proven via a real linked x86_64 ELF and actual ld-linux + glibc artifacts in Linux x86_64 CI, including negative collision/dependency tests.

**Critical boundary:** This remains an in-process **non-executing layout proof**. Supplied guest image VA choices are explicit CI fixture values, not a real randomized guest address-space allocator. No `mmap(MAP_FIXED_NOREPLACE)` reservation, FEX core context setup, JIT guest RIP/RSP, glibc execution, relocation, TLS, syscalls or Windows Wine launch occurs. Stage code is cross-linked on Android Bionic ARM64 via `native-engine/android-host/kernix_g2b_android_launch_plan_entry.cpp` as build-only artifact, **not in distributable APK**. After this passes, a separate isolated child needs real guest VA ownership, page permissions, mapping and a strictly bounded Linux guest process before attempting `ld-linux` on device. Do not claim mobile Wine compatibility.

## G2-B Linux guest HOST address reservation: PROT_NONE only (2026-11-04)

`native-engine/android-host/kernix_g2b_guest_host_reservations.h` now acquires real Linux-kernel-selected anonymous `mmap(nullptr,...,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS)` windows for the **actual** main dynamic ELF, ld-linux interpreter and x86 guest stack sizes. It includes inaccessible guards and alignment slack. It does **not** supply fixed addresses to `mmap`, does not use `MAP_FIXED`, `MAP_FIXED_NOREPLACE`, `mprotect(PROT_EXEC)`, raw writable page pointers or a callback into FEXCore. Each window is held by an RAII reservation and released on failure/destruction. Window spans are individually capped at 32MiB and all planned guest ranges must lie inside their particular kernel-reserved, inaccessible host windows. A `PROT_NONE` window is **not** a mapped executable guest PT_LOAD, and the returned launch plan retains `guestAddressSpaceReserved=false`, `guestMemoryMapped=false`, `fexEntryPointAssigned=false`, `guestCodeExecuted=false`. The separate wrapper's build artifact cannot be called by the current Android UI and explicitly does not return stale freed host window addresses as active execution pointers.

Linux native CI compiles a real x86_64 dynamically-linked PIE, intermediate and leaf libraries, stages actual Linux libc and ld-linux inside a temporary rootfs, reserves the three windows at **kernel-chosen** addresses, reads the actual `/proc/self/maps` permissions to confirm `---p`, checks guest ELF/stack/AUXV consistency, verifies no overlap with image and stack windows, tests all unsupported input cases including a missing transitive DSO, and confirms cleanup. This is much safer than a guess about the Android process VA layout, but it **is still host Linux test coverage**, not proof Android kernel grants those exact address placements or that FEX can access them. A separate NDK/Bionic ARM64 wrapper in `kernix_g2b_android_host_vm_reservations_entry.cpp` is cross-linked as **build-only evidence** and remains intentionally excluded from the APK. No new device test is required from the user.

**Next gate (not yet met):** Acquire explicitly owned FEX guest virtual address space in a bounded isolated Android child; use FEX's actual address-management and syscall semantics, stage original guest ELF PT_LOAD with correct runtime page protections and initial stack bytes only there, and prove an actual guest dynamic Linux executable exit code with watchdog and evidence. The NOACCESS placeholders themselves cannot be directly executed or presumed compatible with FEX.

## G2-B host-owned ELF+stack bytes inside guarded memory (2026-11-04)

`native-engine/android-host/kernix_g2b_readonly_host_install.h` now upgrades the **existing kernel-selected host PROT_NONE reservations** for a controlled fixed ELF64 x86 guest and its Linux interpreter. The source ELF segments are verified and staged to read-only anonymous buffers. For a trusted immutable guest rootfs only, the code briefly applies `mprotect(PROT_READ|PROT_WRITE)` to the already-owned mapped guest windows, copies the exact validated main ELF and interpreter `PT_LOAD` image bytes plus the previously audited Linux argv/envp/AUXV stack bytes, then transitions each window to **`PROT_READ` only**. The adjacent guard pages remain `PROT_NONE`. `mprotect(PROT_EXEC)` and `MAP_FIXED` are never called; there is no x86 guest execution. Host page-size alignment is required for the entire window, rather than silently opening a 16KiB host guard through a smaller 4KiB guest window. On any failure the owned windows are unmapped by RAII and state flags cleared. This is a controlled _host-process memory staging_ proof, not FEX's guest VM mapping or a valid x86 process runtime.

The prior Linux x86_64 integration test now also inspects real `/proc/self/maps` permissions for `r--p` on all three staged windows and `---p` on their guards, compares the actual mapped bytes to the verified ELF main and interpreter image bytes and entire AUXV stack byte-for-byte, and asserts FEX, guest execution, Wine and DirectX flags remain **false**. The Android NDK/Bionic ARM64 build-only wrapper invokes the same routine as a C API but never exposes those transient addresses (all returned window addresses are zero); its runtime artifact is deliberately excluded from APK. This approach is an isolated, observable milestone before implementing FEX-managed guest address ownership, code-translation permissions and syscall callbacks. Nothing new is ready for a user game test.

## G2-C new executable proof candidate: actual FEX enters a dynamic x86 PIE's own _start (2026-11-04)

The user needs **real translation execution**, not another series of static planning gates. The next independent actual ARM64 Ubuntu GitHub Actions workflow is `.github/workflows/kernix-g2c-real-fex-dynamic-pie-arm64.yml`. It rebuilds exact unmodified FEXCore SHA `02e24ca5c01ed0c864466ed573db347336f70170`, cross-builds a real x86-64 PIE that has both genuine `PT_INTERP /lib64/ld-linux-x86-64.so.2` and `DT_NEEDED libc.so.6`, assembles distro x86 libc + loader in a private guest rootfs, uses existing G2-B guest dependency closure/AUXV/host guarded PT_LOAD staging, transitions the *fixed main x86 text only* to `PROT_READ|PROT_EXEC` and points the original FEX CPUState's `RIP` at **the main PIE's own `_start`, not `ld-linux`**. The signed and bounded guest instructions validate actual `argc`, `argv`, `envp`, `AT_PHDR`, `AT_PAGESZ`, `AT_BASE`, `AT_ENTRY`, `AT_RANDOM`, `AT_EXECFN`; finish by HLT with exact RAX `0x4b45524e49584732`. All SYSCALL instructions are **forbidden** by the custom FEX handler. The job is Linux ARM64 only and runs under `timeout -k 3s 20s`; evidence records the real OS exit code and exact x86 register witness, with fail-closed proof verification. No root, dynamic loader execution, Wine processes or game execution. It does not modify the distributable Android v0.20 app, and does not ask the user to install a new APK.

**Release gate separation:** Creating this workflow and a successful static x86 ELF metadata check **do not** mean FEX has run the new guest. Only the actual native ARM64 FEX Actions run, status `completed/success`, exact marker, return code 0 and expected RAX prove **G2-C direct PIE entry**. Even when it passes, the full G2-B/G2-C *dynamic Linux glibc interpreter execution on Android* gate remains CLOSED: true `ld-linux` entry, relocations, TLS, guest syscall ABI, VDSO and Bionic restrictions remain independent. The first Android test must use a signed, fixed, independently supervised child without guesswork or unchecked input.

### Valid zero-length PT_LOAD support for real x86 dynamic PIE

During G2-C real ARM64 preflight, the source-generated x86 PIE contained a valid empty GNU-ld `PT_LOAD` (`p_filesz=p_memsz=0`). The previous stage parser incorrectly treated all zero-length loads as invalid and blocked before FEX executed. The parser now ignores only the fully empty non-mapping entry; any nonzero file data with zero memory, out-of-bounds sections, W+X populated regions or conflicting segment mapping remains rejected. G2-C workflow watches changes to this exact header. ARM64 FEX execution is not considered passing until the independent real-JIT run reports the exact marker.

## G2-C actual native Linux ARM64 FEX JIT dynamic PIE direct entry — VERIFIED PASS (2026-11-04)

The independently built GitHub Actions [run 41787757643](https://github.com/RM11Cor/RM11-WinCore/actions/runs/41787757643) **completed successfully** at source commit `d2fa001aace6e3f71852d13ade0dbe18aa3c8ea7`. Original upstream FEXCore SHA `02e24ca5c01ed0c864466ed573db347336f70170` compiled natively for Ubuntu ARM64, and the x86-64 guest ELF contained genuine PT_INTERP and DT_NEEDED libc.so.6 from the distro x86 cross-compiler. KERNIX loaded ELF and prepared the x86 Linux process entry stack; the **actual original FEXCore JIT executed the guest executable's own `_start`** (deliberately *not* the ld-linux interpreter). Guest x86 machine code checked `argc/argv/envp`, `AT_PHDR`, `AT_PHENT`, `AT_PHNUM`, `AT_PAGESZ`, `AT_BASE`, `AT_ENTRY`, `AT_RANDOM`, `AT_EXECFN`, ending on HLT with the exact register `RAX=0x4b45524e49584732` and Linux process exit 0. The exact proof marker is `KERNIX_G2C_REAL_X86_DYNAMIC_PIE_DIRECT_ENTRY_STACK_AUXV_FEX_ARM64_PASS_NOT_GLIBC`. No guest syscalls were permitted or required. See `native-engine/evidence/linux-arm64-fex-g2c-real-dynamic-pie-direct-entry-pass.json`.

**Two audited blockers found/fixed without patching upstream FEX:** (1) original ELF parser rejected legal empty PT_LOAD emitted by GNU ld; now it ignores only zero-file/zero-memory PT_LOAD. (2) native ARM64 Linux selected host memory VAs outside the x86-64 47-bit canonical guest range; the allocator now makes ordinary **non-MAP_FIXED** low-canonical mmap hints, checks the actual kernel-selected address, and fails/munmaps anything outside range. Additional CI failures were build-only setup: missing x86 libc-dev cross package and compiler treating unmodified upstream FEX header warnings as errors.

**What is and is not proved:** real FEX code execution, prepared main PIE PT_LOAD, Linux initial guest argv/envp/AUXV ABI and expected CPU register result are **PROVED on Linux ARM64 only**. This is substantially beyond file inspection and is a positive isolated milestone. **Not proved:** executing guest PT_INTERP dynamic loader, glibc relocations, GNU symbol resolution, TLS/FS, syscall process ABI, Android Bionic/seccomp compatibility, running Wine/Windows executables or games. Do not label G2-B complete or create G2-C Android PASS evidence from Linux logs. Mobile installation unchanged; G1 and G2-A mobile evidence preserved.

The next bounded gate is (a) verified Android AArch64 NDK build of this exact FEX+ELF probe and preflight source under app-private distribution, then (b) a device child with 8s watchdog running a fixed original signed fixture, (c) only after that, a separate original `ld-linux` entry and glibc syscalls benchmark. Never expose arbitrary ELF execution before verified containment.


## G2-C Android bounded child supervision contract — CI PASS (2026-11-04)

After independently successful G2-C original FEX x86 PIE direct-entry on Ubuntu ARM64
(run 41790833179), and exact Android NDK/Bionic driver cross-linking
(run 41789653101), Android's immutable guest input handoff passed
(run 41792301704). Those three results are separate and do NOT establish
G2-C guest execution on Android.

The next isolated stage now includes the Android source class
G2CAndroidChildSupervisor.java. It validates the exact app-private runtime-v1
rootfs location using G2CFixedGuestFixture.attestAppPrivate, restricts the
future child to a fixed APK-shipped ARM64 ELF filename and exact SHA-256,
permits no shell or arbitrary game path, clears extraneous environment
variables, and supervises the child with an eight-second deadline, forcibly
killing it on timeout or completion. Both child stdout/stderr are drained
concurrently with 2 KiB caps. A zero exit code, exact Android-specific stdout
marker and a non-timeout are mandatory to classify future child output as pass.

**Release interlock CLOSED:** the approved Android native runner SHA-256 is
deliberately empty, so G2CAndroidChildSupervisor.run() always returns
KERNIX_G2C_ANDROID_EXECUTION_GATE_CLOSED today, even if a fake file exists in
app storage. The class is not exposed in MainActivity. The JVM test exercises
deterministic fake-process success/failure/timeout, malformed and oversized
logs, path redirection, package component allowlisting and app-private
fixture bytes, without launching an Android guest.

The isolated GitHub [run 41793128461](https://github.com/RM11Cor/RM11-WinCore/actions/runs/41793128461)
passed strict x86 fixture verification, archive tampering rejection and the
Java child-supervisor test. This is a **JVM contract pass, NOT a device-executed
G2-C PASS**. Previous Android host preview v0.20 remains at its limited scope.

**Next genuine execution gate:** implement and independently audit an actual
Android/Bionic ARM64 child using original FEXCore and native FD-pinned
app-private x86 image provenance (closing the Java check-then-open race),
process page-size/4K-16K layout validation and live syscall/signal constraints.
Recheck source/ABI/provenance, package only verified immutable assets under a
stable signing identity with necessary upstream licenses, pin the resulting
runner digest and enable the child only for a user-initiated bounded run.
Prove device RAX, exit code and watchdog evidence before ld-linux, Wine/games.


## G2-C native fixed-guest descriptor and Android/Bionic cross-link gate (2026-11-04)

The Linux ARM64 original FEX direct x86 dynamic-PIE entry proof remains pinned
to CI run 41790833179. G2-C native Android ELF compilation/linking against
original FEXCore passed again in run 41794116551.

**Safety correction:** The previous Android-only symbol named
kernix_g2c_android_build_only_link_check accepted a non-null path and called
the full guest execution routine even though this binary was marked
BUILD-ONLY. Its callable bypass is now removed. The exported witness always
returns 126; the original execution implementation is retained for linker
analysis with the compiler's used attribute, but has no exported Android
execution entry. The native CI recompiled the real FEX code successfully.

The new header native-engine/android-host/kernix_g2c_native_fixed_guest_fd_guard.h
pins all four original fixed G2-C x86 ELF files as read-only Linux/Android
file descriptors using explicit openat with O_NOFOLLOW and O_DIRECTORY
traversal relative to the app-private files directory. It validates the
app-owned UID, each exact size and SHA-256 (incremental SHA-256 implementation
checked against three standard test vectors), rejects writable files,
missing files, altered content and symbolic links, and retains open fds only
when all four identities match. No Linux host /lib path is used. All result
flags concerning guest execution, Wine and game readiness remain false.

A separate Android NDK API26/Bionic ARM64 library
native-engine/android-host/kernix_g2c_android_native_fd_guard_entry.cpp
builds this identical verifier as a **BUILD ONLY** artifact with no ELF
guest execution or FEX runtime load. [CI run 41794619048](https://github.com/RM11Cor/RM11-WinCore/actions/runs/41794619048)
passed the Linux host negative tests and the Android AArch64 cross-link,
including a verified Bionic libc dependency and absence of glibc or
unbundled libc++ shared runtime. This guard is not packaged into the APK
and does not execute on a phone.

**Remaining security gap:** descriptor pinning by itself only pins inodes,
not immutable file bytes; same-UID in-place mutation can still occur after
hashing. Moreover the current FEX ELF loader can reopen paths separately
rather than consuming the verified descriptors. Before enabling Android
execution, use a verified immutable/sealed snapshot or equivalent
inode-stable byte-for-byte handoff and route *every* FEX loader read through
that attested snapshot. Keep the 8-second child watchdog and qualification
digest gate closed until this, actual native driver integration, appropriate
distribution licenses, and device tests pass. No genuine Android x86
dynamic-PIE entrypoint, glibc interpreter, Wine or game run is established
by this gate.


## G2-C verified anonymous read-only snapshot gate (2026-11-04)

After SHA-256-pinned source file descriptor checks passed, the next gate
copies all four pinned x86-64 ELF fixture files into independent
MAP_PRIVATE|MAP_ANONYMOUS host mappings, re-hashes the **copied bytes**
against the original fixed digest, and changes each mapping to PROT_READ
with mprotect. The source pathname is not used during the memory snapshot
copy and no path is reopened. Total captured bytes are bounded to 3 MiB.
The snapshot object frees mappings with munmap and refuses partially
completed captures. Neither FEX, dynamic ld-linux nor guest instructions
are executed here.

A native Linux test verifies original SHA-256 bytes, checks the mappings
are kernel-reported r--p, then modifies and unlinks the app-private source
test ELF: subsequent source-file attestation fails while the captured
anonymous byte image continues to pass the original digest. The separate
Android NDK API26 AArch64/Bionic build-only exported probe includes the
identical snapshot code, validates the native linker dependencies and
does not distribute it in the user APK.

[GitHub Actions run 41795501155](https://github.com/RM11Cor/RM11-WinCore/actions/runs/41795501155)
passed BOTH the native hostile-file tests and Android/Bionic link checks.

**Important remaining limit:** PROT_READ is not memfd sealing; other
code in the *same process* could deliberately call mprotect to make
anonymous pages writable again. More importantly, existing G2-C FEX guest
loader code still independently opens source files. FEX is NOT wired to
these images, and the checked bytes are not yet the bytes consumed by
FEX. The next distinct gate must convert every ELF interpreter/main
file read to the same attested in-memory snapshot or to a separately
audited kernel-sealed fd, with no fallback to pathname access. The
Android child supervisor's qualified-runner SHA-256 remains empty and
its executable gate remains closed. There is still no verified
Android on-device G2-C, glibc, Wine or Windows game execution.


## G2-C original FEX now executes x86 main PT_LOAD from verified anonymous memory (2026-11-04)

The source-level ELF image PT_LOAD validator now accepts both an existing
read-only Linux guest root FD and an explicit pathless byte span, with
the SAME bounds, W^X, page-alignment and ELF64 identity checks. G2-C uses
kernix_g2c_snapshot_elf_source.h to stage the known x86 dynamic PIE and
ld-linux interpreter directly from the four exact SHA-256-verified anonymous
snapshot byte arrays, with no path reopening in that staging function.
The host guest-VA installer accepts the already verified ELF images through
StageX86ReadonlyHostBytesFromImages and compares the real relocation
layout/entrypoint against the independently built guarded launch plan. Its
legacy root-FD adapter remains for backwards compatibility.

[Handoff CI run 41796371287](https://github.com/RM11Cor/RM11-WinCore/actions/runs/41796371287)
passed immutable snapshot PT_LOAD tests and the Android ARM64/Bionic
**BUILD ONLY** cross-link, but at that point no original FEX JIT consumed the
new snapshot-backed guest code.

The subsequent [bounded host staging CI run 41797581910](https://github.com/RM11Cor/RM11-WinCore/actions/runs/41797581910)
passed an actual guarded guest-VA and stack installation from the two
verified anonymous ELF PT_LOAD images, retaining inaccessible guard regions
and no FEX guest execution.

**Crucial actual FEX runtime evidence:** [GitHub ARM64 FEX run 41797441557](https://github.com/RM11Cor/RM11-WinCore/actions/runs/41797441557)
completed SUCCESS on source commit 2e107e8c5a20e319d6a562502885d8b27ed3f0d0.
It ran the unmodified pinned original FEXCore at upstream commit
02e24ca5c01ed0c864466ed573db347336f70170 with the original
x86_64 dynamic PIE witness twice, each in its own 20-second
timeout-bounded Linux ARM64 child:

- Baseline root-FD PT_LOAD staging: exit 0, exact guest RAX
  0x4b45524e49584732.
- New pathless SHA-256-attested memory PT_LOAD staging for the identical
  real x86 guest: exit 0, exact guest RAX 0x4b45524e49584732, explicit
  KERNIX_G2C_STAGE=RX_PTLOAD_FROM_VERIFIED_ANONYMOUS_SNAPSHOTS_NO_PATH_REOPEN.

This **proves the actual Linux ARM64 FEX JIT executed main x86 guest
instructions from our verified anonymous snapshot-backed PT_LOAD**, not
merely an independent ELF parser. The interpreter was staged from the
verified snapshot but was deliberately **not executed**: FEX entered the
main executable's _start directly. The fixed DT_NEEDED libc.so.6 and
PT_INTERP remain ELF metadata fixtures. Metadata, dependency closure and
initial-stack preparation still read a checked app-private rootfs; they have
not yet been refactored to a single in-memory source. No untrusted
executable path, arbitrary PE file or user game was run.

**Do NOT misinterpret this as an Android device pass.** The full FEX
snapshot JIT proof above is on Ubuntu ARM64 Linux, not Android/Bionic,
and neither Wine nor any Windows application was executed in this gate.
The separate Bionic compile/link tests remain distinct from device
execution. The Android child supervisor has an intentionally empty
qualified-runner hash; user-accessible G2-C activation remains disabled
until all native runtime, licence and device-safety gates pass.


## G2-C single-source snapshot closure, PHDR and initial x86 stack (2026-11-04)

The fixed SHA-256 guest image resolver is now used end-to-end for
Linux x86_64 ELF metadata, transitive DT_NEEDED closure, PHDR addresses,
PT_INTERP path, initial stack (argv, envp and AUXV), host guest virtual
address reservation and PT_LOAD installation. The original root-FD APIs
remain as thin compatibility adapters to the same ELF validation code.

The new G2-C route uses exactly four attested anonymous read-only
file snapshots: the main x86 ELF64 PIE, x86 libc.so.6, one copy of
ld-linux-x86-64.so.2 under /lib/x86_64-linux-gnu and an identical
copy under /lib64. No resolver fallback to the on-disk rootfs exists.
Unknown dependencies and paths are rejected instead of consulting
the Android/Linux host's own system libraries.

CI [run 41798671650](https://github.com/RM11Cor/RM11-WinCore/actions/runs/41798671650)
passed snapshot-only recursive ELF dependency analysis even when the
original source libc.so.6 was deliberately changed and unlinked.
CI [run 41799040776](https://github.com/RM11Cor/RM11-WinCore/actions/runs/41799040776)
passed byte-for-byte parity of x86 initial stack and AUXV against the
original root-FD layout, even after source deletion. CI
[run 41799541904](https://github.com/RM11Cor/RM11-WinCore/actions/runs/41799541904)
passed a second allocation of guarded guest virtual address mappings
and installation of complete x86 PT_LOAD bytes after the original
on-disk program file was removed. The same code compiled and cross-
linked for Android ARM64/Bionic BUILD ONLY; these are NOT device tests.

The genuine Linux ARM64 FEX executable source has been updated so
the snapshot mode no longer opens the original rootfs path. It uses
the verified four-file resolver for metadata, regions and the stack
and the verified image buffers for main RX PT_LOAD at FEX entry,
while the prior Linux root-FD baseline remains available separately.
**Proven real FEX/JIT and Bionic results:** The isolated
[Linux ARM64 FEX run 41799783841](https://github.com/RM11Cor/RM11-WinCore/actions/runs/41799783841)
completed SUCCESS on source SHA 38901431b9ebd598ec9e814b47c12ad2dd4d095d.
Its *second*, independent real x86-64 PIE direct-entry run consumed the
verified anonymous snapshots for the entire fixed DT_NEEDED/PHDR/AUXV
launch plan, guest VA reservation and executable main PT_LOAD. The exact
RAX returned by upstream FEX JIT was 0x4b45524e49584732 with exit code
zero; stderr contained BOTH the RX snapshot PT_LOAD witness and
KERNIX_G2C_STAGE=PT_INTERP_TRANSITIVE_NEEDED_PHDR_AUXV_FROM_SNAPSHOT_ONLY.
The existing root-FD Linux FEX baseline also passed separately in the
same job with identical RAX. Failure of either marker, guest RAX, or exit
code fails the release gate.

The distinct [Android ARM64/Bionic FEX NDK run 41799783944](https://github.com/RM11Cor/RM11-WinCore/actions/runs/41799783944)
also completed SUCCESS after fixing the missing header include at
commit 38901431: the source-compiled original FEXCore and full
snapshot-capable G2-C Android *BUILD-ONLY* driver linked against
Android libc and system linker64. This does **not** demonstrate any
on-device ARM64 FEX guest execution; Android main() intentionally
returns 126 and the user APK gate remains closed.

Remaining work after independent native execution PASS: a genuine
bounded Android/Bionic runtime child with a qualified signed APK
binary, user-initiated device proof, 4KiB/16KiB memory validation,
permitted executable page policy and correct FEX failure reporting.
Actual guest ld-linux/glibc startup, Wine, PE and Windows games are
separate release gates not satisfied by direct-entry _start.


## G2-C genuine bounded native process DATA-ONLY readiness gate (2026-11-04)

The first deliberately **non-FEX** Android/Bionic child ELF source is now
native-engine/android-host/kernix_g2c_bionic_data_only_child.cpp.
It accepts only the fixed flag --fixed-data-only-preflight and an absolute
app-files directory. It pins and SHA-256 verifies exactly the original four
guest files, captures independent anonymous read-only snapshots, audits the
snapshot-only transitive x86 ELF dependency closure, reserves guarded host
virtual address ranges, constructs the x86_64 PHDR/AUXV/initial stack and
stages the bounded PT_LOAD bytes RO. It does NOT mprotect guest pages RX,
instantiate FEXCore, execute guest _start, run guest glibc, Wine or games.
The child has a distinct data-only stdout marker and a separate exact
non-execution stderr marker; its result is never treated as the FEX JIT pass.

The existing Java 8-second G2CAndroidChildSupervisor is exercised with
an **actual separately created Linux native child**, not just a
FakeProcess. G2CAndroidRealDataChildContractTest verifies an exact successful
native stdout/stderr/exit result, rejects the same output when supplied to
the FEX-only supervisor, rejects unsupported command-line arguments and
SHA-256-corrupted fixture files, rejects oversized real output, and kills
a genuinely hung native child at the eight-second watchdog deadline.
Deliberately hanging/oversized-output native modes exist ONLY under
KERNIX_G2C_LINUX_HOST_CI in the Linux test executable and are absent from
the Android/Bionic build.

**Verified [CI run 41801403259](https://github.com/RM11Cor/RM11-WinCore/actions/runs/41801403259):
SUCCESS.** Linux real separate-process / watchdog checks passed. The exact
same normal data-only source separately cross-linked to an ELF64 AArch64
Android/Bionic **PIE executable**, with /system/bin/linker64 as PT_INTERP,
libc.so and no unbundled libc++_shared.so or glibc libc.so.6. The
16KiB maximum ELF page-size linker policy is used. The only preserved
Android build evidence is ABI text and an ELF digest, NOT a redistributable
executable or installable APK.

**Security boundary limitations:** ProcessBuilder spawns a separate
OS process but does not by itself establish a different Android UID,
SELinux domain, seccomp sandbox or dedicated isolatedProcess service.
No Android child/device execution took place in this run. Neither the
future FEX runner nor its libraries have been admitted into the signed
APK, the qualified FEX runner SHA-256 remains empty, and the production
G2CAndroidChildSupervisor.run() still returns the CLOSED marker.
Do not infer phone readiness, actual guest JIT or any Windows game
compatibility from data-only Linux child execution or Bionic cross-link.

Before user-device testing, evaluate Android process-launch restrictions
and SELinux, verify extracted executable identity and ELF dependencies
inside the signed installation, run measured 4KiB and 16KiB memory pages,
confirm correct failure/timeout signaling on real REDMAGIC hardware,
and only then separately qualify the original FEX JIT-enabled child.


## Signed KERNIX v0.21 Android G2-C safe page probe packaged (2026-11-04)

The identical G2-C data-only Android/Bionic C++ child code is now shipped
as a real, separate signed-APK native PIE:
`lib/arm64-v8a/libkernix_g2c_data_only_child.so`.
It has an independently whitelisted, mandatory *exactly one argument*
`--android-host-page-preflight` mode which requires NO downloaded guest
rootfs: it reads the real host process page size (only 4 KiB or 16 KiB
accepted), allocates two anonymous PROT_NONE pages, changes only the
first to PROT_READ, verifies its anonymous zero contents, unmaps the
region, and returns a bounded, strict ABI/page/permission marker. This
mode NEVER permits PROT_EXEC, FEX guest instruction execution, Wine
or games; it never opens a guest x86 ELF.

The user's Android APK UI has a separately labelled G2-C page preflight
button which starts that fixed signed native executable from the
extracted APK native-library directory on demand. Android Java's
G2CAndroidPageProbe supervises it with the existing eight-second
G2CAndroidChildSupervisor watchdog, strict child stdout/stderr format
and fail-closed 4K/16K matching. A Linux host CI variant explicitly
announces `ABI=linux-host-ci` and can NEVER be presented as Android
device PASS. No shell invocation, arbitrary executable path or
writable app-data ELF execution is accepted.

[CI 41803140095](https://github.com/RM11Cor/RM11-WinCore/actions/runs/41803140095)
completed SUCCESS: the very same C++ child ran the page test in a real
host OS process supervised by Android-source Java, plus the original
tamper, eight-second timeout and output flood negative cases. The
Android NDK C++ data-only PIE also cross-linked separately. The
earlier failure was only a host test mistakenly passing an extraneous
third CLI argument, fixed at ecbd3b3d.

[Signed Android host APK run 41803140038](https://github.com/RM11Cor/RM11-WinCore/actions/runs/41803140038)
completed SUCCESS. The published
[APK artifact 13309480068](https://github.com/RM11Cor/RM11-WinCore/actions/runs/41803140038/artifacts/13309480068)
is the actual private-key-signed v0.21 technical host preview. GitHub
confirmed both x86-code-free APK contents and binary SHA256 equality
between built child and the packaged APK, as well as stable signer
certificate `a74735bc30b53e590589d8ff5c233f72dc0e4ddf6e312939d668ae30c46b6f8e`
and package ID `org.kernix.host`. No glibc guest rootfs is distributed.
Release versionCode is 21 (previous 20), and
[CI 41803184819](https://github.com/RM11Cor/RM11-WinCore/actions/runs/41803184819)
verified the signing DSL and a NON-DISTRIBUTABLE disposable-key
versionCode 21 -> 22 contract without changing the production signer.

**Device gate remains UNPROVEN.** GitHub's Linux execution and Android
cross-compilation/APK cryptographic verification do not demonstrate
Android 16 execution on actual REDMAGIC 11 Pro hardware, page-size
compatibility, actual platform SELinux policy or isolated UID. This
page probe is a separate process with the same app UID; it is NOT an
`isolatedProcess` service and should not be described as a full
security sandbox. The original G2-C FEX child supervisor's runner SHA
is still deliberately empty and the FEX guest activation remains
CLOSED. The signed APK is a page/permission readiness test, NOT a
Windows game-running emulator.

Next practical on-device evidence: user-initiated tap on the specific
G2-C safe page test button with reported ABI=aarch64, 4096/16384
HOST_PAGE_BYTES, and exact PASS marker; on failure collect the exact
bounded report before enabling any FEX runtime child.


## G2-C FIRST user-reported real REDMAGIC 11 Pro Android execution evidence (2026-11-04)

The user installed signed KERNIX v0.21 and supplied an on-device
screenshot of the result of explicitly tapping the new
"G2-C: test Android memory pages (safe, no FEX)" button.
This is **user-supplied visual evidence**, NOT an ADB/instrumentation
capture, independently checked physical device logs, or GitHub CI.
The visible native-child markers are:

```text
KERNIX_G2C_ANDROID_DEVICE_PAGE_PREFLIGHT_PASS_NO_FEX
KERNIX_G2C_ANDROID_PAGE_CHILD_8S_PASS_NO_FEX
KERNIX_G2C_ANDROID_PAGE_PREFLIGHT_V1
ABI=aarch64
HOST_PAGE_BYTES=4096
PROT_NONE_RESERVATION=1
PROT_READ_TRANSITION=1
GUEST_EXECUTED=0
FEX_EXECUTED=0
WINE_EXECUTED=0
No x86 guest, dynamic loader, Wine or game executed.
```

**Gate status: G2-C device DATA-ONLY page/protection/PIE subprocess:
USER-REPORTED PASS on REDMAGIC 11 Pro / Android 16 / AArch64 / 4KiB
host pages.** The app received the expected exact process output under
its 8s watchdog, and original host anonymous PROT_NONE and read-only
mprotect calls passed. This independently corroborates (with visual
device evidence) the earlier CI source/ELF/packaging checks. This does
not prove 8s timeout behavior on the actual Android device; forced
timeout behavior was tested on Linux host CI only.

Other gates remain **UNPROVEN/NOT RUN on this phone**: original FEXCore
load in the existing "Check G2 Bionic + FEX host boundary" button,
full G2-C FEX JIT child and guest x86 dynamic PIE, guest ld-linux/glibc
startup, FEX syscall bridge under G2-C, Wine, PE, graphics translation
and actual Windows games. The snapshot fixed guest files are not
packaged in v0.21. No change has been made to the closed G2-C
FEX runner SHA authorization.

**Next single device action:** In the same v0.21 preview APK,
tap the existing "CHECK G2 BIONIC + FEX HOST BOUNDARY (NO WINDOWS
GAMES)" button and collect the exact output with a screenshot. That
test starts its separately supervised Android/Bionic native child
and attempts to load and query FEXCore symbols, but does NOT execute
guest x86 instructions; do not press the unrelated FEX guest-execution
buttons. If this gives `KERNIX_G2_HOST_BOUNDARY_PASS`, label it
strictly a user-reported Android FEXCore **library-load** proof,
not G2-C JIT/guest/glibc game support.


## User screenshot: Android G2 Bionic original FEXCore library load PASS (2026-11-04)

The user ran the **existing v0.21 APK** action
`CHECK G2 BIONIC + FEX HOST BOUNDARY (NO WINDOWS GAMES)`
on REDMAGIC 11 Pro / Android 16 and supplied a screenshot of the
on-device application's report. The displayed exact markers were:

```text
KERNIX_G2_HOST_BOUNDARY_PASS
KERNIX_G2_BIONIC_HOST_BOUNDARY_V1
ABI=aarch64
PAGE_BYTES=4096
SECCOMP_MODE=2
NO_NEW_PRIVS=0
FEX_CORE_LOAD=1
FEX_CONFIG_SYMBOL=1
WINE_PE_EXECUTED=0
```

**G2 Android/Bionic native subprocess + original FEXCore library
dynamic-load and config-symbol gate: USER-REPORTED ON-DEVICE PASS.**
This report is backed by a user-supplied screenshot, not independent
ADB, instrumented traces, or host CI. `SECCOMP_MODE=2` indicates
seccomp filtering already active for the spawned process; this is
an environmental fact, not by itself a test failure. The host reports
4 KiB pages, matching prior G2-C data-only 4KiB/RO mapping PASS.

**NOT established by this screenshot:** FEX creating a JIT context,
executing a single x86 instruction, G2-C dynamic PIE guest start,
running x86 glibc/interpreter, Wine, PE, graphics translation or any
Windows game. G2-C FEX child still has a blank qualified runner SHA
and is NOT in the signed APK. Existing G1 APK bundled ALU test is
a separate *bounded* JIT gate (9-second child supervision); if the user
chooses to invoke it and supplies the exact report, keep its
result explicitly separate from G2-C direct dynamic-PIE.


## User screenshot: G1 original FEXCore x86-64 ALU guest on actual Android (2026-11-04)

The user explicitly tapped the signed KERNIX v0.21 preview action
`RUN FIXED X86-64 CPU INSTRUCTIONS VIA FEXCORE (NO GAME)`
on their REDMAGIC 11 Pro Android phone and supplied a screenshot of
this exact displayed report:

```text
KERNIX_X86_GUEST_EXEC_PASS: original FEXCore ran fixed
x86-64 MOV/ADD/HLT instructions; actual guest RAX=49.
Wine, DirectX and Windows games: NOT TESTED.
```

**Gate status: USER-REPORTED ON-DEVICE PASS for the independent G1
fixed x86-64 ALU / original FEXCore JIT probe.** Unlike the earlier
G2 Bionic library-load and G2-C page-only checks, this fixed test
actually executes guest x86-64 instructions and observes the expected
register result. The signed-APK G1 Java launcher runs a bounded
fixed native child with a nine-second timeout and requires the exact
stdout marker and exit code zero. Screenshot is visual user-reported
device evidence, not independently captured ADB traces or a hardware
instrumentation test.

**Do NOT infer G2-C dynamic PIE execution from this G1 test.** The
original dynamic-interpreter G2-C x86 guest fixture is not shipped
with v0.21, the G2-C FEX child admission hash is still empty, and
no guest glibc/ld-linux startup, Wine, PE, DirectX or Windows games
has been verified on this phone. The screenshot establishes neither
the x86 getpid syscall bridge nor ELF64 filesystem loader behavior.

Next single separate G1 test on the same phone, if user consents:
tap `TEST REAL X86-64 LINUX GETPID SYSCALL BRIDGE (NO GAMES)`,
which runs an APK-pinned bounded x86 syscall fixture in its own
child. Record the exact success/failure output from the device,
without claiming G2-C dynamic PIE or Windows game support.


## User screenshot: real FEXCore G1 x86 Linux getpid syscall bridge on Android (2026-11-04)

The user explicitly tapped the APK v0.21
`TEST REAL X86-64 LINUX GETPID SYSCALL BRIDGE (NO GAMES)`
button and provided a screenshot showing the exact reported success:

```text
KERNIX_X86_SYSCALL_BRIDGE_EXEC_PASS: original
FEXCore ran fixed x86-64 MOV/SYSCALL/ADD/HLT
instructions; actual x86 syscall 39, guest RAX=Android host PID+7.
Wine, DirectX and Windows games: NOT TESTED.
```

**User-reported on-device gate PASS for the G1 bounded fixed x86-64
getpid syscall bridge**, supplementing the independently reported
G1 ALU/RAX=49, G2 Bionic FEXCore library load, and G2-C page-guard
preflight successes. The displayed result is the Java launcher's
verified success report based on its bounded child, not independently
captured ADB or kernel logs.

The native fixed fixture includes Linux x86-64 syscall 39 (getpid)
and adds 7 to the returned PID. This limited witness proves a single
guest syscall bridge operation and result calculation. It does NOT
establish general x86 syscall coverage, user-controlled guest code,
G2-C dynamic PIE/ld-linux/glibc startup, Linux userspace compatibility,
Wine/PE/DirectX or game execution. Production G2-C FEX runner
remains unqualified and gated CLOSED.

**Next independent device test:** use the already bundled
`TEST X86 GUEST MEMORY + WRITE/GETPID SYSCALLS (V0.9)` fixed,
bounded G1 button. Check its exact user-visible return marker,
and do not conflate its outcome with G2-C readiness.


## User screenshot: G1 original FEXCore x86 guest pointer write/getpid bridge PASS on Android (2026-11-04)

The user tapped the existing signed v0.21 preview button
`TEST X86 GUEST MEMORY + WRITE/GETPID SYSCALLS (V0.9)`
on REDMAGIC 11 Pro (Android 16), then supplied a screenshot showing:

```text
KERNIX_X86_MEMORY_WRITE_BRIDGE_EXEC_PASS: actual
FEXCore ran fixed x86-64 write(1, guest pointer, 22 bytes) then
getpid: two ordered syscalls; guest memory read verified by
output and RAX=PID+22.
Wine, DirectX and Windows games: NOT TESTED.
```

**Gate status: USER-REPORTED ON-DEVICE G1 fixed guest-memory pointer
and ordered Linux x86_64 write/getpid syscall-bridge PASS.** This
builds on the earlier screenshot-based on-device G1 x86 ALU RAX=49 and
G1 syscall 39 getpid+7 PASS results, along with G2 Bionic FEXCore
load and G2-C data-only RO/page-size PASS. The Java launcher checks
its own narrow bounded child's success report; no independent adb
trace, stress test or unknown guest code is implied.

The observed fixture demonstrates a 22-byte write via x86 guest memory
pointer, followed by getpid, with return-data computation yielding
guest RAX=host PID+22. This does NOT establish full Linux syscall
semantics, arbitrary ELF/PE execution, x86 interpreter or glibc
startup, Wine, VKD3D or games. This is a G1 fixture, not G2-C dynamic
PIE. The qualified Android G2-C FEX guest child remains CLOSED.

**Next independent device gate (already bundled, no new APK):** user
initiates `RUN GENUINE COMPILED X86-64 ELF64 VIA FEXCORE (V0.10)`.
This checks the real compiled fixed x86 ELF64 guest rather than the
earlier synthetic ALU/syscall microprobe. Collect screenshot of exact
result and halt on any crash/heat rather than bulk-running probes.


## User screenshot: G1 GNU-compiled x86-64 ELF64 PIE executed via original FEXCore on Android (2026-11-04)

The user tapped the existing signed v0.21 host preview's
`RUN GENUINE COMPILED X86-64 ELF64 VIA FEXCORE (V0.10)`
button on REDMAGIC 11 Pro / Android 16 and sent a screenshot
with the following observed app report:

```text
KERNIX_X86_ELF64_EXEC_PASS: genuine FEXCore loaded
and executed independently GNU-as/ld-compiled x86-64
ELF64 PIE with W^X segment protections, write/getpid guest
syscalls and RAX=Android PID+28.
Wine, DirectX and Windows games: NOT TESTED.
```

**G1 on-device GNU-compiled fixed x86-64 ELF64 PIE execution:
USER-REPORTED PASS.** The result is a screenshot of the
actual Android app's fixed, bounded G1 guest probe, not
independent ADB/instrumentation traces. This is stronger than the
earlier G1 x86-64 ALU, getpid and guest-pointer syscall microprobes:
the actual pinned ELF64 PIE, assembler/linker-generated executable
segments, W^X guest memory handling and ordered syscall witness
were exercised by original FEXCore. The native runner reports
`guest RAX = Android host PID + 28`.

**Scope limit:** This is not G2-C's dynamic-linked x86 PIE:
neither its PT_INTERP ld-linux, transitive libc dependency startup,
full guest x86 process ABI, nor Wine/Windows PE/game rendering has
run on this phone. G2-C guest child authorization remains CLOSED,
and no glibc/rootfs was distributed in v0.21.

Next single bounded, signed-APK on-device gate:
`RUN REAL X86 ELF64 .RODATA → .DATA MEMORY COPY (V0.11)`,
testing an ELF segment read/write transition and FEX guest-memory
behavior independently of the previous ELF64 proof. Stop
and capture an exact screenshot if the child fails or hangs,
rather than chaining tests.


## User screenshot: G1 x86 ELF64 .rodata-to-.data REP MOVSB copy PASS on Android (2026-11-04)

The user explicitly tapped the existing signed KERNIX v0.21
`RUN REAL X86 ELF64 .RODATA → .DATA MEMORY COPY (V0.11)`
button on REDMAGIC 11 Pro, Android 16, and supplied a screenshot
with this actual app report:

```text
KERNIX_X86_ELF64_RW_EXEC_PASS: genuine FEXCore
loaded and executed independently assembled x86-64 ELF64
PIE with W^X read-only/read-write segments, guest REP
MOVSB copy from .rodata to .data; write/getpid syscalls and
RAX=PID+26.
Wine, DirectX and Windows games: NOT TESTED.
```

**User-reported Android-device PASS for the bounded fixed G1
GNU-assembled ELF64 PIE .rodata → .data guest-memory copy.**
The native x86-64 REP MOVSB and W^X segment separation were
exercised as reported by the APK's guest runner; the launcher
accepted its strict native result. This is visual user-supplied
evidence, not independent ADB/kernel tracing. It supplements
the G1 x86 ELF64 execution / write-getpid proof and
the earlier bounded microprobes.

This is not the distinct G2-C snapshot-backed dynamic-linked
glibc ELF boot path. G2-C Android guest execution remains
gated OFF; ld-linux, Wine, DirectX and Windows games are untested.

**Next separate, bounded G1 device gate:** the existing APK
`VERIFY ORIGINAL FEXCORE X86 SYSCALL ABI (G1 V0.19)`
button. This uses its signed fixed ELF64 guest and up to a
12-second child watchdog; four allowlisted guest syscalls
mmap/write/getpid/munmap on a 16KiB guarded RW heap.
Do not attribute any G1 heap success to G2-C dynamic PIE.


## 2026-11-04 — REDMAGIC 11 Pro user screenshot: G1 FEXCore guarded heap + four x86 syscalls PASS

The user tapped `VERIFY ORIGINAL FEXCORE X86 SYSCALL ABI (G1 V0.19)` in
the signed v0.21 KERNIX host-preview Android APK and provided a screenshot
of the displayed report:

```text
KERNIX_X86_ELF64_HEAP_EXEC_PASS: genuine FEXCore
loaded and executed independently assembled x86-64 ELF64
PIE via FEXCore with guarded guest heap, four ordered x86
Linux syscalls mmap/write/getpid/munmap; copied the
ELF .rodata message into a new 16KiB RW mapping, verified
its contents, and freed the mapping; RAX=PID+26.
Wine, DirectX and Windows games: NOT TESTED.
```

Evidence type: USER-PROVIDED screenshot of the APK report on actual
REDMAGIC 11 Pro Android 16, NOT an independent ADB log or kernel
instrumentation trace. The Java fixed ALU/ELF heap launcher requires
exact native stdout and exit 0 with a 12-second watchdog. This report
indicates success for this bounded *G1* original FEXCore
x86-64 ELF64 guest heap and syscall ABI fixture: 16KiB RW mmap,
the displayed final register specifically checks PID+26,
and the sequence has four ordered allowlisted operations
mmap, write, getpid, munmap. Do not infer generic mmap, runtime memory
allocation or user-provided binary compatibility from the bounded proof.

G1 on-device fixture series now has user-reported PASS for:
fixed x86 arithmetic RAX=49, getpid +7, write(22)+getpid,
GNU x86 ELF64 PIE +28, ELF64 rodata→data REP MOVSB +26,
and this guarded x86 ELF64 heap mmap/write/getpid/munmap +26.
G2 Bionic FEX library load and G2-C data-only ARM64 4KiB
page check have separate user-reported PASS.

Important next boundary: stop repeating already-proven G1 fixed
tests. Actual G2-C original FEXCore dynamic PIE and snapshot-backed
guest interpreter startup are NOT yet available in the APK; the
qualified G2-C runner digest remains intentionally blank. The next
engineering milestone is to qualify one narrowly scoped signed
G2-C Android child, attest its original immutable x86 rootfs fixture,
use the existing 8s Android child watchdog and reject any
non-allowlisted guest path. It must be packaged/tested separately
and must NOT be called a game compatibility pass or used for Wine.


## G2-C Android original-FEX DIRECT-PIE candidate build gate (2026-11-04)

Following the user's on-device REDMAGIC 11 Pro G1 fixed-ELF64 x86
ALU, memory-copy and four-syscall proofs, the next distinct G2-C
milestone is a *non-distributable* Android/Bionic original-FEX JIT
candidate for the one pre-verified dynamically declared x86 PIE.
The existing Linux ARM64 original-FEX snapshot proof remains the
only successfully **executed** G2-C dynamic PIE witness.
The Android v0.21 signed preview G2-C child still performs only a
DATA-ONLY page-guard test. Do NOT infer G2-C device x86 execution.

The same original upstream FEXCore Android driver source now has
**mutually exclusive** compile policies:

- `KERNIX_G2C_ANDROID_BIONIC_BUILD_ONLY`: the existing
  exported link-check and `main()` still return **126** under
  every input. Existing signed APKs do NOT include this driver.
- `KERNIX_G2C_ANDROID_DEVICE_CANDIDATE_CI`: future separately
  supervised x86 **direct _start** candidate. Exactly one fixed
  command flag `--kernix-g2c-execute-fixed-snapshot-direct-entry-v1`
  and the canonical `/data/user/<decimal-id>/org.kernix.host/files`
  (or `/data/data/org.kernix.host/files`) are admitted.
  The native file-pinning + SHA-256 snapshot gate then checks the
  **four exact original** x86 guest fixture ELF files before
  planning VA/PHDR/AUXV and enabling one guest RX segment. No other
  guest executable or user-supplied EXE is admitted.
- The existing Linux ARM64 real-FEX source-built JIT mode remains
  separate under `KERNIX_G2C_NATIVE_ARM64_CI`.

The Android candidate emits a DIFFERENT exact two-line stdout proof
when and only when original FEX finishes the intended fixed x86 guest
instruction stream and returns RAX `0x4b45524e49584732`.
Its *future* Java supervisor's runner CLI was corrected to match the
native **flag + app-files directory**, not the guest-rootfs directory.
The supervisor still has `QUALIFIED_RUNNER_SHA256 = ""`, its user-UI
entrypoint is disconnected, and it cannot launch the candidate.

The exact-command / app-private path admission negative tests passed:
[CI run 41809470038](https://github.com/RM11Cor/RM11-WinCore/actions/runs/41809470038).
Those tests reject arbitrary flags, removable storage, path traversal,
other Android packages, malformed user IDs, and excess CLI arguments.
The original source-built Android NDK candidate cross-link is gated
separately by `.github/workflows/kernix-fexcore-android-ndk-audit.yml`.
Its candidate executable MUST stay outside uploaded artifacts in
`/tmp`, be deleted after binary/ABI checks, and **must not** be put
into the signed-APK build. Thus compile/link CI can never be treated
as on-device FEX execution evidence.

Future runtime release is gated independently on a qualified original
runner ELF SHA matching the *same exact bytes inside the signed APK*,
licensed/provenanced immutable guest fixture deployment to app-private
storage, user-initiated 8s child supervision and real Android device
stdout/stderr evidence. Guest interpreter execution, guest glibc
startup, Wine/PE, renderer, and games remain separately unproven.
