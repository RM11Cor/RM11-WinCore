# KERNIX G2-E/C3-D7F — Real original x86-64 ld-linux JIT entry gate

Date: 2026-11-04. Branch: `kernix-native-engine-v1`. Status: **source-pinned Linux ARM64 FEX first original ld-linux instruction JIT-compile-path PASS** in completed GitHub Actions [run 41897107922](https://github.com/RM11Cor/RM11-WinCore/actions/runs/41897107922), source SHA `ced505a300f6820f50484f3a3dd7fdd3d10d3499`. **NOT** original x86 guest instruction execution, and no Android C3-D7F runtime/APK.

## Ground truth

- The user-supplied REDMAGIC Android 16 screenshot for C3-D7D showed a **real** fixed x86-64 instruction fixture executing via source-pinned FEXCore against rebased original Linux ELF **data** and Linux initial stack. It did not enter the interpreter's original x86 guest machine-code RIP.
- C3-D7E Linux ARM64 and x86_64 succeeded: SHA-pinned source main/ld-linux/libc plus exact original 16-byte PT_INTERP entry bytes, rebased canonical guest/native identity VA, temporary `PROT_READ|PROT_EXEC` on only owned entry page then restore `PROT_READ`. Android Bionic cross-compilation passed; no Android device execution.

## Narrow C3-D7F validation now implemented

- Test: `native-engine/android-host/tests/kernix_g2e_c3d7f_original_ldso_real_one_instruction_source_pinned_fex_compile_arm64.cpp`.
- Workflow: `.github/workflows/kernix-g2e-c3d7f-original-ldso-one-instruction-real-fex-jit-compile-linux-arm64.yml`, source-pinned upstream FEX `02e24ca5c01ed0c864466ed573db347336f70170`.
- Validate original exact x86 ELF provenance and real source-backed `e_entry` inside interpreter file-backed PT_LOAD RX segment. Place real ld-linux interpreter bytes at a 4KiB native, x86 guest-canonical rebased identity VM address chosen by the Linux ARM64 kernel, with stack/AUXV rebased.
- Initialize original FEXCore context/thread, assign its guest `CpuStateFrame.State.rip` to **real original interpreter entry** and RSP to relocated original Linux startup stack.
- Call `CompileRIPCount(thread,realOriginalGuestRIP,1)` only: request the FEX JIT to compile **one original x86 instruction**; inspect source-pinned FEXCore `SHMStats::ThreadStats.AccumulatedJITCount` increment after `CompileRIPCount`; this proves the FEX JIT compile path was visited but does **not** independently prove a nonzero JIT code cache block. Its LookupCache internal ABI is not externally exported. No custom IR, fake x86 guest bytes or synthetic success marker.
- Verify original 16 entry bytes unchanged and CpuStateFrame RIP/RSP unchanged. Never invoke `ExecuteThread`: this is a genuine original *instruction translation* gate, not guest execution, and does not prove the original ld-linux ran.
- Isolate via GitHub runner process `timeout -k 3s 25s`, deny all guest syscalls. Fail closed on unsupported source opcode, original provenance discrepancy, JIT block absent, W^X or memory permission error. Original v0.27 host untouched.

## Next real execution gate after translation passes

Before requesting the original x86 `ld-linux` RIP to **execute** in FEX, implement a correct per-PT_LOAD memory permission map for main/ldso/libc, allow necessary data/relocation writes without `PROT_WRITE|PROT_EXEC`, prove the Linux auxiliary vector and x86 TLS/FS/GS setup, and install bounded Linux syscall translation plus guest signal and fault handling. Run in an isolated Linux ARM64 process with bounded proof of *actual* guest RIP advancing and source-original ldso instruction semantics. Then prepare source-pinned Android opt-in independent signed APK. Do NOT claim Wine/Proton/PC games until original x86 ld-linux and glibc startup genuinely complete.

## Observed final CI evidence

- Run [41897107922](https://github.com/RM11Cor/RM11-WinCore/actions/runs/41897107922): completed/success, original pinned Linux AArch64 FEXCore build, strict three SHA-256 original Linux ELF provenance, C3-D7E original x86 ld-linux PT_INTERP entry 16-byte source-backed RX gate, and C3-D7F source-pinned FEX JIT compile invocation.
- Exact successful marker `KERNIX_G2EC3D7F_SOURCE_PINNED_FEX_ORIGINAL_X86_LDSO_ONE_INSTRUCTION_JIT_TRANSLATION_LINUX_ARM64_PASS`, with `original_FEX_JIT_compile_event_counter_incremented=1`, `fex_ExecuteThread_called=0`, `original_ldso_entered=0`, `original_guest_instruction_executed=0`, `android_runtime=0`.
- Stronger private LookupCache block-check was **not used** because that is not an exported upstream FEX ABI. The documented FEX `ThreadStats.AccumulatedJITCount` event validates the original compiler path was called; it is **not** a cache-block byte audit or program startup claim. Earlier failed CI on the stricter internal approach remains visible and should not be mistaken for an engine failure.
- Exact evidence record: `native-engine/evidence/g2e-c3d7f-source-pinned-first-original-ldso-x86-jit-compile-linux-pass.json`.
