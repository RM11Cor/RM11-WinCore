# KERNIX — C3-D8 isolated memory probe closeout and graphics-entry gates

This document defines **where to stop testing individual x86 opcodes** and how to transition to actionable graphics/whole-process integration. It is a stage signoff specification, **not** a declaration that the entire memory subsystem, Linux dynamic loader, Wine/Proton or Vulkan translation is complete.

## 1. Verified baseline, by evidence type

- **Physical Android (user-supplied on-screen probe, not independently signed hardware attestation):** C3-D8C5 source SHA-locked `ld-linux-x86-64.so.2` first **25** genuine x86-64 guest instructions under opt-in native Android/Bionic FEX child; source guest RX/RW mappings, real 8-byte RW guest store, 192-byte guest stack and original PT_LOAD bytes restored; original next (26th) instruction not executed. See `evidence/g2e-c3d8c5-android-user-device-source-original-25-fex-instructions-screenshot-pass.json`.
- **Actual Linux ARM64 FEX ExecuteThread CI:** C3-D7AC first **28** genuine x86-64 original `ld-linux` guest instructions succeeded with original `MOV R14,RCX`, `OR RAX,RDX`, source-relative `LEA RDX` witnesses, exact 25th guest RW qword rollback and stop before the 29th original RW store. CI run `42045838935`.
- **Android C3-D8C6 source/binary artifact:** separate `org.kernix.originalfexldso28` Android ARM64 source-pinned FEX original 28-opcode debug APK was rebuilt with corrected `versionName=0.1-c3d8c6-original-fex-ldso-28`, [CI #42050146267](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42050146267) **PASS**, and directly published as a separate [GitHub prerelease](https://github.com/RM11Cor/RM11-WinCore/releases/tag/kernix-c3d8c6-fex28-debug-20261105-9c4972a8) by [publisher CI #42051113585](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42051113585) **PASS**. Independently verified final 2,318,975-byte APK SHA256 `ae26617695514734e17fa97769fef1467cc316583b18cffb5558eada855e167e`, native FEXCore and 28-opcode child hashes, original SHA-locked Linux x86 ELF triad and package identity. This is **compiled and released**, not yet **executed on the phone**.
- **Not yet proven:** first 28 source opcodes physically executed on Android device, full Linux `ld-linux` loading/relocation/TLS/IFUNC, guest Linux syscall/signal runtime, any Windows PE/Wine/Proton or DXVK/VKD3D graphics, Vulkan swapchain, game first frame.

## 2. Close the C3-D8 bounded-original-opcode **probe series** (not memory subsystem)

1. Build and source/SHA audit the corrected, separately signed **C3-D8C6 first-28-opcode test APK**, original Linux data and native FEXCore hashes, Android package/version label; publish a GitHub direct, SHA-locked **prerelease**, not a production KERNIX update.
2. Require one physical Android user test showing the **exact full native+Java marker** `KERNIX_C3D8C6_ANDROID_DEVICE_SOURCE_ORIGINAL_LDSO_28_FEX_INSTRUCTIONS_PASS` and the explicit fields `SOURCE_TWENTYNINTH_MOV_GUEST_RW_EXECUTED=0`, `SOURCE_GUEST_192_STACK_AND_HOST_STACK_RESTORED=1`, `ORIGINAL_THREE_FILE_BACKED_PTLOAD_BYTES_RESTORED=1`, `ALL_ORIGINAL_GUEST_WINDOWS_RELEASED=1`. Record as user screenshot evidence and do **not** describe it as signed hardware telemetry.
3. **After phone PASS:** label `C3-D8 bounded 28-opcode memory/guest-state probe series: CLOSED`. Do **not** keep adding synthetic 29th/30th/31st incremental opcode tests without a specific bug requiring instruction-level isolation. This is not the same as closing general memory management.
4. **On failure:** use one exact device trace and concrete fault mechanism (JIT, W^X, address, stack or guest bytes), fix root cause; do not open graphics while the core 28-opcode portability proof is failing.

## 3. Next whole-process and graphics **functional**, not opcode-count, gates

- **G0 functional Linux guest dynamic-loader/runtime:** run a whole real x86-64 Linux ELF process using authentic `ld-linux`, libc relocations, TLS/stack/auxv, controlled guest syscalls and native FEX execution; define exit code, stdout and cleanup as measurable proof. The bounded guest loader stage is not enough for this.
- **G1 Android physical Vulkan WSI smoke test (isolated from Wine):** enumerate physical GPU/driver/caps and Android page alignment, create `VkInstance`/`VkDevice`, Android surface, swapchain and frame-loop; verify presented frames, rotation/touch/resize/recreation and clean teardown. Do not call success from test colors or image creation only. Logs and physical device result required. Keep this isolated to avoid reproducing prior `VK_ERROR_INITIALIZATION_FAILED (-3)` and black-after-touch failures.
- **G2 FEX + Wine/Proton + Vulkan bridge:** demonstrate a real Windows PE executable's UI/event-loop (not just `MessageBox` or ephemeral window) with 64-bit FEX guest CPU, Wine/Proton runtime, working `DXVK` D3D11 translation into device Vulkan WSI, consistent touch/gamepad input. Separate D3D12/`VKD3D` gate follows D3D11; do not assume shader/API support from installed component names.
- **G3 first real game/per-game compatibility:** immutable game folder selection, reproducible component version selection, game-specific diagnostics, first real frame, FPS/crash evidence, bounded thermal/device settings; first use a known lighter functioning reference title before heavy titles. No unverifiable 100% compatibility promise.

## 4. Non-regression and truth labels

- Do **not** touch the stable signed KERNIX v0.27 APK, its app ID, the user's game files or Wine prefixes. Test apps always have distinct IDs, explicit opt-in and bounded execution.
- Maintain an exact classification in every release: `source-only`, `CI compiled`, `Linux ARM64 FEX actually executed`, `Android physical user screenshot`, `full process`, `Vulkan frame presented`, `Windows PE executed`, `game frame proven`. These classes are not interchangeable.
- Prefer **one instrumented functional acceptance gate per subsystem**, replacing a long series of shallow micro-tests. Return to instruction-level isolation only on a concrete reproducible bug.

