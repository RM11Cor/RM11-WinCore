# KERNIX — Android FEXCore integration gate

## Objective
Port **actual pinned upstream FEXCore** to Android ARM64/Bionic as an independently attestable component, then connect it to an Android-native host and, later, a real Windows runtime. This is **not** an instruction to copy FEX Linux/glibc binaries, reuse another emulator's APK, or pretend that a Win32 game already runs.

Pinned FEX upstream source: `FEX-Emu/FEX@02e24ca5c01ed0c864466ed573db347336f70170`. License: original upstream MIT with all applicable transitive submodule notices preserved.

## Gates and required evidence
1. **Android compile:** Cross-compile a genuine `libFEXCore.so` with Android NDK targeting `arm64-v8a`. Explicitly record any temporary changes to upstream CMake, and require an ELF AArch64 checksum and Android Bionic dependencies; a green log-collection workflow is not a build pass.
2. **Safe load:** Include an immutable verified version only after the first gate; use an Android app-private, read-only APK-native-library location. Test genuine Android dynamic loader `dlopen` plus a known upstream symbol and report the error accurately. No arbitrary executable paths.
3. **CPU/runtime integration:** Connect real guest instruction execution through FEXCore with an Android host implementing required guest memory, syscall and filesystem interfaces. `dlopen` alone is not guest x86 execution. Validate with a true x86_64 ELF guest, independent of Wine.
4. **Wine/PE:** Wire an actual Wine runtime with reliable guest/host pathname visibility (the earlier Linux ARM64 path-mirroring fix is reference evidence only, not an Android implementation). Require real Win32 output and exit code on device.
5. **Display, Vulkan, input:** Prove GUI surface lifetime and Android presentation, then verify physical Vulkan/DXVK/VKD3D and native HID/XInput mapping. No FPS promises without game evidence.

## Current implementation and evidence
- Original Linux ARM64 FEX + Ubuntu Wine9 proved genuine Windows `cmd.exe`, PE and Notepad/X11 on GitHub ARM64 Linux, including mapped X11 window. **These are Linux, not Android device results.**
- Independent Android Host Preview v0.3 includes a single fixed Bionic ARM64 process probe, but its result on an actual REDMAGIC 11 Pro is not verified in CI.
- `.github/workflows/kernix-fexcore-android-ndk-audit.yml` performs a deliberately **audit-only** source checkout and isolated core-only NDK compilation. The only source adjustment is in the ephemeral CI checkout and is recorded as a diff; all official upstream source files remain untouched in KERNIX.
- Initial audit run `41602358126` found a **CI target-name mistake** (`FEX_shared` vs actual upstream `FEXCore_shared`) after CMake configured successfully. This was an audit harness problem, not evidence of an incompatible FEX C++ source; corrected in subsequent workflow.
- No new FEX Android binary is in `components/registry.json` until the real library is built, dynamically linked correctly and qualified on device.

## Safety requirements
Never write into Android `/usr/lib`, `/usr/share` or protected paths; don't use root, disable Android security, run unknown game files during component qualification, or erase existing user prefixes. Any output labeled *Android-ready* must have actual on-device evidence; source compilation alone merits only *Android cross-built, device-untested*.


## Confirmed physical Android FEXCore loading from v0.4 screenshot (2026-11-03)

The user ran the direct KERNIX Host Preview v0.4 on REDMAGIC 11 Pro (Android 16).
The displayed result was exactly headed **FEXCORE_ANDROID_LOAD_PASS** and said
the actual pinned ARM64 FEXCore library loaded and the expected symbol was exported.
Host ABI 1, an Android ARM64 report, and Vulkan system loader reporting 1.4.0
were visible. A separate Android-native process proof still displayed *not
started*, and Vulkan GPU/swapchain/game validation was *not tested*.

This is useful first-person **on-device application diagnostic evidence**, not
an independently signed trace. Its machine-readable scope is recorded at
native-engine/evidence/android-fexcore-v04-ondevice-observation.json. The result
promotes Android FEXCore **loading**, not guest x86 instruction execution.
It cannot promote a game component to the registry yet.

### Next independent functional execution gate

The fixed source native-engine/android-host/kernix_fexcore_x86_64_alu_probe.cpp
uses original upstream Context APIs, initializes a real FEXCore context/thread,
and attempts to execute a bounded, in-memory x86-64 instruction sequence:
mov RAX, 42; add RAX, 7; HLT. The probe must return only when its real guest
CPUState register equals 49. Neither source file presence nor NDK compilation
is a guest execution pass. Compile as an Android ARM64 PIE, audit ELF linkage,
package it as a fixed signed-APK helper, and execute in an isolated, timed
child process. Do not use arbitrary EXE files or games in this gate.
