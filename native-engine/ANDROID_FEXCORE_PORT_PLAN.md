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
