# ARM64EC SEH blocker — verified after X11 relay repair (2026-10-26)

## What the REDMAGIC 11 Pro device ZIP proves

Device diagnostic ZIP for RM11-WinCore v4.0.59, selected Windows x86_64 game Hollow Knight Silksong:
- `RM11_V459_RELAY_MAX_CLIENTS=96`
- `RM11_V459_RELAY_PEAK_CLIENTS=14`
- `RM11_V459_RELAY_REJECTED_CLIENTS=0`
- `RM11_V459_RELAY_CAPACITY_EXHAUSTED=false`
- Wine X11 query succeeded: 8 X11 root child windows, all unmapped.
- Android Vulkan loader fallback succeeded: `RM11_V458_ANDROID_VULKAN_DLOPEN_SUCCESS`.
- Wine server stayed alive; **game Wine launcher exited 1**.
- Fatal Wine process log:
  ```
  err:seh:call_seh_handlers invalid frame 1000fda60 (0000000000022000-0000000000120000)
  err:seh:NtRaiseException Exception frame is not in stack limits => unable to dispatch exception.
  ```
- Missing FreeType and GnuTLS warnings also exist, but they do not independently prove the cause of the fatal SEH unwind.

## What the upstream Wine ARM64EC source says

Wine `dlls/ntdll/signal_arm64ec.c`, `is_valid_arm64ec_frame()`, validates a
frame against either normal stack bounds OR `ChpeV2CpuAreaInfo->EmulatorStackLimit`
and `EmulatorStackBase`; an unaligned frame is also invalid. When the check
fails, `call_seh_handlers()` logs the failure using the **normal TEB stack
bounds**, not the emulator stack bounds.

**Therefore the printed native TEB bounds cannot alone prove corruption of the
emulated x64 stack**. Do not patch this check to blindly accept out-of-range
frames or replace `EmulatorStackBase` with TEB StackBase. That could mask
genuine memory corruption and make arbitrary code execution unsafe.

Upstream references:
- https://github.com/wine-mirror/wine/blob/master/dlls/ntdll/signal_arm64ec.c
- https://wiki.fex-emu.com/index.php/Development:ARM64EC
- https://github.com/FEX-Emu/FEX/issues/6041 (related exception-dispatch / unwind problem, NOT proven identical)

## Working and failing layers

- Working, confirmed on device: Android native X11 TCP-to-Unix relay admission,
  Vulkan Bionic loader link, ARM64 Wine loader launch, several child processes.
- Broken: dispatch/unwind of a Windows exception in the x86_64 game within
  ARM64EC Wine/FEX. The exact producer of the invalid establisher frame remains
  UNPROVEN: Wine ARM64EC virtual_unwind / metadata vs. guest x86_64 FEX
  exception/context translation vs. a genuine game fault.
- Not yet usable: DXVK/VKD3D acceleration, game X11 window mapping, final
  game rendering. These are independent later milestones.

## A real fix — required engineering sequence

1. Pin and inspect the exact paired Wine-ARM64EC and FEX PE DLL source commits
   used in the signed APK. Verify matching ARM64EC ABI and exception metadata
   rather than upgrading one library at a time.
2. Build an isolated Windows x86_64 unwind/exception validation test in CI,
   plus an ARM64EC-native reference, and execute both in the same on-device
   Wine/FEX runtime without changing the user's game/prefix. Assert that
   handlers and unwind complete; report the exact exception status and module.
3. Capture the **first** exception (with bounded `+seh,+unwind` diagnostics)
   and actual `EmulatorStackBase/Limit` *inside the Wine/FEX native module*.
   Generic Android-side X11 logs cannot supply these values.
4. Apply the verified upstream Wine or FEX exception-unwinder fix to the
   native source and rebuild the **matched** pair. Re-run the isolated
   regression test before using the game as acceptance.
5. Only after clean exception dispatch, wire compatible DXVK/VKD3D and
   Vulkan ICD and assert the game maps an X11 window with nonblack pixels.

NO MORE: blindly changing X11 client limits, only toggling graphics settings,
raising timers, or changing emulator/graphics builds without matched ABI checks.

This document is an evidence-backed root-cause classification and integration
contract; it is **not** an implemented/native-binary fix, and must never be
called proof of game compatibility.
