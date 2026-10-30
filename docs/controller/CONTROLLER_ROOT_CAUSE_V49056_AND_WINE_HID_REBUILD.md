# RM11 WinCore — native controller root-cause review (2026-10-30)

**Source of truth:** REDMAGIC 11 Pro, Android 16, actual v4.90.56 user diagnostics (game ZIP #16, native ZIP #15). Do **not** confuse standalone XInput probe success with game detection.

## Confirmed device findings

1. APK installed: `4.90.56-sdl-host-identity`, code 49056.
2. Native touch → 64-byte shared pad → native XInput DLL **does work** in the named Win64 probe. `RM11_V49044_XINPUT_STATE_STATUS=0`, `RM11_V49044_XINPUT_CAPABILITIES_STATUS=0`, button `0x1000`, analog LX samples.
3. Direct game CarX Street (30 s): XInput game-side DLL was **loaded**, `RM11_V49053_XINPUT_DLL_LOAD_EVENTS=9`, but `RM11_V49053_GETSTATE_DELTA=0` and `RM11_V49053_GETCAPABILITIES_DELTA=0`. A successful load is **not** evidence of gamepad support.
4. Wine launcher environment reached server and game: `RM11_V49055_SERVER_ENV_SDL_DEVICE_CONFIGURED=true` and `RM11_V49055_GAME_CHILD_BUS_ENV_VALID=true`.
5. Most important new trace (v49056): `game/last-v49054-sdl-winebus.log` contains **only** `RM11_V49054_WINEBUS=SDL_INIT_ENTERED_WITH_CONTROLLER_ENV`, not `SDL_INIT_RETURNED_SUCCESS`, `SDL_INIT_RETURNED_FAILURE` or `VIRTUAL_PAD_ATTACHED_WINEBUS_SDL_INSTANCE`. Thus the *native Winebus SDL_Init call is reached* but did not return within the observation period. Exact inner SDL subsystem is **not proven** without a native backtrace/instrumentation.
6. Wine's `winebus.so`, `winebus.sys`, `winehid.sys`, `hidclass.sys`, `winexinput.sys` and `winedevice.exe` are present in the runtime inventory. Presence alone does not prove bus/PNP enumerated a device.
7. CarX x64 PE and window exist and launcher process continues CPU activity; whether gameplay's input loop has begun remains unverified.

## Independent upstream evidence

- Wine `dlls/winebus.sys/bus_sdl.c` calls `SDL_Init(SDL_INIT_GAMECONTROLLER | SDL_INIT_HAPTIC)`, receives SDL joystick events and registers virtual HID via `bus_event_queue_input_report()`. A native XInput DLL injected into the game is **not** equivalent to exposing a PnP/HID device.
  https://github.com/wine-mirror/wine/blob/master/dlls/winebus.sys/bus_sdl.c
- SDL 2 `SDL_InitSubSystem` initializes events, joystick, gamecontroller and haptic on that call; `SDL_INIT_GAMECONTROLLER` implies joystick and events.
  https://wiki.libsdl.org/SDL2/SDL_Init
- SDL's Android backend expects Java/JNI integration, while RM11 runs Wine services headless without SDLActivity. This is a compatibility risk, not a proven identity of the blocked SDL function.
  https://wiki.libsdl.org/SDL2/README-android
- Bannerlator/Winlator's working rootless controller architecture presents synthetic Linux evdev devices via a native `libfakeinput.so` shim into Wine's bus, and newer Bannerlator provides a single publisher with BANNERIN + Direct XInput to complement DirectInput/evdev. Their codebase contains `app/src/main/cpp/winlator/fakeinput.cpp`, `app/src/main/cpp/bannerin/*`, and `BannerinWriter.java`.
  https://github.com/The412Banner/Bannerlator
  https://github.com/The412Banner/Bannerlator/issues/69
- CarX Street PC declares controller support. PCGamingWiki lists DirectInput middleware, so testing only app-local XInput misses a legitimate enumeration path.
  https://www.pcgamingwiki.com/wiki/CarX_Street

## Decision — stop iterating on SDL2 wrapper and per-game DLL placement

**Selected architecture for RM11:** one native virtual controller published into Wine's **PnP/HID bus**, implemented as a new `winebus` Unix-side backend matched to the *exact* signed Wine PE/Unix builds. Feed it the already-proven 64-byte shared Android mmap. No Android keyboard emulation, no root/uinput, no SDLActivity or JNI, no game-folder DLL injection required once Wine's own HID/XInput bridge works.

### Correct full data path

Android touch / external pad
→ RM11VirtualXInputV49037 shared state
→ **native Winebus RM11 HID backend (new)**
→ Wine PnP `winebus.sys` + `winehid.sys` + `hidclass.sys`
→ **DirectInput / WinMM**, and `winexinput.sys` → **all Wine builtin XInput API versions**
→ actual running Windows game.

The XInput DLL path is retained as an **isolated diagnostic fallback** until a native HID / PnP device is demonstrably enumerated. Never claim it fixes the game merely because a DLL loads.

### Required implementation work, in order

1. **Source pin/ABI gate:** identify the *exact source commit* and build options of the signed `winebus.so` and `winebus.sys`, and rebuild the two as a matched pair. Do not mix newer Wine Unix libraries with older PE drivers.
2. **Register bus:** add an RM11 bus to `dlls/winebus.sys` with the native `unix_device` registration interfaces for an Xbox-compatible HID gamepad, stable vendor/product, one slot, no fake keyboard mapping. Install and register the service in the Wine prefix **before** starting the game.
3. **State and events:** reuse the existing mmap (magic/version/seqlock) for 16-bit button bits, 6 axes, analog LT/RT, hat/D-pad. Native side diffs samples and queues true HID input reports. Preserve pressed/released edges; bound updates while idle and on disconnect. Avoid high-frequency log spam.
4. **Discovery:** ensure `winebus.sys`, `winehid.sys`, `hidclass.sys` and `winexinput.sys` enumerate an actual `HID\\VID_...` device. `XInputGetState(0)` and `IDirectInput8::EnumDevices` must both see *the same pad*.
5. **Game launch:** create the virtual device **before** launching CarX (controller discoverability at process startup). Keep it connected through focus changes/overlays. Clean up at Wine session end, not on individual UI transitions.
6. **CI gates:** native ABI match; unit tests for connected/disconnected, seqlock retry, 16 button mappings, 6 analog channels, simultaneous inputs, release edges and report descriptors. Stage no signed update until source gates and emulator smoke tests pass.
7. **Device acceptance gates:** on REDMAGIC (a) `joy.cpl` sees one Xbox-style controller; (b) DirectInput device count >= 1 and button edges read live; (c) Wine builtin XInput API reads live state; (d) CarX responds. This is the actual end-to-end definition of done.

### Fallback if upstream Wine bus source cannot be rebuilt

Port Bannerlator's **rootless evdev shim + synthetic `/dev/input/event*` backed by the RM11 state**, but only if the pinned Wine Unix bus can enumerate that synthetic device. The Wine/SDL module dependency must be proven, not assumed. This is materially more work than renaming XInput DLLs.

## Guardrails

- Never promise a "guaranteed" controller fix solely from a passing Actions build.
- Never treat `SDL_INIT_ENTERED` as `SDL_INIT_RETURNED_SUCCESS`.
- Never conflate Wine's PnP/HID device list with Android's input-device list.
- Avoid using `LD_PRELOAD` SDL concurrency hacks again; previous builds hung in SDL init.
- No more v49057/v49058 speculative feature releases before the bus/backend and acceptance tests exist.
