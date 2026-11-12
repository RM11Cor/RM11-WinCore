# Forza Horizon 5 — Standalone Android APK port contract (P0)

## User requirement, mandatory

- An independent, game-specific **Android APK** for REDMAGIC 11 Pro (Android 16 / ARM64 / Adreno 840).
- The app itself selects legitimate game data, handles setup, renders the game, exposes touch/gamepad controls, captures diagnostics, and eventually starts the game.
- **No dependency on launching Bannerlator, Winlator, GameHub, a Windows desktop app or a separate emulator UI.**
- No cloud gaming. Game files remain on the user's phone. No game copyrighted executables or assets are committed to this repository or packaged in the APK.
- A working APK shell is NOT falsely labelled as a playable game port.

## Research findings (2026-11-12)

1. [XHYN V (GTA V)](https://github.com/XHYN-PH/XHYN-V-reborn/blob/main/docs/SOURCE.md):
   The described Android port loads an ARM64 `libgtav.so` game engine through Android/SDL, and uses a native DXVK path from D3D11 to Vulkan.
   The modification-layer repo does **not** publish the original Android port engine source or its complete reproducible build.
   We cannot use that proprietary ARM64 engine as a drop-in conversion method for Forza.
   Correct documentation: https://github.com/XHYN-PH/XHYN-V-reborn/blob/main/docs/SOURCE.md

2. [Daedalus / The Last of Us Remastered](https://github.com/erickmendes22/tlou-remastered-android):
   Bionic ARM64 game-specific Android launcher/runtime; FEX executes guest x86-64 instructions;
   shadPS4-derived Vulkan rendering and reimplemented PS4 libraries.
   Its [build guide](https://github.com/erickmendes22/tlou-remastered-android/blob/main/android/README.md)
   builds `build_deps`, `build_fex`, `build_gpu`, `build_runtime`, then an APK.
   Important difference: this is a **PS4** title; Windows FH5 needs Windows runtime APIs, Steam/launcher integration, and D3D12.

3. [Pinyon Shift / original Forza Horizon on Xbox 360](https://github.com/deivid22srk/pinyon-shift-android):
   PowerPC-to-C++ AOT translation plus a game-specific Vulkan renderer; this is **Forza Horizon 1**,
   not FH5 and not an FH5 native backend.

## FH5 Android port architecture

```
FH5 Native Port APK (Android Activity / standalone)
    |
    +-- game data picker (Android SAF ZIP or folder; no 100+GB bulk copy)
    +-- renderer + native Surface/Swapchain (Vulkan on Adreno)
    +-- runtime loader and game-version identity (NOT yet implemented)
    |      +-- x86-64 -> ARM64 translation or verified ahead-of-time recompilation
    |      +-- Win32 / NT process, memory, thread, filesystem ABI
    |      +-- Steam integration via legitimate user's original account (no bypass)
    |      +-- D3D12 + DXGI -> Vulkan via a validated VKD3D-Proton path
    |      +-- media, XAudio, input, controller, saves
    +-- per-game diagnostics and crash gates
```

Unlike Daedalus's PS4 library replacements, an FH5 Windows build requires a substantial Windows-compatible API/runtime to work. We can *embed* independently integrated open-source components into our APK after ABI, performance and license review, but the user must never be sent to a separate emulator UI.

A native `libforza.so` compiled from actual engine source would be ideal but no licensed FH5 Android engine/source is present; do not invent it or suggest that PE scanning creates such a library. AOT translation is a research track and not an established replacement for the Windows process/DRM/graphics stack.

## Deliverables / acceptance gates

| Gate | User-visible result | Does it load FH5 game code? |
|---|---|---|
| **P0** | Real independent debug APK; opens on phone; user selects ZIP/folder; 90 Vulkan swapchain frames inside its own Activity; export privacy-safe status | **No** |
| **P1** | In-APK ZIP64 data reader and read-only versioned game-file source mapping, without full extraction | No |
| **P2** | ARM64 runtime + x64 instruction execution in same APK; native executable ABI diagnostics | Synthetic tests only |
| **P3** | First verified FH5 executable bootstrap; resolve Windows libraries, process startup, legitimate Steam/launcher | Attempted |
| **P4** | Game creates its own Vulkan-backed window/first actual graphical frame through DX12 layer | Yes, if proven |
| **P5** | Menu + game asset streaming + audio + controls + save/load | Yes, if proven |
| **P6** | Open-world drive, stability, FPS optimisation for Adreno 840 | Yes, if proven |

**No regression of unrelated KERNIX/RM11 source.** This APK is under `fh5-port/`, with an independent application ID `com.fh5.port`. Test APK debug signing is distinct from any RM11 app certificate.

P0 explicitly disables Play because the real game runtime is not present; a false 'Play' button is not acceptable. Native graphics test shows that the Android Vulkan presentation path works, not that DirectX 12 works.

## P0 validation

- GitHub Actions builds `fh5-port/app/build/outputs/apk/debug/app-debug.apk`
- APK should contain `lib/arm64-v8a/libfh5_renderer.so`
- Test on REDMAGIC 11 Pro: open APK; select existing source archive; run Vulkan GPU; export report.
- Do not request full 100+ GB extraction or raw game bytes for this gate.
