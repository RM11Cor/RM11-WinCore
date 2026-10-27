# RM11 — Engine rebuild, not another black-screen patch
Updated: 2026-10-27. Working branch: `rm11-engine-rebuild`

## Nonnegotiable user constraints

- Preserve Android `applicationId=com.rm11.autocore`, existing stable signing key,
  the RM11/Nova file-manager UI, game folders on user storage, and existing prefix.
- No on-device user experiments or black-screen APK releases during reconstruction.
- Keep the last installable version **v4.0.89** untouched; this branch must never
  publish an APK merely because Java/Gradle succeeds.
- On Android 16 with targetSdk 35, do not execute code from writable app-private
  folders. Native Wine launchers and drivers must be packaged as signed APK-native ELF.
- Preserve existing user's prefix and shortcuts; new root/prefix is side-by-side,
  opt-in migration only after successful import and verified rollback.
- No assertion that Vulkan swapchain success or a viewable X11 child means
  that a Windows game frame appeared on Android.

## Evidence actually observed, not assumed

2026-10-27 physical device diagnostic ZIP, installed APK v4.0.89 code 167:
- Native X.Org reachable, but X11 root contained 13 children, 12 unmapped
  and one mapped service-size child at session end. No game window rendered.
- Wine PE-loader logs show the selected CarX Launcher and Windows DLL modules
  can be opened. Direct3D/Vulkan backend activation was not observed.
- v489 app-UID process census recorded 97 processes, 94 classified as Wine
  clients, **none of the 94 advancing CPU ticks between the last two scans**.
  Most were in other non-R/S scheduling states; this is not yet proof of
  the root scheduling cause because multiple Wine processes may be zombies.
- v478 software WSI succeeded at calling vkQueuePresentKHR in an isolated
  probe; Android surface presentation of guest/game pixels remained unverified.
- Build-time closure audit on the SHA256-pinned signed v489 APK inspected
  **3,830 archive entries** and found Wine launchers, X.Org, and FEX modules,
  but no coherent manifest and no *verified* DXVK D3D11 or hardware Turnip
  provider. This does NOT prove those DLLs never appear at runtime;
  it means their provenance and configuration cannot be certified.

## Source-level ABI truth from the exact shipped v4.0.89 APK

The byte-for-byte checked release APK (SHA256
`1f6c511e6949080e9ec41b6b08ae724cccc49d5c10491db16db9bb32371e34e8`)
has now passed the independent header/metadata audit:

- `libwineprobe.so`, `libwineserverrm11.so`, `libwine_winex11.so`
  and `libXlorie.so` are AArch64 ELF64 binaries, machine 183.
- `libwow64fex.dll` is PE32+ for ARM64, machine `0xAA64`.
- `libarm64ecfex.dll` is a **final linked hybrid ARM64EC PE** with
  COFF machine `0x8664` (AMD64) and present CHPE load-configuration
  metadata, version 1. This is **correct**, not an architecture error.
  ARM64EC `0xA641` is associated with intermediate object files, not
  the normal linked final DLL header. Do not "fix" this DLL by swapping
  it for an ARM64-only image.
- `tools/pe_chpe.py` checks the actual mapped PE Load Config
  `CHPEMetadataPointer`, not a filename or string occurrence.
- This is **structural ABI compatibility only**. It does not prove
  the Windows PE executes, Wine/FEX lifecycle is correct, or GPU frames
  reach the Android screen.

The missing release readiness proof remains the coherent DXVK and
hardware Turnip closure, native child-process lifecycle, and real
Android frame presentation. No more game APK iterations are justified
until those components are proven.

### New integrity rule

The old `.verified-bundle` marker alone was insufficient: installed
DLLs could be overwritten while leaving the marker intact. The new
`EngineInstalledTreeVerifier` compares every staged PE/data byte with
the SHA-pinned original ZIP and rejects missing or extra files, symlinks
and tampered content before even reusing an installed engine directory.
It cannot silently overwrite a user's existing Wine prefix.

### Existing process evidence is concerning but not a root-cause proof

The v4.0.89 device report recorded 97 same-app-UID Linux processes:
94 categorized as Wine clients, none advancing CPU ticks between two
20-second snapshots, and 86 states not classified as running/sleeping
by our older process census. Those "other" states were not subdivided
(`Z` zombie, `T` stopped, etc.), so attributing the entire failure
to zombie-process accumulation would be premature. The future
coordinated process supervisor must handle re-exec, SIGCHLD and child
reaping explicitly, rather than continuing to patch graphics blindly.

### Supporting verified upstream references

- Microsoft: https://learn.microsoft.com/en-us/windows/arm/arm64ec
- Wine loader `has_chpe_metadata()`: Wine `dlls/ntdll/loader.c`
- FEX build example with `llvm-readobj --coff-load-config`:
  https://github.com/The412Banner/Nightlies/blob/main/.github/workflows/fexcore-linux-stable.yml

## Why copy-pasting a working emulator would regress compatibility

Upstream candidate `StevenMXZ/Winlator-Ludashi` branch `4.1`
pinned review commit `1042ba5d2444900068b14137bf93a4ed6689cdd4`
is MIT-licensed but currently targets SDK 28. Our APK targets SDK 35.
The difference involves Android exec restrictions, native ABI linkage,
service lifecycle and storage permissions. Do not import its executable
rootfs strategy unchanged or replace our existing signing package name.

Alternative architectural reference: `Kachinaco/gamenative` at
`2bea2aaa54e9541873aebdf6d50e2187e6c44f30`,
GPL-3.0; no GameNative source copied. Termux:X11 Lorie already resides
in RM11 and is GPL-3.0. Review and comply with license notices
before importing more upstream code.

## Upstream implementation ports under review (source paths)

Source review (no binaries or GPL source transplanted yet) identifies the
specific working components that must be made coherent:
- `com.winlator.cmod.xenvironment.components.GuestProgramLauncherComponent`
  from MIT-licensed Winlator Bionic 4.1: handles Guest Wine execution,
  emulation-module extraction and per-container settings. It references
  `Container`, `XEnvironment`, `ImageFs`,
  `FEXCoreManager`, content profiles and rootfs configuration.
  Copying this class alone would not provide that dependency chain.
- `com.winlator.cmod.XServerDisplayActivity` constructs a full
  `XServer` rendering backend and installs graphics drivers,
  DXVK wrappers and Win32 components in a coordinated container.
  The class is thousands of lines; grafting UI wholesale would replace RM11.
- New RM11 will bridge its file UI into a reusable runtime session and
  guest-renderer host, **not** transplant Winlator's entire activity.
  Existing Termux:Lorie display remains available only when the hardware
  presentation path is confirmed.
- The side-by-side signed data installer now exists at
  `app/src/main/java/com/rm11/autocore/engine/EngineDataStager.java`.
  It verifies archive bytes, rejects ELF/native executables in writable
  engine data, checks PE headers for new Windows DLLs, and atomically
  promotes versioned data without overwriting the legacy prefix.
  It does not yet activate a new Wine engine, import binary packages or
  prove game drawing.

## Implementation order and gates

### Gate 1: Real shipped APK component proof (implemented)

- `tools/engine_closure_audit.py` inspects the exact pre-existing
  `v4.0.89` APK, including nested Wine ZIP content,
  rather than relying on old Gradle source tree.
- Rejects using Wine's builtin `d3d11.dll` as false proof of
  DXVK. A replacement engine needs signed provider manifest, source SHA
  and SHA256 of the actual DXVK DLL bytes and Turnip ICD ELF.
- The separate Action publishes a JSON **gap report only**. No APK release.
- Gate outcome on legacy APK: **BLOCKED**.

### Gate 2: One coherent source-pinned ARM64EC runtime (NOT YET COMPLETE)

- Import/compile matching Wine + FEX ARM64EC/WOW64 module pair, from the
  same build and PE ABI. Record source SHA, toolchain, ABI and SHA256.
- Provide signed APK-native Linux launchers, no app-data exec, and correct
  Wine child re-exec/IPC lifetime. No Wine cross-process zombie leaks.
- Provide a side-by-side ImageFs and Wine prefix; never overwrite user's
  existing registry/saves. Signed manifest and atomic activation/rollback.

### Gate 3: Hardware rendering to a REAL Android frame (NOT YET COMPLETE)

- Install content-addressed ARM64EC DXVK D3D11/DXGI and hardware Adreno A8xx
  Turnip ICD with the correct Bionic Vulkan loader and X11 WSI.
- Reject software `MESA_VK_WSI_DEBUG=sw` as a game-ready hardware path.
- Prove actual Android Lorie surface receives changing frames and window
  ownership, not just successful vkQueuePresentKHR return.
- Driver abort/cleanup must not kill wineserver or destroy the prefix.

### Gate 4: Release validation (NOT YET COMPLETE)

- Independent Windows-native small graphical PE with window + text, then
  a D3D11 sample demonstrating >1 distinct Android screen frame.
- Verify Wine host-child lifecycle, native CPU progression and termination.
- Hardware test on physical REDMAGIC 11 Pro. Only after these pass, consider
  CarX Street and its own compatibility requirements.
- Only after hardware proof: same packageName, stable keystore verification,
  APK upgrade migration and rollback. No claim of guaranteed CarX compatibility.

## What should not be done

- No more game-specific flags (`-force-d3d11`), FreeType
  blind redirects, random X11 window mapping, or artificial Android splash
  surfaces as substitutes for a working Wine/DXVK/Turnip chain.
- Do not conclude Wine is healthy just because the host Java Process is alive.
- Do not call old resource bundles a new engine or publish release version 4.0.90
  with the same v2.5.6 pinned Wine payload.
- Do not demand another diagnostic ZIP from the user while Gates 2–3 are open.

## Trusted sources

- https://github.com/StevenMXZ/Winlator-Ludashi/tree/4.1
- https://github.com/Kachinaco/gamenative
- https://github.com/termux/termux-x11
- https://github.com/FEX-Emu/FEX
- https://github.com/doitsujin/dxvk
- https://docs.vulkan.org/spec/latest/chapters/fundamentals.html
